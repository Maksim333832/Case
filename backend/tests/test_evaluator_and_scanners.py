from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import reload_settings
from app.core.crypto import encrypt_secret
from app.core.db import CredentialORM, get_session_factory, init_db
from app.core.models import Finding
from app.main import create_app
from app.nodes.scanners._stubs import scan_sast_stub, scan_sca_stub, scan_secrets_stub
from tools.evaluate import evaluate_report
from tools.evaluate import main as eval_cli_main
from tools.mutate_project import generate_mutated_variants

TRUTH_PATH = Path("/home/user/training/ground-truth/training-findings.json")
TRAINING_PROJECT = Path("/home/user/training/training-project")
VULN_DB_PATH = Path("/home/user/backend/data/vulnerabilities.json")


def _zip_training_repo() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in TRAINING_PROJECT.rglob("*"):
            if f.is_file():
                rel = f.relative_to(TRAINING_PROJECT).as_posix()
                zf.write(f, arcname=f"training/training-project/{rel}")
    return buf.getvalue()


def test_stubs_and_evaluator_15_of_15_and_0_controls(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'eval.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    reload_settings()

    app = create_app()
    with TestClient(app) as client:
        up = client.post("/api/uploads", files={"file": ("training.zip", _zip_training_repo(), "application/zip")})
        assert up.status_code == 201
        upload_id = up.json()["upload_id"]

        wf = client.post(
            "/api/workflows",
            json={
                "name": "Training Full Scan",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
                        {"id": "n3", "type": "scanner.secrets", "params": {}},
                        {"id": "n4", "type": "scanner.sca", "params": {}},
                        {"id": "n5", "type": "scanner.sast", "params": {}},
                        {"id": "n6", "type": "findings.merge", "params": {"deduplicate": True}},
                        {"id": "n7", "type": "findings.export", "params": {"title": "Training Evaluation"}},
                    ],
                    "edges": [
                        {"id": "e1", "source": "n1", "sourceHandle": "out", "target": "n2", "targetHandle": "trigger"},
                        {"id": "e2", "source": "n2", "sourceHandle": "workspace", "target": "n3", "targetHandle": "workspace"},
                        {"id": "e3", "source": "n2", "sourceHandle": "workspace", "target": "n4", "targetHandle": "workspace"},
                        {"id": "e4", "source": "n2", "sourceHandle": "workspace", "target": "n5", "targetHandle": "workspace"},
                        {"id": "e5", "source": "n3", "sourceHandle": "findings", "target": "n6", "targetHandle": "in"},
                        {"id": "e6", "source": "n4", "sourceHandle": "findings", "target": "n6", "targetHandle": "in"},
                        {"id": "e7", "source": "n5", "sourceHandle": "findings", "target": "n6", "targetHandle": "in"},
                        {"id": "e8", "source": "n6", "sourceHandle": "findings", "target": "n7", "targetHandle": "in"},
                    ],
                },
            },
        )
        assert wf.status_code == 201
        run = client.post(f"/api/workflows/{wf.json()['id']}/run?wait=true")
        assert run.status_code == 200
        run_id = run.json()["run_id"]

        report_json = client.get(f"/api/runs/{run_id}/report.json")
        assert report_json.status_code == 200
        out_file = tmp_path / "out.json"
        out_file.write_text(report_json.text, encoding="utf-8")

        exit_code = eval_cli_main(["--report", str(out_file), "--truth", str(TRUTH_PATH)])
        assert exit_code == 0

        res = evaluate_report(report_json.json(), json.loads(TRUTH_PATH.read_text(encoding="utf-8")))
        assert len(res.matched) == 15
        assert len(res.missed) == 0
        assert len(res.control_false_positives) == 0
        assert res.recall == 1.0
        assert res.precision == 1.0


def test_evaluator_catches_missed_controls_and_bad_schema(tmp_path: Path):
    truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))

    # Missed findings -> fail
    res_empty = evaluate_report({"findings": []}, truth)
    assert not res_empty.passed
    assert len(res_empty.missed) == 15

    # Control false positives -> fail
    ctrl_fp = evaluate_report(
        {
            "findings": [
                {"category": "SECRET", "path": "README.md", "class": "api-key", "line": 9},
                {
                    "category": "SCA",
                    "path": "build.gradle.kts",
                    "group": "org.apache.commons",
                    "artifact": "commons-lang3",
                    "version": "3.20.0",
                    "advisoryId": "CVE-2025-48924",
                },
                {
                    "category": "SAST",
                    "path": "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt",
                    "class": "sql-injection",
                    "line": 17,
                },
            ]
        },
        truth,
    )
    assert not ctrl_fp.passed
    assert len(ctrl_fp.control_false_positives) == 3

    # CLI returns non-zero on fail
    bad_file = tmp_path / "bad.json"
    bad_file.write_text('{"findings": [{"category": "SECRET", "path": "a.kt", "class": "api-key", "line": "7"}]}', encoding="utf-8")
    assert eval_cli_main(["--report", str(bad_file), "--truth", str(TRUTH_PATH)]) == 1


def test_mutate_project_generates_valid_variants_and_catches_hardcoded_stubs(tmp_path: Path):
    variants = generate_mutated_variants(TRAINING_PROJECT, TRUTH_PATH, tmp_path / "mutants")
    assert len(variants) == 2

    for var in variants:
        pdir = var["project_dir"]
        truth_data = json.loads(var["truth_file"].read_text(encoding="utf-8"))
        assert len(truth_data["findings"]) == 15
        for f in truth_data["findings"]:
            target = pdir / f["path"]
            assert target.is_file(), f"Missing mutated path {f['path']} in {var['name']}"
            lines = target.read_text(encoding="utf-8").splitlines()
            assert 1 <= f["line"] <= len(lines)

        # Hardcoded dev stubs MUST fail on mutated variants (anti-overfitting verification)
        stub_findings = (
            scan_secrets_stub(pdir, {})
            + scan_sca_stub(pdir, {"vuln_db_path": str(VULN_DB_PATH)})
            + scan_sast_stub(pdir, {})
        )
        res = evaluate_report({"findings": [x.to_submission() for x in stub_findings]}, truth_data)
        assert len(res.missed) > 0


def test_telegram_notify_success_and_token_masking_on_error(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'tg.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    monkeypatch.setenv("SECRET_KEY_FILE", str(tmp_path / "secret.key"))
    reload_settings()

    init_db(f"sqlite:///{tmp_path / 'tg.db'}")
    secret_bot_token = "1000000002:TEST_FAKE_TOKEN_SHOULD_NEVER_LEAK_12345"
    with get_session_factory()() as session:
        session.add(
            CredentialORM(
                id="cred_tg_1",
                name="bot",
                kind="telegram",
                encrypted_value=encrypt_secret(secret_bot_token),
            )
        )
        session.commit()

    captured_payloads = []

    async def fake_post_ok(self, url, json=None, **kwargs):
        captured_payloads.append({"url": url, "json": json})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 777}})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post_ok)

    app = create_app()
    with TestClient(app) as client:
        up = client.post("/api/uploads", files={"file": ("training.zip", _zip_training_repo(), "application/zip")})
        upload_id = up.json()["upload_id"]

        wf = client.post(
            "/api/workflows",
            json={
                "name": "TG Notify WF",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
                        {"id": "n3", "type": "scanner.secrets", "params": {}},
                        {"id": "n4", "type": "findings.export", "params": {}},
                        {
                            "id": "n5",
                            "type": "notify.telegram",
                            "params": {"credential_id": "cred_tg_1", "chat_id": "123456789"},
                        },
                    ],
                    "edges": [
                        {"id": "e1", "source": "n1", "sourceHandle": "out", "target": "n2", "targetHandle": "trigger"},
                        {"id": "e2", "source": "n2", "sourceHandle": "workspace", "target": "n3", "targetHandle": "workspace"},
                        {"id": "e3", "source": "n3", "sourceHandle": "findings", "target": "n4", "targetHandle": "in"},
                        {"id": "e4", "source": "n4", "sourceHandle": "report", "target": "n5", "targetHandle": "in"},
                    ],
                },
            },
        )
        assert wf.status_code == 201
        wf_id = wf.json()["id"]

        run = client.post(f"/api/workflows/{wf_id}/run?wait=true")
        assert run.status_code == 200
        assert run.json()["status"] == "success"
        assert len(captured_payloads) == 1
        assert captured_payloads[0]["json"]["chat_id"] == "123456789"
        assert "Находок: 5" in captured_payloads[0]["json"]["text"]
        assert secret_bot_token not in captured_payloads[0]["json"]["text"]

        # Simulate network exception containing URL with token -> must be masked!
        async def fake_post_err(self, url, json=None, **kwargs):
            raise httpx.ConnectError(f"Failed connecting to {url}")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post_err)
        run2 = client.post(f"/api/workflows/{wf_id}/run?wait=true").json()
        assert run2["status"] == "partial"
        det2 = client.get(f"/api/runs/{run2['run_id']}").json()
        tg_node = next(nr for nr in det2["node_runs"] if nr["node_id"] == "n5")
        assert tg_node["status"] == "failed"
        assert secret_bot_token not in (tg_node["error"] or "")
