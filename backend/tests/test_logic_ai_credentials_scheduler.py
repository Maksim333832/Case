from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import reload_settings
from app.core.db import CredentialORM, get_session_factory
from app.core.models import Finding
from app.engine.scheduler import get_scheduler
from app.main import create_app
from app.nodes.ai.llm_client import OpenAICompatibleClient
from app.nodes.ai.validator import validate_ai_response
from app.nodes.logic._eval_helpers import safe_regex_search

TRAINING_PROJECT = Path("/home/user/training/training-project")


def _zip_training() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in TRAINING_PROJECT.rglob("*"):
            if f.is_file():
                zf.write(f, arcname=f"training/training-project/{f.relative_to(TRAINING_PROJECT).as_posix()}")
    return buf.getvalue()


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            category="SECRET",
            path="src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
            **{"class": "api-key"},
            line=7,
            severity="MEDIUM",
            description="Embedded API key in QuoteRequest.kt",
            evidence="cg26****6c",
        ),
        Finding(
            category="SCA",
            path="build.gradle.kts",
            group="org.apache.commons",
            artifact="commons-text",
            version="1.9",
            advisoryId="CVE-2022-42889",
            aliases=["GHSA-599f-7c49-w659"],
            severity="CRITICAL",
            description="Vulnerable commons-text dependency",
        ),
    ]


def test_logic_regex_redos_protection():
    assert safe_regex_search(r"QuoteRequest\.kt", "src/main/QuoteRequest.kt") is True
    # Input beyond MAX_REGEX_INPUT_LEN is safely truncated (no match beyond cap)
    assert safe_regex_search(r"NEEDLE_AT_END", ("x" * 60_000) + "NEEDLE_AT_END") is False
    with pytest.raises(ValueError, match="timed out"):
        safe_regex_search(r"^((?:a|aa)+)+b$", "a" * 40 + "c")


def test_ai_validator_adversarial_cases():
    findings = _sample_findings()

    # (a) Invalid JSON -> passed=False
    res_bad_json = validate_ai_response("not valid json {{{", findings)
    assert res_bad_json.stats.passed is False

    # (b) Nonexistent finding_ref -> dropped_items=1, valid F-001 kept
    payload_bad_ref = json.dumps(
        {
            "summary": "Summary",
            "items": [
                {
                    "finding_ref": "F-001",
                    "explanation": "API key in QuoteRequest.kt line 7",
                    "risk": "Exposure",
                    "fix_steps": ["Move to env"],
                },
                {
                    "finding_ref": "F-999",
                    "explanation": "Ghost finding",
                    "risk": "None",
                    "fix_steps": ["Ignore"],
                },
            ],
        }
    )
    res_bad_ref = validate_ai_response(payload_bad_ref, findings)
    assert res_bad_ref.stats.passed is True
    assert res_bad_ref.stats.dropped_items == 1
    assert len(res_bad_ref.report["items"]) == 1

    # (c) Hallucinated CVE -> dropped_cve incremented and hallucinated CVE stripped
    payload_bad_cve = json.dumps(
        {
            "summary": "Summary mentioning CVE-2099-99999 and CVE-2022-42889",
            "items": [
                {
                    "finding_ref": "F-002",
                    "explanation": "commons-text affected by CVE-2022-42889 and fake GHSA-aaaa-bbbb-cccc",
                    "risk": "RCE",
                    "fix_steps": ["Upgrade"],
                }
            ],
        }
    )
    res_bad_cve = validate_ai_response(payload_bad_cve, findings)
    assert res_bad_cve.stats.passed is True
    assert res_bad_cve.stats.dropped_cve == 2
    assert "CVE-2099-99999" not in res_bad_cve.report["summary"]
    assert "CVE-2022-42889" in res_bad_cve.report["summary"]
    assert "GHSA-aaaa-bbbb-cccc" not in res_bad_cve.report["items"][0]["explanation"]

    # (d) Wrong file or wrong line -> item dropped -> if 0 remain, passed=False
    payload_wrong_file = json.dumps(
        {
            "summary": "Summary",
            "items": [
                {
                    "finding_ref": "F-001",
                    "explanation": "Key hardcoded in OtherFile.kt",
                    "risk": "High",
                    "fix_steps": ["Fix"],
                }
            ],
        }
    )
    res_wf = validate_ai_response(payload_wrong_file, findings)
    assert res_wf.stats.passed is False
    assert res_wf.stats.dropped_items == 1

    payload_wrong_line = json.dumps(
        {
            "summary": "Summary",
            "items": [
                {
                    "finding_ref": "F-001",
                    "explanation": "Key hardcoded in QuoteRequest.kt at line 999",
                    "risk": "High",
                    "fix_steps": ["Fix"],
                }
            ],
        }
    )
    res_wl = validate_ai_response(payload_wrong_line, findings)
    assert res_wl.stats.passed is False
    assert res_wl.stats.dropped_items == 1


def test_ai_retry_and_fallback_and_ollama_config(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'ai.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    # Simulate switching to local Ollama strictly via settings
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("LLM_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("LLM_API_KEY", "")
    reload_settings()

    call_urls: list[str] = []

    async def fake_chat_json(self, system_prompt: str, user_prompt: str) -> str:
        call_urls.append(f"{self.base_url}:{self.model}")
        # Always return invalid JSON to verify 1 retry + deterministic fallback
        return "INVALID_JSON"

    monkeypatch.setattr(OpenAICompatibleClient, "chat_json", fake_chat_json)

    app = create_app()
    with TestClient(app) as client:
        up = client.post("/api/uploads", files={"file": ("training.zip", _zip_training(), "application/zip")})
        upload_id = up.json()["upload_id"]

        wf = client.post(
            "/api/workflows",
            json={
                "name": "AI Fallback WF",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
                        {"id": "n3", "type": "scanner.secrets", "params": {}},
                        {"id": "n4", "type": "ai.explain", "params": {"language": "ru"}},
                        {"id": "n5", "type": "findings.export", "params": {}},
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
        run = client.post(f"/api/workflows/{wf.json()['id']}/run?wait=true").json()
        assert run["status"] == "success"
        # Called twice (initial + 1 retry) with local Ollama URL & model
        assert call_urls == ["http://localhost:11434/v1:qwen2.5-coder:7b"] * 2
        assert run["ai_report"]["validation"]["retried"] is True
        assert run["ai_report"]["validation"]["used_fallback"] is True
        assert len(run["ai_report"]["items"]) == 5

        md = client.get(f"/api/runs/{run['run_id']}/report.md").text
        assert "AI-анализ и рекомендации" in md


def test_credentials_api_and_scheduler_persistence(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'cred_sched.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("SECRET_KEY_FILE", str(tmp_path / "secret.key"))
    reload_settings()

    app1 = create_app()
    with TestClient(app1) as client:
        raw_secret = "super-secret-tg-token-987654"
        cr = client.post("/api/credentials", json={"name": "tg-bot", "kind": "telegram", "value": raw_secret})
        assert cr.status_code == 201
        cred_data = cr.json()
        assert cred_data["masked_value"] == "****7654"
        assert raw_secret not in json.dumps(cred_data)

        listed = client.get("/api/credentials").json()
        assert len(listed) == 1
        assert raw_secret not in json.dumps(listed)

        # Verify encrypted value in DB is not plaintext
        with get_session_factory()() as session:
            db_row = session.get(CredentialORM, cred_data["id"])
            assert db_row is not None
            assert raw_secret not in db_row.encrypted_value

        # Create scheduled workflow
        wf = client.post(
            "/api/workflows",
            json={
                "name": "Scheduled WF",
                "graph": {
                    "nodes": [
                        {"id": "t1", "type": "trigger.schedule", "params": {"mode": "interval", "interval_seconds": 60, "enabled": True}},
                        {"id": "ex", "type": "findings.export", "params": {}},
                    ],
                    "edges": [{"id": "e1", "source": "t1", "sourceHandle": "out", "target": "ex", "targetHandle": "in"}],
                },
            },
        )
        assert wf.status_code == 201
        wf_id = wf.json()["id"]
        assert f"wf_sched:{wf_id}:t1" in get_scheduler().list_job_ids()

    # Recreate app from same SQLite DB -> scheduler restores job automatically!
    app2 = create_app()
    with TestClient(app2):
        assert f"wf_sched:{wf_id}:t1" in get_scheduler().list_job_ids()


def test_full_e2e_with_logic_branching_ai_and_telegram(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'full_e2e.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.setenv("LLM_API_KEY", "fake-key-for-test")
    reload_settings()

    async def fake_llm(self, system_prompt: str, user_prompt: str) -> str:
        return json.dumps(
            {
                "summary": "Обнаружены уязвимости в Repair Desk, включая CVE-2022-42889.",
                "items": [
                    {
                        "finding_ref": "F-001",
                        "explanation": "Критичная уязвимость CVE-2022-42889 в org.apache.commons:commons-text.",
                        "risk": "Удалённое выполнение кода через интерполяцию строк.",
                        "fix_steps": ["Обновите commons-text до 1.10.0+ в build.gradle.kts"],
                    }
                ],
            }
        )

    sent_tg = []

    async def fake_tg_post(self, url, json=None, **kwargs):
        sent_tg.append(json)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 101}})

    monkeypatch.setattr(OpenAICompatibleClient, "chat_json", fake_llm)
    monkeypatch.setattr(httpx.AsyncClient, "post", fake_tg_post)

    app = create_app()
    with TestClient(app) as client:
        cred_id = client.post("/api/credentials", json={"name": "bot", "kind": "telegram", "value": "123456789:FAKE_TOKEN_ABCDEF123456"}).json()["id"]
        upload_id = client.post("/api/uploads", files={"file": ("training.zip", _zip_training(), "application/zip")}).json()["upload_id"]

        wf = client.post(
            "/api/workflows",
            json={
                "name": "Full Pipeline",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
                        {"id": "n3", "type": "scanner.secrets", "params": {}},
                        {"id": "n4", "type": "scanner.sca", "params": {}},
                        {"id": "n5", "type": "scanner.sast", "params": {}},
                        {"id": "n6", "type": "findings.merge", "params": {"deduplicate": True}},
                        {"id": "n7", "type": "ai.explain", "params": {"language": "ru"}},
                        {"id": "n8", "type": "findings.export", "params": {}},
                        {"id": "n9", "type": "logic.if_else", "params": {"left": "findings.by_severity.CRITICAL", "op": ">", "right": 0}},
                        {"id": "n10", "type": "notify.telegram", "params": {"credential_id": cred_id, "chat_id": "99999"}},
                        {"id": "n11", "type": "logic.compare", "params": {"left": "findings.count", "op": "==", "right": 0}},
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
                        {"id": "e9", "source": "n7", "sourceHandle": "report", "target": "n8", "targetHandle": "in"},
                        {"id": "e10", "source": "n8", "sourceHandle": "report", "target": "n9", "targetHandle": "in"},
                        {"id": "e11", "source": "n9", "sourceHandle": "true", "target": "n10", "targetHandle": "in"},
                        {"id": "e12", "source": "n9", "sourceHandle": "false", "target": "n11", "targetHandle": "in"},
                    ],
                },
            },
        )
        assert wf.status_code == 201, wf.text
        run = client.post(f"/api/workflows/{wf.json()['id']}/run?wait=true").json()
        assert run["status"] == "success"
        assert len(run["findings"]) == 15
        assert run["ai_report"]["validation"]["passed"] is True
        assert len(sent_tg) == 1

        det = client.get(f"/api/runs/{run['run_id']}").json()
        nr_status = {nr["node_id"]: nr["status"] for nr in det["node_runs"]}
        assert nr_status["n10"] == "success"
        assert nr_status["n11"] == "skipped"  # false branch cleanly skipped!
