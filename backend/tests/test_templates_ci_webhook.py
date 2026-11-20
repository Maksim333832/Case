from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.config import reload_settings
from app.main import create_app

TRAINING_PROJECT = Path("/home/user/training/training-project")


def _zip_training() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in TRAINING_PROJECT.rglob("*"):
            if f.is_file():
                zf.write(f, arcname=f"training/training-project/{f.relative_to(TRAINING_PROJECT).as_posix()}")
    return buf.getvalue()


def test_webhook_and_smtp_discovered_with_zero_engine_edits(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'wh.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    reload_settings()

    received_hooks = []

    async def fake_request(self, method, url, json=None, headers=None, **kwargs):
        received_hooks.append({"method": method, "url": url, "json": json, "headers": headers})
        return httpx.Response(200, json={"accepted": True})

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)

    app = create_app()
    with TestClient(app) as client:
        node_types = {item["type"] for item in client.get("/api/node-types").json()}
        assert "notify.webhook" in node_types
        assert "notify.smtp" in node_types

        cred_id = client.post("/api/credentials", json={"name": "wh-auth", "kind": "webhook", "value": "hook-secret-XYZ123"}).json()["id"]
        upload_id = client.post("/api/uploads", files={"file": ("training.zip", _zip_training(), "application/zip")}).json()["upload_id"]

        wf = client.post(
            "/api/workflows",
            json={
                "name": "Webhook Test",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
                        {"id": "n3", "type": "scanner.sca", "params": {}},
                        {"id": "n4", "type": "findings.export", "params": {}},
                        {
                            "id": "n5",
                            "type": "notify.webhook",
                            "params": {
                                "url": "https://hooks.repairdesk.invalid/sec",
                                "credential_id": cred_id,
                            },
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
        run = client.post(f"/api/workflows/{wf.json()['id']}/run?wait=true").json()
        assert run["status"] == "success"
        assert len(received_hooks) == 1
        assert received_hooks[0]["headers"]["Authorization"] == "Bearer hook-secret-XYZ123"
        assert received_hooks[0]["json"]["count"] == 5


def test_templates_seed_copy_and_publish(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'tpl.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    reload_settings()

    app = create_app()
    with TestClient(app) as client:
        templates = client.get("/api/templates").json()
        tpl_ids = {t["id"] for t in templates}
        assert {"tpl_full_security_audit", "tpl_scheduled_git_audit", "tpl_ci_pr_gate"}.issubset(tpl_ids)

        up_id = client.post("/api/uploads", files={"file": ("training.zip", _zip_training(), "application/zip")}).json()["upload_id"]

        copied = client.post(
            "/api/templates/tpl_full_security_audit/copy",
            json={
                "name": "My Repair Desk Audit",
                "param_overrides": {"source.upload_zip": {"upload_id": up_id}},
            },
        )
        assert copied.status_code == 201
        wf_copy = copied.json()
        assert wf_copy["is_template"] is False
        assert wf_copy["name"] == "My Repair Desk Audit"
        src_node = next(n for n in wf_copy["graph"]["nodes"] if n["type"] == "source.upload_zip")
        assert src_node["params"]["upload_id"] == up_id

        # Publish custom workflow as template
        pub = client.post(
            f"/api/workflows/{wf_copy['id']}/publish",
            json={"name": "Published Team Audit"},
        )
        assert pub.status_code == 201
        assert pub.json()["is_template"] is True
        assert pub.json()["name"] == "Published Team Audit"


def test_ci_endpoint_auth_gate_and_config_generation(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'ci.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "0")
    monkeypatch.setenv("CI_API_TOKEN", "ci-super-secret-token")
    reload_settings()

    app = create_app()
    with TestClient(app) as client:
        up_id = client.post("/api/uploads", files={"file": ("training.zip", _zip_training(), "application/zip")}).json()["upload_id"]
        wf = client.post(
            "/api/workflows",
            json={
                "name": "CI Gate WF",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": up_id}},
                        {"id": "n3", "type": "scanner.secrets", "params": {}},
                        {"id": "n4", "type": "scanner.sca", "params": {}},
                        {"id": "n5", "type": "scanner.sast", "params": {}},
                        {"id": "n6", "type": "findings.merge", "params": {"deduplicate": True}},
                        {"id": "n7", "type": "findings.export", "params": {}},
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
        wf_id = wf.json()["id"]

        # Unauthenticated rejected
        unauth = client.post(f"/api/ci/workflows/{wf_id}/run")
        assert unauth.status_code == 401

        # Authenticated with strict_http=True fails gate on HIGH/CRITICAL findings (returns 422)
        ci_fail = client.post(
            f"/api/ci/workflows/{wf_id}/run",
            headers={"X-CI-Token": "ci-super-secret-token"},
            json={"fail_on_severity": "HIGH", "strict_http": True},
        )
        assert ci_fail.status_code == 422
        body = ci_fail.json()
        assert body["gate_passed"] is False
        assert body["total_findings_count"] == 15
        assert body["blocking_findings_count"] > 0

        # Generate GitHub & GitLab CI snippets
        gh_yaml = client.get(f"/api/ci/workflows/{wf_id}/config?provider=github")
        gl_yaml = client.get(f"/api/ci/workflows/{wf_id}/config?provider=gitlab")
        assert gh_yaml.status_code == 200 and "secrets.SECURITY_PLATFORM_URL" in gh_yaml.text
        assert gl_yaml.status_code == 200 and "merge_request_event" in gl_yaml.text
