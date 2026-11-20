from __future__ import annotations

import asyncio
import io
import json
import stat
import zipfile
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, reload_settings
from app.core.models import Finding, WorkflowGraphModel
from app.engine.graph import WorkflowValidationError, validate_and_sort_graph
from app.main import create_app
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node, unregister_node
from app.nodes.source._project_root import detect_gradle_project_root, safe_extract_zip, validate_repo_allowlist


def _make_training_zip_bytes(wrap_folder: str = "training-repo") -> bytes:
    buf = io.BytesIO()
    src_root = Path("/home/user/training/training-project")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in src_root.rglob("*"):
            if f.is_file():
                rel = f.relative_to(src_root).as_posix()
                zf.write(f, arcname=f"{wrap_folder}/training-project/{rel}")
    return buf.getvalue()


def test_graph_validation_cycle_and_triggers():
    # Cycle rejected
    cycle = WorkflowGraphModel(
        nodes=[
            {"id": "t", "type": "trigger.manual", "params": {}},
            {"id": "a", "type": "logic.if_else", "params": {"left": "findings.count", "op": ">", "right": 0}},
            {"id": "b", "type": "logic.compare", "params": {"left": "findings.count", "op": "==", "right": 1}},
        ],
        edges=[
            {"id": "e1", "source": "t", "sourceHandle": "out", "target": "a", "targetHandle": "in"},
            {"id": "e2", "source": "a", "sourceHandle": "true", "target": "b", "targetHandle": "in"},
            {"id": "e3", "source": "b", "sourceHandle": "true", "target": "a", "targetHandle": "in"},
        ],
    )
    with pytest.raises(WorkflowValidationError) as exc_info:
        validate_and_sort_graph(cycle)
    assert any("cycle" in e.lower() for e in exc_info.value.errors)

    # Zero triggers rejected
    no_trigger = WorkflowGraphModel(
        nodes=[
            {"id": "s", "type": "source.upload_zip", "params": {"upload_id": "up1"}},
            {"id": "sc", "type": "scanner.secrets", "params": {}},
        ],
        edges=[{"id": "e1", "source": "s", "sourceHandle": "workspace", "target": "sc", "targetHandle": "workspace"}],
    )
    with pytest.raises(WorkflowValidationError) as exc_info2:
        validate_and_sort_graph(no_trigger)
    assert any("trigger" in e.lower() for e in exc_info2.value.errors)

    # Multiple triggers in same connected component rejected
    two_triggers = WorkflowGraphModel(
        nodes=[
            {"id": "t1", "type": "trigger.manual", "params": {}},
            {"id": "t2", "type": "trigger.schedule", "params": {}},
            {"id": "ex", "type": "findings.export", "params": {}},
        ],
        edges=[
            {"id": "e1", "source": "t1", "sourceHandle": "out", "target": "ex", "targetHandle": "in"},
            {"id": "e2", "source": "t2", "sourceHandle": "out", "target": "ex", "targetHandle": "in"},
        ],
    )
    with pytest.raises(WorkflowValidationError) as exc_info3:
        validate_and_sort_graph(two_triggers)
    assert any("multiple trigger" in e.lower() for e in exc_info3.value.errors)

    # Port kind mismatch rejected
    bad_port = WorkflowGraphModel(
        nodes=[
            {"id": "t", "type": "trigger.manual", "params": {}},
            {"id": "s", "type": "source.upload_zip", "params": {"upload_id": "up1"}},
            {"id": "m", "type": "findings.merge", "params": {}},
        ],
        edges=[
            {"id": "e1", "source": "t", "sourceHandle": "out", "target": "s", "targetHandle": "trigger"},
            {"id": "e2", "source": "s", "sourceHandle": "workspace", "target": "m", "targetHandle": "in"},
        ],
    )
    with pytest.raises(WorkflowValidationError) as exc_info4:
        validate_and_sort_graph(bad_port)
    assert any("incompatible" in e.lower() for e in exc_info4.value.errors)


def test_zip_slip_symlink_and_project_root_detection(tmp_path: Path):
    # Zip-slip attempt
    slip_zip = tmp_path / "slip.zip"
    with zipfile.ZipFile(slip_zip, "w") as zf:
        zf.writestr("../../evil.txt", "pwned")
    with pytest.raises(ValueError, match="traversal|Zip-slip"):
        safe_extract_zip(slip_zip, tmp_path / "out1", max_files=100, max_total_bytes=1_000_000)

    # Symlink attempt
    sym_zip = tmp_path / "sym.zip"
    with zipfile.ZipFile(sym_zip, "w") as zf:
        zi = zipfile.ZipInfo("link")
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zi, "/etc/passwd")
    with pytest.raises(ValueError, match="symlink"):
        safe_extract_zip(sym_zip, tmp_path / "out2", max_files=100, max_total_bytes=1_000_000)

    # Nested training-project auto-detection
    ok_zip = tmp_path / "ok.zip"
    ok_zip.write_bytes(_make_training_zip_bytes("repo-main"))
    out3 = tmp_path / "out3"
    safe_extract_zip(ok_zip, out3, max_files=500, max_total_bytes=10_000_000)
    detected = detect_gradle_project_root(out3)
    assert detected == (out3 / "repo-main" / "training-project").resolve()


def test_git_allowlist():
    allow = ["https://github.com/TBagirov/training"]
    assert validate_repo_allowlist("https://github.com/TBagirov/training", allow) == "https://github.com/TBagirov/training"
    assert validate_repo_allowlist("https://github.com/TBagirov/training.git", allow) == "https://github.com/TBagirov/training.git"
    with pytest.raises(PermissionError):
        validate_repo_allowlist("https://github.com/evil/other", allow)
    with pytest.raises(ValueError):
        validate_repo_allowlist("file:///tmp/training", allow)
    with pytest.raises(ValueError):
        validate_repo_allowlist("https://user@github.com/TBagirov/training", allow)


def test_node_failure_isolation_and_timeout(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'fail.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("NODE_TIMEOUT_SECONDS", "1")
    reload_settings()

    @register_node
    class _FailNode(BaseNode):
        type = "test.fail_always"
        label = "Fail"
        group = "logic"
        inputs = [Port(name="in", kind="Any")]
        outputs = [Port(name="out", kind="Any")]

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params):
            raise RuntimeError("boom secret=cg26_raw_secret_value_123")

    @register_node
    class _SlowNode(BaseNode):
        type = "test.slow"
        label = "Slow"
        group = "logic"
        inputs = [Port(name="in", kind="Any")]
        outputs = [Port(name="out", kind="Any")]

        async def run(self, ctx: NodeContext, inputs: dict[str, Any], params):
            await asyncio.sleep(5)
            return {"out": "done"}

    app = create_app()
    try:
        with TestClient(app) as client:
            wf_resp = client.post(
                "/api/workflows",
                json={
                    "name": "Failure Isolation WF",
                    "graph": {
                        "nodes": [
                            {"id": "t1", "type": "trigger.manual", "params": {}},
                            {"id": "f1", "type": "test.fail_always", "params": {}},
                            {"id": "after_fail", "type": "findings.export", "params": {}},
                            {"id": "t2", "type": "trigger.manual", "params": {}},
                            {"id": "ok_exp", "type": "findings.export", "params": {}},
                        ],
                        "edges": [
                            {"id": "e1", "source": "t1", "sourceHandle": "out", "target": "f1", "targetHandle": "in"},
                            {"id": "e2", "source": "f1", "sourceHandle": "out", "target": "after_fail", "targetHandle": "in"},
                            {"id": "e3", "source": "t2", "sourceHandle": "out", "target": "ok_exp", "targetHandle": "in"},
                        ],
                    },
                },
            )
            assert wf_resp.status_code == 201, wf_resp.text
            wf_id = wf_resp.json()["id"]

            run_resp = client.post(f"/api/workflows/{wf_id}/run?wait=true")
            assert run_resp.status_code == 200
            body = run_resp.json()
            assert body["status"] == "partial"

            details = client.get(f"/api/runs/{body['run_id']}").json()
            statuses = {nr["node_id"]: nr for nr in details["node_runs"]}
            assert statuses["f1"]["status"] == "failed"
            assert "cg26_raw_secret_value_123" not in (statuses["f1"]["error"] or "")
            assert statuses["after_fail"]["status"] == "skipped"
            assert statuses["ok_exp"]["status"] == "success"

            # Timeout test
            wf_slow = client.post(
                "/api/workflows",
                json={
                    "name": "Timeout WF",
                    "graph": {
                        "nodes": [
                            {"id": "t1", "type": "trigger.manual", "params": {}},
                            {"id": "s1", "type": "test.slow", "params": {}},
                        ],
                        "edges": [
                            {"id": "e1", "source": "t1", "sourceHandle": "out", "target": "s1", "targetHandle": "in"}
                        ],
                    },
                },
            )
            run_slow = client.post(f"/api/workflows/{wf_slow.json()['id']}/run?wait=true").json()
            assert run_slow["status"] == "failed"
            slow_det = client.get(f"/api/runs/{run_slow['run_id']}").json()
            assert slow_det["node_runs"][1]["status"] == "failed"
            assert "Timeout" in (slow_det["node_runs"][1]["error"] or "")
    finally:
        unregister_node("test.fail_always")
        unregister_node("test.slow")


def test_e2e_phase_b_upload_scan_merge_export_and_ws(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'e2e_b.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("RUNS_DIR", str(tmp_path / "tmp_runs"))
    monkeypatch.setenv("USE_STUB_SCANNERS", "1")
    reload_settings()

    # Use a temporary stub returning 2 distinct findings + 1 duplicate to test merge + export
    from app.nodes.scanners import _stubs

    sample_secret = Finding(
        category="SECRET",
        path="src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
        **{"class": "api-key"},
        line=7,
        severity="MEDIUM",
        description="API key used in X-Api-Key header",
        evidence="cg26****6c",
    )
    sample_sca = Finding(
        category="SCA",
        path="build.gradle.kts",
        group="org.apache.commons",
        artifact="commons-text",
        version="1.9",
        advisoryId="CVE-2022-42889",
        severity="CRITICAL",
    )
    monkeypatch.setattr(_stubs, "scan_secrets_stub", lambda root, params: [sample_secret, sample_secret])
    monkeypatch.setattr(_stubs, "scan_sca_stub", lambda root, params: [sample_sca])
    monkeypatch.setattr(_stubs, "scan_sast_stub", lambda root, params: [])

    app = create_app()
    with TestClient(app) as client:
        # 1. Upload zip
        up_resp = client.post(
            "/api/uploads",
            files={"file": ("training.zip", _make_training_zip_bytes(), "application/zip")},
        )
        assert up_resp.status_code == 201
        upload_id = up_resp.json()["upload_id"]

        # 2. Create workflow: Manual -> Upload -> [Secrets, SCA, SAST] -> Merge -> Export
        wf_resp = client.post(
            "/api/workflows",
            json={
                "name": "Phase B E2E",
                "graph": {
                    "nodes": [
                        {"id": "n1", "type": "trigger.manual", "params": {}},
                        {"id": "n2", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
                        {"id": "n3", "type": "scanner.secrets", "params": {}},
                        {"id": "n4", "type": "scanner.sca", "params": {}},
                        {"id": "n5", "type": "scanner.sast", "params": {}},
                        {"id": "n6", "type": "findings.merge", "params": {"deduplicate": True}},
                        {"id": "n7", "type": "findings.export", "params": {"title": "Repair Desk Report"}},
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
        assert wf_resp.status_code == 201, wf_resp.text
        wf_id = wf_resp.json()["id"]

        # 3. Run workflow synchronously (?wait=true)
        run_resp = client.post(f"/api/workflows/{wf_id}/run?wait=true")
        assert run_resp.status_code == 200
        run_data = run_resp.json()
        assert run_data["status"] == "success"
        run_id = run_data["run_id"]
        assert len(run_data["findings"]) == 2  # deduplicated + sorted CRITICAL first
        assert run_data["findings"][0]["category"] == "SCA"

        # 4. Verify report.json & report.md consistency
        r_json = client.get(f"/api/runs/{run_id}/report.json")
        r_md = client.get(f"/api/runs/{run_id}/report.md")
        assert r_json.status_code == 200
        assert r_md.status_code == 200
        parsed_json = r_json.json()
        assert len(parsed_json["findings"]) == 2
        assert "CVE-2022-42889" in r_md.text
        assert "QuoteRequest.kt:7" in r_md.text

        # 5. Verify WS replays accumulated history
        with client.websocket_connect(f"/ws/runs/{run_id}") as ws:
            events = []
            while True:
                ev = ws.receive_json()
                events.append(ev)
                if ev["event"] == "run_finished":
                    break
            ev_names = [e["event"] for e in events]
            assert ev_names[0] == "run_started"
            assert "node_finished" in ev_names
            assert ev_names[-1] == "run_finished"
