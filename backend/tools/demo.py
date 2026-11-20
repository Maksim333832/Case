from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import zipfile
from pathlib import Path

from tools.evaluate import evaluate_report, format_evaluation_summary


def _zip_dir(project_dir: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in project_dir.rglob("*"):
            if f.is_file():
                zf.write(f, arcname=f"{project_dir.name}/{f.relative_to(project_dir).as_posix()}")
    return buf.getvalue()


def run_demo(
    project_dir: Path,
    truth_path: Path | None = None,
    use_stubs: bool = False,
) -> int:
    if use_stubs:
        os.environ["USE_STUB_SCANNERS"] = "1"

    tmp_dir = Path(tempfile.mkdtemp(prefix="aisec_demo_"))
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_dir / 'demo.db'}"
    os.environ["UPLOADS_DIR"] = str(tmp_dir / "uploads")
    os.environ["ARTIFACTS_DIR"] = str(tmp_dir / "runs")
    os.environ["RUNS_DIR"] = str(tmp_dir / "tmp_runs")

    from fastapi.testclient import TestClient

    from app.config import reload_settings
    from app.main import create_app

    reload_settings()
    app = create_app()

    with TestClient(app) as client:
        print("[1/5] Checking /health and /api/node-types...")
        health = client.get("/health").json()
        node_types = client.get("/api/node-types").json()
        print(f"      Status={health['status']}, registered nodes={len(node_types)}, use_stub_scanners={health['use_stub_scanners']}")

        print("[2/5] Uploading project ZIP archive...")
        zip_bytes = _zip_dir(project_dir)
        up = client.post("/api/uploads", files={"file": (f"{project_dir.name}.zip", zip_bytes, "application/zip")})
        up.raise_for_status()
        upload_id = up.json()["upload_id"]
        print(f"      upload_id={upload_id}")

        print("[3/5] Creating workflow from template 'tpl_full_security_audit'...")
        wf_resp = client.post(
            "/api/templates/tpl_full_security_audit/copy",
            json={
                "name": f"Demo Audit: {project_dir.name}",
                "param_overrides": {"source.upload_zip": {"upload_id": upload_id}},
            },
        )
        wf_resp.raise_for_status()
        wf_id = wf_resp.json()["id"]

        # Drop Telegram notify node for local offline demo if no chat_id configured
        wf = wf_resp.json()
        wf["graph"]["nodes"] = [n for n in wf["graph"]["nodes"] if n["type"] != "notify.telegram"]
        wf["graph"]["edges"] = [e for e in wf["graph"]["edges"] if e["target"] != "n10"]
        client.put(f"/api/workflows/{wf_id}", json={"graph": wf["graph"]}).raise_for_status()

        print("[4/5] Running workflow (wait=true)...")
        run_resp = client.post(f"/api/workflows/{wf_id}/run?wait=true")
        run_resp.raise_for_status()
        run_data = run_resp.json()
        run_id = run_data["run_id"]
        print(f"      run_id={run_id}, status={run_data['status']}, findings={len(run_data.get('findings', []))}")
        if run_data.get("ai_report"):
            print(f"      AI validation={run_data['ai_report'].get('validation')}")

        rep_json = client.get(f"/api/runs/{run_id}/report.json")
        rep_md = client.get(f"/api/runs/{run_id}/report.md")
        rep_json.raise_for_status()
        rep_md.raise_for_status()

        out_json_path = tmp_dir / "report.json"
        out_md_path = tmp_dir / "report.md"
        out_json_path.write_text(rep_json.text, encoding="utf-8")
        out_md_path.write_text(rep_md.text, encoding="utf-8")
        print(f"      Saved {out_json_path} and {out_md_path}")

        if truth_path and truth_path.is_file():
            print("[5/5] Evaluating report.json against ground-truth...")
            res = evaluate_report(rep_json.json(), json.loads(truth_path.read_text(encoding="utf-8")))
            print(format_evaluation_summary(res))
            return 0 if res.passed else 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="End-to-end demo runner for AI Security Workflow backend")
    parser.add_argument("--project", default="/home/user/training/training-project", help="Path to Gradle project root")
    parser.add_argument("--truth", default="/home/user/training/ground-truth/training-findings.json", help="Optional path to truth JSON")
    parser.add_argument("--use-stubs", action="store_true", help="Enable dev stub scanners (USE_STUB_SCANNERS=1)")
    args = parser.parse_args(argv)
    return run_demo(Path(args.project), Path(args.truth) if args.truth else None, use_stubs=args.use_stubs)


if __name__ == "__main__":
    raise SystemExit(main())
