from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.crypto import decrypt_secret, encrypt_secret, mask_credential_value
from app.core.db import CredentialORM, WorkflowORM, get_session_factory, init_db
from app.core.logging import SecretMaskingFilter
from app.core.masking import clear_runtime_secrets, contains_raw_secret, mask_secret, mask_text, register_runtime_secret
from app.core.models import Finding
from app.core.severity import max_severity, severity_counts
from app.main import create_app
from app.nodes.registry import discover_nodes, list_node_types
from app.nodes.scanners.base import ScannerNotConfiguredError, resolve_scanner_callable


def test_finding_secret_submission_contract():
    f = Finding(
        category="SECRET",
        path="src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
        **{"class": "api-key"},
        line=7,
        endLine=7,
        severity="MEDIUM",
        description="Embedded API key in header",
        id="internal-1",
        rule_id="sec-02",
        evidence="cg26****6c",
        confidence=0.95,
    )
    sub = f.to_submission()
    assert sub == {
        "category": "SECRET",
        "path": "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
        "class": "api-key",
        "line": 7,
        "endLine": 7,
        "severity": "MEDIUM",
        "description": "Embedded API key in header",
    }
    assert "id" not in sub
    assert "rule_id" not in sub
    assert "evidence" not in sub
    assert "confidence" not in sub


def test_finding_sca_submission_contract():
    f = Finding(
        category="SCA",
        path="build.gradle.kts",
        group="org.apache.commons",
        artifact="commons-text",
        version="1.9",
        advisoryId="CVE-2022-42889",
        aliases=["GHSA-599f-7c49-w659"],
    )
    sub = f.to_submission()
    assert sub == {
        "category": "SCA",
        "path": "build.gradle.kts",
        "group": "org.apache.commons",
        "artifact": "commons-text",
        "version": "1.9",
        "advisoryId": "CVE-2022-42889",
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"category": "SECRET", "path": "/abs/file.kt", "class": "api-key", "line": 1},
        {"category": "SECRET", "path": "../escape.kt", "class": "api-key", "line": 1},
        {"category": "SECRET", "path": "C:secret.kt", "class": "api-key", "line": 1},
        {"category": "SECRET", "path": "a.kt", "class": "api-key", "line": "13"},
        {"category": "SECRET", "path": "a.kt", "class": "api-key", "line": True},
        {"category": "SECRET", "path": "a.kt", "class": "api-key", "line": 5, "endLine": 4},
        {"category": "SECRET", "path": "a.kt", "class": "api-key", "line": 5, "endLine": 20},
        {"category": "SAST", "path": "a.kt", "line": 5},
        {"category": "SCA", "path": "build.gradle.kts", "group": "g", "artifact": "a", "version": "1.0"},
    ],
)
def test_finding_strict_validators(kwargs):
    with pytest.raises(Exception):
        Finding(**kwargs)


def test_severity_helpers():
    findings = [
        Finding(category="SECRET", path="a.kt", **{"class": "api-key"}, line=1, severity="LOW"),
        Finding(category="SAST", path="b.kt", **{"class": "sql-injection"}, line=2, severity="HIGH"),
    ]
    assert max_severity(findings) == "HIGH"
    assert severity_counts(findings) == {"LOW": 1, "HIGH": 1}


def test_masking_and_logging_filter():
    clear_runtime_secrets()
    secret = "cg26_parts_H9r4Vm2Kb6Qp"
    register_runtime_secret(secret)
    try:
        assert mask_secret(secret).startswith("cg26****")
        assert secret not in mask_text(f"token={secret} and Bearer xyz123456789")
        assert contains_raw_secret(f"leak {secret}") is True
        assert contains_raw_secret(mask_text(f"leak {secret}")) is False
        assert contains_raw_secret("Hardcoded Bearer authorization token in application.yml") is False

        filt = SecretMaskingFilter()
        rec = logging.LogRecord("test", logging.INFO, __file__, 1, "Attempt with %s", (secret,), None)
        filt.filter(rec)
        assert secret not in rec.getMessage()
    finally:
        clear_runtime_secrets()


def test_fernet_encryption_outside_repo(tmp_path: Path):
    key_file = tmp_path / "outside_secret.key"
    cfg = Settings(app_secret_key="", secret_key_file=key_file)
    token = encrypt_secret("super-bot-token-12345", settings=cfg)
    assert "super-bot-token-12345" not in token
    assert decrypt_secret(token, settings=cfg) == "super-bot-token-12345"
    assert key_file.exists()
    assert mask_credential_value("1000000001:FAKE_TEST_BOT_TOKEN_WndZ") == "****WndZ"


def test_stubs_disabled_by_default(monkeypatch):
    cfg = Settings()
    assert cfg.use_stub_scanners is False
    # By default real scanners from app.scanners_impl.* resolve cleanly
    fn = resolve_scanner_callable("secrets", cfg)
    assert fn.__module__ == "app.scanners_impl.secrets"

    # When implementation module is missing/unconfigured and stubs are disabled, raise ScannerNotConfiguredError
    import importlib

    real_import = importlib.import_module

    def fake_import(name: str, *args, **kwargs):
        if name.startswith("app.scanners_impl."):
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    with pytest.raises(ScannerNotConfiguredError):
        resolve_scanner_callable("secrets", cfg)


def test_db_tables_created(tmp_path: Path):
    db_path = tmp_path / "test.db"
    init_db(f"sqlite:///{db_path}")
    factory = get_session_factory()
    with factory() as session:
        session.add(WorkflowORM(id="wf1", name="Test WF", graph_json='{"nodes":[],"edges":[]}'))
        session.add(CredentialORM(id="cr1", name="tg", kind="telegram", encrypted_value="enc"))
        session.commit()
        assert session.get(WorkflowORM, "wf1") is not None


def test_node_registry_and_api_node_types(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    from app.config import reload_settings

    reload_settings()
    nodes = discover_nodes(force=True)
    expected_types = {
        "trigger.manual",
        "trigger.schedule",
        "source.upload_zip",
        "source.git_clone",
        "logic.if_else",
        "logic.compare",
        "logic.regex",
        "scanner.secrets",
        "scanner.sca",
        "scanner.sast",
        "findings.merge",
        "findings.export",
        "ai.explain",
        "notify.telegram",
    }
    assert expected_types.issubset(set(nodes.keys()))

    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/api/node-types")
        assert resp.status_code == 200
        items = resp.json()
        returned_types = {item["type"] for item in items}
        assert expected_types.issubset(returned_types)
        if_else = next(i for i in items if i["type"] == "logic.if_else")
        assert [o["name"] for o in if_else["outputs"]] == ["true", "false"]
        assert "properties" in if_else["params_schema"]
