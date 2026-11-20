from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import reload_settings
from app.core.masking import contains_raw_secret
from app.main import create_app
from app.scanners_impl import sast, sca, secrets
from tools.evaluate import evaluate_report
from tools.mutate_project import generate_mutated_variants

TRUTH_PATH = Path("/home/user/training/ground-truth/training-findings.json")
TRAINING_PROJECT = Path("/home/user/training/training-project")
VULN_DB_PATH = Path("/home/user/Case/backend/data/vulnerabilities.json")


def test_real_scanners_pass_mutated_variants(tmp_path: Path):
    variants = generate_mutated_variants(TRAINING_PROJECT, TRUTH_PATH, tmp_path / "mutants")
    assert len(variants) == 2

    for var in variants:
        pdir = var["project_dir"]
        truth_data = json.loads(var["truth_file"].read_text(encoding="utf-8"))
        findings = (
            secrets.scan(pdir, {})
            + sca.scan(pdir, {"vuln_db_path": str(VULN_DB_PATH)})
            + sast.scan(pdir, {})
        )
        res = evaluate_report({"findings": [f.to_submission() for f in findings]}, truth_data)
        assert res.passed, f"{var['name']} failed: missed={res.missed}, fp={res.control_false_positives}, extra={res.extra_findings}"
        assert len(res.matched) == 15
        assert res.precision == 1.0
        assert res.recall == 1.0
        assert len(res.control_false_positives) == 0


def test_secrets_scanner_individual_classes_and_controls(tmp_path: Path):
    # 1. Password + masking check
    (tmp_path / "src/main/kotlin").mkdir(parents=True)
    kt_pw = tmp_path / "src/main/kotlin/Auth.kt"
    raw_pw = "Adm!nPass987654"
    kt_pw.write_text(f'class Auth {{ private val dbPassword = "{raw_pw}" }}', encoding="utf-8")
    res_pw = secrets.scan(tmp_path, {})
    assert len(res_pw) == 1
    assert res_pw[0].class_ == "password"
    assert raw_pw not in (res_pw[0].description or "")
    assert raw_pw not in (res_pw[0].evidence or "")
    assert not contains_raw_secret(res_pw[0].description or "")

    # 2. Placeholder & env var controls
    kt_pw.write_text(
        'class Auth {\n  val apiKey = "YOUR_API_KEY"\n  val port = System.getenv("PORT") ?: "8080"\n}\n',
        encoding="utf-8",
    )
    assert secrets.scan(tmp_path, {}) == []

    # 3. Template concatenation recoverable-token + YAML spring fallback
    kt_pw.write_text(
        'fun make() {\n  val a = "tok_prefix_"\n  val b = "Xy9Zw4Qp2Lm8"\n  val full = "$a$b"\n  hdr.setBearerAuth(full)\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "src/main/resources").mkdir(parents=True)
    (tmp_path / "src/main/resources/application.yml").write_text(
        'service:\n  safeToken: "${SAFE_ENV_TOKEN}"\n  unsafeFallback: "${ENV_TOK:hardcoded_fb_9Xq2Lm7}"\n',
        encoding="utf-8",
    )
    found = secrets.scan(tmp_path, {})
    classes = {f.class_ for f in found}
    assert "recoverable-token" in classes
    assert "secret-fallback" in classes
    assert len(found) == 2


def test_sca_scanner_ranges_multi_advisory_qualifiers_and_lockfile(tmp_path: Path):
    (tmp_path / "gradle.properties").write_text("yamlVer=1.29\n", encoding="utf-8")
    (tmp_path / "build.gradle.kts").write_text(
        """
val yamlVer: String by project
dependencies {
    implementation("org.yaml:snakeyaml:$yamlVer")
    implementation("org.apache.commons:commons-lang3:3.20.0")
    implementation("org.jsoup:jsoup:1.14.1-beta1")
    implementation("com.unknown:custom-lib:$unresolvedVar")
}
""",
        encoding="utf-8",
    )
    findings = sca.scan(tmp_path, {"vuln_db_path": str(VULN_DB_PATH)})
    # snakeyaml 1.29 hits 4 advisories in vulnerabilities.json; commons-lang3:3.20.0 is safe;
    # 1.14.1-beta1 (qualifier) and $unresolvedVar (unknown) must be excluded.
    assert len(findings) == 4
    assert all(f.artifact == "snakeyaml" and f.version == "1.29" for f in findings)
    assert len({f.advisoryId for f in findings}) == 4


def test_sast_scanner_all_five_classes_and_controls(tmp_path: Path):
    pkg = tmp_path / "src/main/kotlin/demo"
    pkg.mkdir(parents=True)

    # SQLi via String.format vs safe '?'
    (pkg / "SearchController.kt").write_text(
        """
@RestController
@RequestMapping("/api/search")
class SearchController(private val jdbc: JdbcTemplate) {
    @GetMapping("/bad")
    fun bad(@RequestParam q: String) =
        jdbc.queryForList("SELECT id FROM items WHERE name = '%s'".format(q), String::class.java)

    @GetMapping("/good")
    fun good(@RequestParam q: String) =
        jdbc.queryForList("SELECT id FROM items WHERE name = ?", String::class.java, q)
}
""",
        encoding="utf-8",
    )
    # TLS empty TrustManager + safe HttpsURLConnection
    (pkg / "TlsClients.kt").write_text(
        """
class UnsafeTrust : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
}
class SafeClient {
    fun open() = URI("https://safe.example/").toURL().openConnection() as HttpsURLConnection
}
""",
        encoding="utf-8",
    )
    # CrossOrigin credentialed wildcard
    (pkg / "CorsCtrl.kt").write_text(
        '@CrossOrigin(origins = ["*"], allowCredentials = "true")\nclass CorsCtrl {}\n',
        encoding="utf-8",
    )

    found = sast.scan(tmp_path, {})
    classes = [f.class_ for f in found]
    assert classes.count("sql-injection") == 1
    assert classes.count("tls-verification") == 1
    assert classes.count("credentialed-cors") == 1


def test_llm_settings_and_uploads_list_endpoints(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'settings.db'}")
    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("SECRET_KEY_FILE", str(tmp_path / "secret.key"))
    monkeypatch.setenv("LLM_API_KEY", "")
    reload_settings()

    app = create_app()
    with TestClient(app) as client:
        cur = client.get("/api/settings/llm").json()
        assert cur["base_url"]
        assert cur["has_api_key"] is False

        secret_key = "sk-test-provider-key-987654321"
        updated = client.put(
            "/api/settings/llm",
            json={
                "base_url": "http://localhost:11434/v1",
                "model": "qwen2.5-coder:7b",
                "api_key": secret_key,
            },
        )
        assert updated.status_code == 200
        body = updated.json()
        assert body["base_url"] == "http://localhost:11434/v1"
        assert body["model"] == "qwen2.5-coder:7b"
        assert body["has_api_key"] is True
        assert secret_key not in json.dumps(body)

        # Uploads list initially empty
        assert client.get("/api/uploads").json() == []
