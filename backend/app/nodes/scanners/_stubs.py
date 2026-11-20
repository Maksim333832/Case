"""Development-only reference stub scanners strictly gated behind USE_STUB_SCANNERS=1.

WARNING: These stubs exist solely to verify the platform pipeline and evaluator during
development while team scanner modules (members 3 & 4) are in progress. They are
strictly disabled by default (USE_STUB_SCANNERS=0).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.core.models import Finding

logger = logging.getLogger(__name__)


def _has_marker(root: Path, rel_path: str, needle: str) -> bool:
    target = root / rel_path
    if not target.is_file():
        return False
    try:
        return needle in target.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


def scan_secrets_stub(root: Path, params: dict[str, Any]) -> list[Finding]:
    logger.warning("DEV STUB ACTIVE (USE_STUB_SCANNERS=1): scan_secrets_stub on %s", root.name)
    out: list[Finding] = []
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt", "legacyImportPassword"):
        out.append(
            Finding(
                category="SECRET",
                path="src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt",
                **{"class": "password"},
                line=4,
                endLine=4,
                severity="HIGH",
                description="Hardcoded service import password detected in legacyImportPassword",
                remediation="Move import password to environment variable or secret vault",
                evidence="cg26****Qp",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt", "pricingApiKey"):
        out.append(
            Finding(
                category="SECRET",
                path="src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
                **{"class": "api-key"},
                line=7,
                endLine=7,
                severity="MEDIUM",
                description="Hardcoded API key passed in X-Api-Key header",
                remediation="Load pricing API key from runtime configuration",
                evidence="cg26****6c",
            )
        )
    if _has_marker(root, "src/main/resources/application.yml", "pickup:") and _has_marker(
        root, "src/main/resources/application.yml", "cg26_pickup_"
    ):
        out.append(
            Finding(
                category="SECRET",
                path="src/main/resources/application.yml",
                **{"class": "configuration-token"},
                line=13,
                endLine=13,
                severity="HIGH",
                description="Hardcoded Bearer authorization token in application.yml",
                remediation="Reference environment variable instead of embedding bearer token",
                evidence="Bearer cg26****zN",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt", "DEPOT_STATUS_TOKEN"):
        out.append(
            Finding(
                category="SECRET",
                path="src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt",
                **{"class": "secret-fallback"},
                line=8,
                endLine=8,
                severity="LOW",
                description="Fallback literal token used when DEPOT_STATUS_TOKEN env var is missing",
                remediation="Fail fast when required token environment variable is unset",
                evidence="cg26****qT",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt", "cg26_warranty_"):
        out.append(
            Finding(
                category="SECRET",
                path="src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt",
                **{"class": "recoverable-token"},
                line=7,
                endLine=10,
                severity="MEDIUM",
                description="Bearer token assembled from concatenated string literals",
                remediation="Inject warranty bearer token from external secret storage",
                evidence="cg26****Q9",
            )
        )
    return out


def scan_sca_stub(root: Path, params: dict[str, Any]) -> list[Finding]:
    logger.warning("DEV STUB ACTIVE (USE_STUB_SCANNERS=1): scan_sca_stub on %s", root.name)
    vuln_db_path = Path(str(params.get("vuln_db_path", "")))
    if not vuln_db_path.is_file():
        return []

    out: list[Finding] = []
    gradle_rel = "build.gradle.kts"
    if _has_marker(root, gradle_rel, "org.apache.commons:commons-text:1.9"):
        out.append(
            Finding(
                category="SCA",
                path=gradle_rel,
                group="org.apache.commons",
                artifact="commons-text",
                version="1.9",
                advisoryId="CVE-2022-42889",
                aliases=["GHSA-599f-7c49-w659"],
                severity="CRITICAL",
                description="commons-text 1.9 vulnerable to arbitrary script/lookup interpolation (Text4Shell)",
                remediation="Upgrade org.apache.commons:commons-text to 1.10.0+",
            )
        )
    if _has_marker(root, gradle_rel, "org.jsoup:jsoup:1.14.1"):
        out.append(
            Finding(
                category="SCA",
                path=gradle_rel,
                group="org.jsoup",
                artifact="jsoup",
                version="1.14.1",
                advisoryId="CVE-2021-37714",
                aliases=["GHSA-m72m-mhq2-9p6c"],
                severity="HIGH",
                description="jsoup 1.14.1 vulnerable to DoS when parsing crafted HTML input",
                remediation="Upgrade org.jsoup:jsoup to 1.14.2+",
            )
        )
    if _has_marker(root, gradle_rel, "archiveFormatVersion = \"1.25.0\"") and _has_marker(
        root, gradle_rel, "commons-compress:$archiveFormatVersion"
    ):
        out.append(
            Finding(
                category="SCA",
                path=gradle_rel,
                group="org.apache.commons",
                artifact="commons-compress",
                version="1.25.0",
                advisoryId="CVE-2024-25710",
                aliases=["GHSA-4g9r-vxhx-9pgx"],
                severity="MEDIUM",
                description="commons-compress 1.25.0 vulnerable to infinite loop in DUMP archive parsing",
                remediation="Upgrade org.apache.commons:commons-compress to 1.26.0+",
            )
        )
    if _has_marker(root, gradle_rel, "commons-net:commons-net:3.8.0"):
        out.append(
            Finding(
                category="SCA",
                path=gradle_rel,
                group="commons-net",
                artifact="commons-net",
                version="3.8.0",
                advisoryId="CVE-2021-37533",
                aliases=["GHSA-cgp8-4m63-fhh5"],
                severity="MEDIUM",
                description="commons-net 3.8.0 FTP client trusts PASV host responses without validation",
                remediation="Upgrade commons-net:commons-net to 3.9.0+",
            )
        )
    if _has_marker(root, gradle_rel, "legacyManifestJsonVersion") and _has_marker(
        root, "gradle.properties", "legacyManifestJsonVersion=20230227"
    ):
        out.append(
            Finding(
                category="SCA",
                path=gradle_rel,
                group="org.json",
                artifact="json",
                version="20230227",
                advisoryId="CVE-2023-5072",
                aliases=["GHSA-4jq9-2xhw-jpx7"],
                severity="HIGH",
                description="org.json 20230227 vulnerable to DoS via nested JSONObject keys",
                remediation="Upgrade org.json:json to 20231013+",
            )
        )
    return out


def scan_sast_stub(root: Path, params: dict[str, Any]) -> list[Finding]:
    logger.warning("DEV STUB ACTIVE (USE_STUB_SCANNERS=1): scan_sast_stub on %s", root.name)
    out: list[Finding] = []
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt", "frame_tag = '$frameTag'"):
        out.append(
            Finding(
                category="SAST",
                path="src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt",
                **{"class": "sql-injection"},
                line=13,
                endLine=14,
                severity="HIGH",
                description="HTTP request parameter interpolated directly into SQL query",
                remediation="Use parameterized query placeholder '?' in JdbcTemplate",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt", "HostnameVerifier { _, _ -> true }"):
        out.append(
            Finding(
                category="SAST",
                path="src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt",
                **{"class": "tls-verification"},
                line=13,
                endLine=13,
                severity="MEDIUM",
                description="TLS hostname verification disabled via permissive HostnameVerifier",
                remediation="Remove custom trust-all HostnameVerifier and validate certificates properly",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/config/RepairCors.kt", "allowedOriginPatterns = listOf(\"*\")"):
        out.append(
            Finding(
                category="SAST",
                path="src/main/kotlin/lab/repairdesk/config/RepairCors.kt",
                **{"class": "credentialed-cors"},
                line=13,
                endLine=14,
                severity="MEDIUM",
                description="Wildcard origin pattern combined with allowCredentials=true on private endpoint",
                remediation="Restrict allowedOriginPatterns to trusted frontend origins",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt", '"/api/pickup/export").permitAll()'):
        out.append(
            Finding(
                category="SAST",
                path="src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt",
                **{"class": "route-authorization"},
                line=18,
                endLine=18,
                severity="HIGH",
                description="Sensitive /api/pickup/export route permits unauthenticated access before MECHANIC role rule",
                remediation="Require MECHANIC role on /api/pickup/export",
            )
        )
    if _has_marker(root, "src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt", "WHERE ticket_id = ?") and _has_marker(
        root, "src/main/kotlin/lab/repairdesk/repair/RepairTicketController.kt", "reader.read(ticketId)"
    ):
        out.append(
            Finding(
                category="SAST",
                path="src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt",
                **{"class": "object-authorization"},
                line=10,
                endLine=11,
                severity="HIGH",
                description="Ticket fetched solely by ticketId without verifying ownership against authenticated Principal",
                remediation="Filter ticket query by authenticated Principal customerId",
            )
        )
    return out
