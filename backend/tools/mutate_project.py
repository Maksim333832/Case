from __future__ import annotations

import argparse
import copy
import json
import shutil
from pathlib import Path
from typing import Any


def _find_line(lines: list[str], needle: str) -> int:
    for idx, line in enumerate(lines, start=1):
        if needle in line:
            return idx
    raise ValueError(f"Needle not found while mutating project: {needle!r}")


def _update_location_by_needle(item: dict[str, Any], project_dir: Path, path: str, needle_start: str, needle_end: str | None = None) -> None:
    file_lines = (project_dir / path).read_text(encoding="utf-8").splitlines()
    start = _find_line(file_lines, needle_start)
    end = _find_line(file_lines, needle_end) if needle_end else start
    item["path"] = path
    item["line"] = start
    item["endLine"] = max(start, end)


def generate_mutated_variants(source_dir: Path, truth_path: Path, out_dir: Path) -> list[dict[str, Path]]:
    """
    Create mutated copies of training-project/ with renamed symbols, changed literals,
    shifted line numbers, and varied build.gradle.kts layouts, alongside updated truth JSONs.
    Used to verify scanners do not overfit to training-project identifiers or exact lines.
    """
    truth_base = json.loads(truth_path.read_text(encoding="utf-8"))
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Path]] = []

    variants = ["mutant_rename_shift", "mutant_gradle_styles"]
    for variant_name in variants:
        dest = out_dir / variant_name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source_dir, dest)
        truth = copy.deepcopy(truth_base)
        truth["dataset"] = f"training-{variant_name}"

        # 1. Rename classes & variables and shift lines in Kotlin files
        renames = [
            (
                "src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt",
                "src/main/kotlin/lab/repairdesk/integration/VendorImportConfig.kt",
                [
                    ("class PartsImportSettings", "// shifted header 1\n// shifted header 2\n// shifted header 3\ninternal class VendorImportConfig"),
                    ("internal internal class", "internal class"),
                    ("legacyImportPassword", "vendorSyncPasscode"),
                    ('"cg26_parts_H9r4Vm2Kb6Qp"', '"svc_pass_9Xk2Lp8Vm4Qw"'),
                ],
                "A-SEC-01",
                "vendorSyncPasscode",
                None,
            ),
            (
                "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
                "src/main/kotlin/lab/repairdesk/integration/CatalogPriceClient.kt",
                [
                    ("class QuoteRequest", "// shifted quote header\n// audit note\ninternal class CatalogPriceClient"),
                    ("internal internal class", "internal class"),
                    ("pricingApiKey", "catalogClientKey"),
                    ('"cg26_quote_qA7mN4kV9rT2sJ6c"', '"key_live_8Tn3Qr7Zx2Mb9Kp4"'),
                ],
                "A-SEC-02",
                "catalogClientKey =",
                None,
            ),
            (
                "src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt",
                "src/main/kotlin/lab/repairdesk/integration/HubHealthClient.kt",
                [
                    ("class DepotStatusClient", "// shifted line 1\n// shifted line 2\ninternal class HubHealthClient"),
                    ("internal internal class", "internal class"),
                    ('"DEPOT_STATUS_TOKEN"', '"HUB_HEALTH_TOKEN"'),
                    ('"cg26_depot_mK7xR4bP9wD2qT"', '"fallback_dev_4Jm9Kt2Rp6Nx"'),
                    ("val access =", "val bearerToken ="),
                    ("$access", "$bearerToken"),
                ],
                "A-SEC-04",
                "HUB_HEALTH_TOKEN",
                None,
            ),
            (
                "src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt",
                "src/main/kotlin/lab/repairdesk/integration/ClaimAuthHeaders.kt",
                [
                    ("class WarrantyHeaders", "// shifted warranty header\n// extra comment\ninternal class ClaimAuthHeaders"),
                    ("internal internal class", "internal class"),
                    ("val series =", "val prefixPart ="),
                    ('"cg26_warranty_"', '"hdr_part1_"'),
                    ("val grant =", "val secretTail ="),
                    ('"D7v4sB2wJ8kP6mQ9"', '"Zx9Qm3Lp7Vw2Rt5N"'),
                    ("series + grant", "prefixPart + secretTail"),
                ],
                "A-SEC-05",
                "val prefixPart =",
                "prefixPart + secretTail",
            ),
            (
                "src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt",
                "src/main/kotlin/lab/repairdesk/integration/PartnerTlsClient.kt",
                [
                    ("class SupplierHttpsClient", "// TLS client comment 1\n// TLS client comment 2\ninternal class PartnerTlsClient"),
                    ("internal internal class", "internal class"),
                ],
                "A-SAST-02",
                "HostnameVerifier {",
                None,
            ),
            (
                "src/main/kotlin/lab/repairdesk/config/RepairCors.kt",
                "src/main/kotlin/lab/repairdesk/config/GatewayCorsConfig.kt",
                [
                    ("class RepairCors", "// CORS config comment 1\n// CORS config comment 2\nclass GatewayCorsConfig"),
                    ("customerSummary", "memberCorsPolicy"),
                ],
                "A-SAST-03",
                "allowedOriginPatterns",
                "allowCredentials",
            ),
        ]

        findings_by_id = {f["id"]: f for f in truth["findings"]}
        controls_by_id = {c["id"]: c for c in truth["controls"]}

        for old_rel, new_rel, replacements, fid, n_start, n_end in renames:
            old_p = dest / old_rel
            new_p = dest / new_rel
            text = old_p.read_text(encoding="utf-8")
            for src_s, dst_s in replacements:
                text = text.replace(src_s, dst_s)
            old_p.unlink()
            new_p.write_text(text, encoding="utf-8")
            _update_location_by_needle(findings_by_id[fid], dest, new_rel, n_start, n_end)

        # Mutate application.yml (shift lines + new bearer token)
        yml_rel = "src/main/resources/application.yml"
        yml_p = dest / yml_rel
        yml_text = yml_p.read_text(encoding="utf-8")
        yml_text = "# Mutated configuration\n# Environment metadata\n" + yml_text.replace(
            "cg26_pickup_Gq7mP8vJdW3sY6zN", "tok_cfg_7Wp3Ln9Qr5Vx8Bm2"
        )
        yml_p.write_text(yml_text, encoding="utf-8")
        _update_location_by_needle(findings_by_id["A-SEC-03"], dest, yml_rel, "tok_cfg_7Wp3Ln9Qr5Vx8Bm2")
        _update_location_by_needle(controls_by_id["A-CTRL-02"], dest, yml_rel, "${INVENTORY_TOKEN}")

        # Mutate RepairLookupController.kt (shift lines & rename param)
        lookup_rel = "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt"
        lookup_p = dest / lookup_rel
        lookup_text = lookup_p.read_text(encoding="utf-8").replace(
            "class RepairLookupController", "// shifted sql 1\n// shifted sql 2\n// shifted sql 3\nclass RepairLookupController"
        ).replace("frameTag", "serialTag")
        lookup_p.write_text(lookup_text, encoding="utf-8")
        _update_location_by_needle(findings_by_id["A-SAST-01"], dest, lookup_rel, "findByFrameTag", "serialTag'")
        _update_location_by_needle(controls_by_id["A-CTRL-04"], dest, lookup_rel, "findByTicketCode", "ticket_code = ?")

        # Mutate RepairSecurity.kt & PickupExportController.kt
        sec_rel = "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt"
        sec_p = dest / sec_rel
        sec_text = sec_p.read_text(encoding="utf-8").replace(
            "fun securityFilterChain", "// security policy note\n    fun securityFilterChain"
        )
        sec_p.write_text(sec_text, encoding="utf-8")
        _update_location_by_needle(findings_by_id["A-SAST-04"], dest, sec_rel, "/api/pickup/export")
        _update_location_by_needle(controls_by_id["A-CTRL-05"], dest, sec_rel, "/api/catalog/services")

        exp_rel = "src/main/kotlin/lab/repairdesk/pickup/PickupExportController.kt"
        exp_p = dest / exp_rel
        exp_text = exp_p.read_text(encoding="utf-8").replace(
            "fun export()", "// export endpoint\n    fun export()"
        )
        exp_p.write_text(exp_text, encoding="utf-8")
        _update_location_by_needle(findings_by_id["A-SAST-04"]["alternateLocations"][0], dest, exp_rel, "fun export()")

        # Mutate RepairTicketReader & RepairTicketController
        reader_rel = "src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt"
        reader_p = dest / reader_rel
        reader_text = reader_p.read_text(encoding="utf-8").replace(
            "fun read(", "// shifted reader\n    fun read("
        ).replace("ticketId: Long", "orderId: Long").replace("ticketId,", "orderId,")
        reader_p.write_text(reader_text, encoding="utf-8")
        _update_location_by_needle(findings_by_id["A-SAST-05"], dest, reader_rel, "fun read(", "SELECT ticket_code")

        ctrl_rel = "src/main/kotlin/lab/repairdesk/repair/RepairTicketController.kt"
        ctrl_p = dest / ctrl_rel
        ctrl_text = ctrl_p.read_text(encoding="utf-8").replace(
            "fun getTicket(", "// shifted ticket controller\n    fun getTicket("
        )
        ctrl_p.write_text(ctrl_text, encoding="utf-8")
        _update_location_by_needle(findings_by_id["A-SAST-05"]["alternateLocations"][0], dest, ctrl_rel, "fun getTicket(", "reader.read")

        # 2. Mutate build.gradle.kts & gradle.properties layouts in second variant
        if variant_name == "mutant_gradle_styles":
            gradle_p = dest / "build.gradle.kts"
            props_p = dest / "gradle.properties"
            props_p.write_text("compressLibVer=1.25.0\n", encoding="utf-8")

            gradle_text = gradle_p.read_text(encoding="utf-8")
            gradle_text = gradle_text.replace(
                'val archiveFormatVersion = "1.25.0"\nval manifestVersion = providers.gradleProperty("legacyManifestJsonVersion").get()',
                'val textLibVersion = "1.9"\nval compressLibVer = providers.gradleProperty("compressLibVer").get()',
            )
            old_deps_block = """    implementation("org.apache.commons:commons-text:1.9")
    implementation("org.jsoup:jsoup:1.14.1")
    implementation("org.apache.commons:commons-compress:$archiveFormatVersion")
    add(
        "implementation",
        "commons-net:commons-net:3.8.0",
    )
    implementation("org.json:json:$manifestVersion")
    implementation("org.apache.commons:commons-lang3:3.20.0")"""
            new_deps_block = """    implementation("org.apache.commons:commons-text:$textLibVersion")
    add(
        "implementation",
        "org.jsoup:jsoup:1.14.1",
    )
    implementation("org.apache.commons:commons-compress:$compressLibVer")
    implementation("commons-net:commons-net:3.8.0")
    implementation("org.json:json:20230227")
    implementation("org.apache.commons:commons-lang3:3.20.0")"""
            assert old_deps_block in gradle_text
            gradle_text = gradle_text.replace(old_deps_block, new_deps_block)
            gradle_p.write_text(gradle_text, encoding="utf-8")

            _update_location_by_needle(findings_by_id["A-SCA-01"], dest, "build.gradle.kts", "commons-text")
            _update_location_by_needle(findings_by_id["A-SCA-02"], dest, "build.gradle.kts", "jsoup:1.14.1")
            _update_location_by_needle(findings_by_id["A-SCA-03"], dest, "build.gradle.kts", "commons-compress")
            findings_by_id["A-SCA-03"]["alternateLocations"] = [{"path": "gradle.properties", "line": 1, "endLine": 1}]
            _update_location_by_needle(findings_by_id["A-SCA-04"], dest, "build.gradle.kts", "commons-net:3.8.0")
            _update_location_by_needle(findings_by_id["A-SCA-05"], dest, "build.gradle.kts", "org.json:json")
            findings_by_id["A-SCA-05"]["alternateLocations"] = []
            _update_location_by_needle(controls_by_id["A-CTRL-03"], dest, "build.gradle.kts", "commons-lang3")

        truth_out = out_dir / f"{variant_name}-truth.json"
        truth_out.write_text(json.dumps(truth, ensure_ascii=False, indent=2), encoding="utf-8")
        results.append({"name": variant_name, "project_dir": dest, "truth_file": truth_out})

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate mutated copies of training-project/ to test scanner generalization")
    parser.add_argument("--source", required=True, help="Path to training-project/")
    parser.add_argument("--truth", required=True, help="Path to ground-truth/training-findings.json")
    parser.add_argument("--out", required=True, help="Output directory for mutated variants")
    args = parser.parse_args(argv)

    variants = generate_mutated_variants(Path(args.source), Path(args.truth), Path(args.out))
    for v in variants:
        print(f"Generated {v['name']}: project={v['project_dir']} truth={v['truth_file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
