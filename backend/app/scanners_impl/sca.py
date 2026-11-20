from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.core.models import Finding

SKIP_DIR_NAMES = {".git", ".gradle", ".idea", ".kotlin", "build", "target", "node_modules", "dist", "out", "__pycache__"}

_NUMERIC_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_VAL_LITERAL_RE = re.compile(r"""^\s*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*["']([^"'\r\n]+)["']""")
_VAL_GRADLE_PROP_RE = re.compile(
    r"""^\s*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*(?:providers\s*\.\s*gradleProperty|findProperty|project\s*\.\s*property|property)\s*\(\s*["']([^"'\r\n]+)["']\s*\)(?:\s*\.\s*(?:get\(\)|orNull))?"""
)
_VAL_BY_PROJECT_RE = re.compile(
    r"""^\s*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?\s+by\s+(?:project|settings)\b"""
)
_DEP_COORD_CALL_RE = re.compile(
    r"""\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt|ksp)\s*\(\s*["']([^"'\r\n]+)["']\s*\)"""
)
_DEP_GROOVY_QUOTED_RE = re.compile(
    r"""^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s+["']([^"'\r\n]+)["']"""
)
_ADD_MULTILINE_RE = re.compile(
    r"""\badd\s*\(\s*["'][^"'\r\n]+["']\s*,\s*["']([^"'\r\n]+)["']\s*,?\s*\)""",
    flags=re.MULTILINE,
)
_NAMED_COORD_RE = re.compile(
    r"""\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(\s*group\s*=\s*["']([^"'\r\n]+)["']\s*,\s*name\s*=\s*["']([^"'\r\n]+)["']\s*(?:,\s*version\s*=\s*["']([^"'\r\n]+)["'])?\s*\)""",
    flags=re.MULTILINE,
)


@dataclass(frozen=True)
class DeclaredDependency:
    path: str
    line: int
    group: str
    artifact: str
    raw_version: str | None


def _is_numeric_version(version: str | None) -> bool:
    return bool(version and _NUMERIC_VERSION_RE.match(version.strip()))


def _parse_numeric_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.strip().split("."))


def compare_numeric_versions(a: str, b: str) -> int:
    pa = list(_parse_numeric_tuple(a))
    pb = list(_parse_numeric_tuple(b))
    max_len = max(len(pa), len(pb))
    pa.extend([0] * (max_len - len(pa)))
    pb.extend([0] * (max_len - len(pb)))
    return (pa > pb) - (pa < pb)


def version_in_range(version: str, rng: dict[str, Any]) -> bool:
    if not _is_numeric_version(version):
        return False
    lower = rng.get("lower")
    if lower is not None:
        if not _is_numeric_version(str(lower)):
            return False
        cmp_low = compare_numeric_versions(version, str(lower))
        if rng.get("lowerInclusive", False):
            if cmp_low < 0:
                return False
        else:
            if cmp_low <= 0:
                return False

    upper = rng.get("upper")
    if upper is None or not _is_numeric_version(str(upper)):
        return False
    cmp_up = compare_numeric_versions(version, str(upper))
    if rng.get("upperInclusive", False):
        if cmp_up > 0:
            return False
    else:
        if cmp_up >= 0:
            return False
    return True


def _load_gradle_properties(root: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    for prop_file in sorted(root.rglob("gradle.properties")):
        if any(part in SKIP_DIR_NAMES for part in prop_file.relative_to(root).parts):
            continue
        try:
            text = prop_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
    return props


def _load_gradle_lockfile(root: Path) -> dict[tuple[str, str], str]:
    locked: dict[tuple[str, str], str] = {}
    for lock_file in sorted(root.rglob("gradle.lockfile")):
        if any(part in SKIP_DIR_NAMES for part in lock_file.relative_to(root).parts):
            continue
        try:
            text = lock_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coord = line.split("=", 1)[0].strip()
            parts = coord.split(":")
            if len(parts) >= 3:
                g, a, v = parts[0].strip(), parts[1].strip(), parts[2].strip()
                if g and a and v:
                    locked[(g, a)] = v
    return locked


def _resolve_version_expr(expr: str | None, local_vals: dict[str, str], props: dict[str, str]) -> str | None:
    if expr is None:
        return None
    raw = expr.strip()
    if not raw:
        return None

    # Handle ${providers.gradleProperty("prop").get()} inside coordinate string
    m_inline_prop = re.fullmatch(
        r"""\$\{\s*(?:providers\s*\.\s*gradleProperty|findProperty|property)\s*\(\s*["']([^"']+)["']\s*\)(?:\s*\.\s*(?:get\(\)|orNull))?\s*\}""",
        raw,
    )
    if m_inline_prop:
        return props.get(m_inline_prop.group(1))

    # Handle $var or ${var}
    m_var = re.fullmatch(r"""\$\{?([A-Za-z_][A-Za-z0-9_.]*)\}?""", raw)
    if m_var:
        key = m_var.group(1)
        if key in local_vals:
            return local_vals[key]
        if key in props:
            return props[key]
        return None

    return raw


def _parse_build_script(rel_path: str, text: str, props: dict[str, str]) -> list[DeclaredDependency]:
    lines = text.splitlines()
    local_vals: dict[str, str] = {}

    for line in lines:
        m_prop = _VAL_GRADLE_PROP_RE.match(line)
        if m_prop:
            var_name, prop_name = m_prop.group(1), m_prop.group(2)
            if prop_name in props:
                local_vals[var_name] = props[prop_name]
            continue
        m_by = _VAL_BY_PROJECT_RE.match(line)
        if m_by:
            var_name = m_by.group(1)
            if var_name in props:
                local_vals[var_name] = props[var_name]
            continue
        m_lit = _VAL_LITERAL_RE.match(line)
        if m_lit:
            local_vals[m_lit.group(1)] = m_lit.group(2)

    deps: list[DeclaredDependency] = []
    seen: set[tuple[int, str, str, str | None]] = set()

    def _add_coord(coord_str: str, line_no: int) -> None:
        parts = coord_str.split(":")
        if len(parts) < 2:
            return
        group = parts[0].strip()
        artifact = parts[1].strip()
        raw_ver = parts[2].strip() if len(parts) >= 3 else None
        resolved = _resolve_version_expr(raw_ver, local_vals, props)
        key = (line_no, group, artifact, resolved)
        if group and artifact and key not in seen:
            seen.add(key)
            deps.append(DeclaredDependency(path=rel_path, line=line_no, group=group, artifact=artifact, raw_version=resolved))

    # Single-line calls
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for m in _DEP_COORD_CALL_RE.finditer(line):
            _add_coord(m.group(1), idx)
        for m in _DEP_GROOVY_QUOTED_RE.finditer(line):
            _add_coord(m.group(1), idx)

    # Multiline add("implementation", "group:artifact:version") and named args
    for regex in (_ADD_MULTILINE_RE, _NAMED_COORD_RE):
        for m in regex.finditer(text):
            start_pos = m.start()
            # Line number where the coordinate (or call) appears; prefer coordinate line for clarity
            if regex is _ADD_MULTILINE_RE:
                coord = m.group(1)
                coord_offset = m.start(1)
                line_no = text.count("\n", 0, coord_offset) + 1
                _add_coord(coord, line_no)
            else:
                line_no = text.count("\n", 0, start_pos) + 1
                group, artifact, raw_ver = m.group(1), m.group(2), m.group(3)
                resolved = _resolve_version_expr(raw_ver, local_vals, props)
                key = (line_no, group, artifact, resolved)
                if key not in seen:
                    seen.add(key)
                    deps.append(
                        DeclaredDependency(path=rel_path, line=line_no, group=group, artifact=artifact, raw_version=resolved)
                    )

    return deps


def _load_vulnerabilities(vuln_db_path: Path) -> list[dict[str, Any]]:
    if not vuln_db_path.is_file():
        return []
    raw = json.loads(vuln_db_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        items = raw.get("vulnerabilities")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def scan(root: Path, params: dict[str, Any] | None = None) -> list[Finding]:
    params = params or {}
    raw_db = str(params.get("vuln_db_path") or "").strip()
    vuln_db_path = Path(raw_db) if raw_db else get_settings().vuln_db_path
    advisories = _load_vulnerabilities(vuln_db_path)
    if not advisories:
        return []

    lockfile_priority = bool(params.get("lockfile_priority", True))
    props = _load_gradle_properties(root)
    lockfile_versions = _load_gradle_lockfile(root) if lockfile_priority else {}

    adv_by_coord: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for adv in advisories:
        g = str(adv.get("group") or "").strip()
        a = str(adv.get("artifact") or "").strip()
        if g and a:
            adv_by_coord.setdefault((g, a), []).append(adv)

    declared: list[DeclaredDependency] = []
    for build_file in sorted(root.rglob("build.gradle*")):
        if not build_file.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in build_file.relative_to(root).parts):
            continue
        if build_file.name not in ("build.gradle.kts", "build.gradle"):
            continue
        rel_path = build_file.relative_to(root).as_posix()
        try:
            text = build_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        declared.extend(_parse_build_script(rel_path, text, props))

    findings: list[Finding] = []
    emitted_keys: set[tuple[str, str, str, str, str]] = set()

    for dep in declared:
        locked_ver = lockfile_versions.get((dep.group, dep.artifact)) if lockfile_priority else None
        version = locked_ver or dep.raw_version
        if not _is_numeric_version(version):
            continue
        assert version is not None

        for adv in adv_by_coord.get((dep.group, dep.artifact), []):
            ranges = adv.get("ranges") or []
            if not any(version_in_range(version, r) for r in ranges):
                continue

            adv_id_primary = str(adv.get("id") or "").strip()
            aliases = [str(a).strip() for a in (adv.get("aliases") or []) if str(a).strip()]
            cve_id = next((a for a in aliases if a.upper().startswith("CVE-")), None)
            chosen_id = cve_id or adv_id_primary
            if not chosen_id:
                continue

            dedup_key = (dep.path, dep.group, dep.artifact, version, adv_id_primary or chosen_id)
            if dedup_key in emitted_keys:
                continue
            emitted_keys.add(dedup_key)

            other_aliases = [a for a in ([adv_id_primary] + aliases) if a and a != chosen_id]
            fixed_versions = [str(v) for v in (adv.get("fixedVersions") or []) if str(v).strip()]
            fixed_hint = ", ".join(fixed_versions) if fixed_versions else "a patched release"
            severity = str(adv.get("severity") or "MEDIUM").upper()
            if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                severity = "MEDIUM"

            findings.append(
                Finding(
                    category="SCA",
                    path=dep.path,
                    group=dep.group,
                    artifact=dep.artifact,
                    version=version,
                    advisoryId=chosen_id,
                    aliases=other_aliases,
                    severity=severity,  # type: ignore[arg-type]
                    description=(
                        f"Vulnerable dependency {dep.group}:{dep.artifact}:{version} declared at {dep.path}:{dep.line} "
                        f"matches advisory {chosen_id}."
                    ),
                    remediation=f"Upgrade {dep.group}:{dep.artifact} from {version} to {fixed_hint}.",
                    rule_id=f"sca-maven-{adv_id_primary or chosen_id}",
                    evidence=f"{dep.group}:{dep.artifact}:{version} ({chosen_id})",
                )
            )

    return findings
