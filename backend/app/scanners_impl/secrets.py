from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

import yaml

from app.core.masking import mask_secret, register_runtime_secret
from app.core.models import Finding

DEFAULT_EXTENSIONS = {".kt", ".kts", ".yml", ".yaml", ".properties", ".json"}
SKIP_DIR_NAMES = {".git", ".gradle", ".idea", ".kotlin", "build", "target", "node_modules", "dist", "out", "__pycache__"}

_PLACEHOLDER_MARKERS = (
    "your_",
    "your-",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "dummy",
    "sample",
    "insert_",
    "put_your_",
    "<your",
    "xxxx",
    "****",
)

_NON_SECRET_WORDS = {
    "true",
    "false",
    "null",
    "none",
    "always",
    "never",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "authorization",
    "bearer",
    "basic",
    "application/json",
    "utf-8",
    "x-api-key",
    "x-import-password",
    "default",
    "unknown",
    "development",
    "production",
}

_PASSWORD_NAME_RE = re.compile(r"(?i)(?:password|passwd|passcode|pwd)")
_API_KEY_NAME_RE = re.compile(r"(?i)(?:api[_-]?key|x-api-key|client[_-]?key|secret[_-]?key|access[_-]?key)")
_TOKEN_NAME_RE = re.compile(
    r"(?i)(?:token|bearer|authorization|auth[_-]?(?:header|secret|value)|secret|credential|jwt|signing[_-]?key|private[_-]?key)"
)
_NON_SECRET_ENV_RE = re.compile(r"(?i)^(?:port|host|env|profile|mode|address|url|uri|host_name|log_level|locale|lang|tz)$")

# Kotlin patterns
_ENV_FALLBACK_RE = re.compile(
    r"""(?:System\s*\.\s*getenv|getenv|System\s*\.\s*getProperty)\s*\(\s*"([^"\r\n]+)"\s*\)\s*\?:\s*"([^"\r\n]+)"\s*"""
)
_KOTLIN_STR_ASSIGN_RE = re.compile(
    r"""^\s*(?:(?:private|internal|public|protected)\s+)?(?:(?:val|var|const\s+val)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"\r\n]*)"(?:\s*[,)]|\s*(?://.*)?$)"""
)
_KOTLIN_CONCAT_ASSIGN_RE = re.compile(
    r"""^\s*(?:(?:private|internal|public|protected)\s+)?(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*\+\s*[A-Za-z_][A-Za-z0-9_]*)+)"""
)
_KOTLIN_INLINE_CONCAT_RE = re.compile(
    r"""(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"\r\n]+)"\s*\+\s*"([^"\r\n]+)"\s*"""
)
_KOTLIN_TEMPLATE_CONCAT_RE = re.compile(
    r"""^\s*(?:(?:private|internal|public|protected)\s+)?(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"((?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)+)"\s*$"""
)
_SPRING_PROP_FALLBACK_RE = re.compile(r"""^\$\{([A-Za-z0-9_.-]+):([^}]+)\}$""")
_KOTLIN_HEADER_CALL_RE = re.compile(
    r"""\.(?:header|set|put)\s*\(\s*(?:HttpHeaders\s*\.\s*AUTHORIZATION|"([^"\r\n]+)")\s*,\s*([A-Za-z_][A-Za-z0-9_]*|"[^"\r\n]+")"""
)
_KOTLIN_MAP_ENTRY_RE = re.compile(
    r"""(?:HttpHeaders\s*\.\s*AUTHORIZATION|"([^"\r\n]+)")\s+to\s+([A-Za-z_][A-Za-z0-9_]*|"[^"\r\n]+")"""
)
_KOTLIN_BEARER_CALL_RE = re.compile(r"""\.setBearerAuth\s*\(\s*([A-Za-z_][A-Za-z0-9_]*|"[^"\r\n]+")\s*\)""")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _strip_auth_scheme(value: str) -> tuple[str | None, str]:
    stripped = value.strip()
    m = re.match(r"(?i)^(Bearer|Basic|Token)\s+(.+)$", stripped)
    if m:
        return m.group(1), m.group(2).strip()
    return None, stripped


def _is_placeholder(value: str) -> bool:
    s = value.strip()
    if not s:
        return True
    if re.match(r"^\$\{[^}]+\}$", s) or re.match(r"^#\{[^}]+\}$", s):
        return True
    if s.startswith("<") and s.endswith(">"):
        return True
    low = s.lower()
    if low in _NON_SECRET_WORDS:
        return True
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    if re.match(r"(?i)^https?://", s) or re.match(r"(?i)^jdbc:", s):
        return True
    # Pure template interpolation like "Bearer $token"
    if "$" in s and re.fullmatch(r"(?:[A-Za-z]+\s+)?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", s):
        return True
    return False


def _is_plausible_secret(value: str, strict_entropy: bool = False) -> bool:
    scheme, payload = _strip_auth_scheme(value)
    if _is_placeholder(value) or _is_placeholder(payload):
        return False
    if len(payload) < 8:
        return False
    if " " in payload or "\t" in payload:
        return False
    has_alpha = any(c.isalpha() for c in payload)
    if not has_alpha:
        return False
    classes = sum(
        [
            any(c.islower() for c in payload),
            any(c.isupper() for c in payload),
            any(c.isdigit() for c in payload),
            any(c in "_-!@#$%^&*+=.:/" for c in payload),
        ]
    )
    entropy = _shannon_entropy(payload)
    if strict_entropy:
        return classes >= 3 and len(payload) >= 12 and entropy >= 3.0
    if scheme is not None:
        return classes >= 2 and entropy >= 2.6
    return classes >= 2 and entropy >= 2.4


def _safe_evidence(raw_value: str) -> str:
    scheme, payload = _strip_auth_scheme(raw_value)
    register_runtime_secret(raw_value)
    register_runtime_secret(payload)
    masked = mask_secret(payload)
    return f"{scheme} {masked}" if scheme else masked


def _strip_kotlin_comments(lines: list[str]) -> list[str]:
    """Replace comments with spaces while keeping line count 1:1."""
    cleaned: list[str] = []
    in_block = False
    for line in lines:
        out_chars: list[str] = []
        i = 0
        n = len(line)
        in_str = False
        while i < n:
            if in_block:
                if i + 1 < n and line[i : i + 2] == "*/":
                    in_block = False
                    out_chars.extend("  ")
                    i += 2
                else:
                    out_chars.append(" ")
                    i += 1
                continue
            if not in_str and i + 1 < n and line[i : i + 2] == "/*":
                in_block = True
                out_chars.extend("  ")
                i += 2
                continue
            if not in_str and i + 1 < n and line[i : i + 2] == "//":
                out_chars.append(" " * (n - i))
                break
            ch = line[i]
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                in_str = not in_str
            out_chars.append(ch)
            i += 1
        cleaned.append("".join(out_chars))
    return cleaned


def _classify_key_name(key_name: str, raw_value: str) -> tuple[str, str] | None:
    if _PASSWORD_NAME_RE.search(key_name):
        return ("password", "HIGH")
    if _API_KEY_NAME_RE.search(key_name):
        return ("api-key", "MEDIUM")
    scheme, _ = _strip_auth_scheme(raw_value)
    if scheme is not None or _TOKEN_NAME_RE.search(key_name):
        return ("configuration-token", "HIGH")
    return None


def _scan_kotlin_file(rel_path: str, text: str) -> list[Finding]:
    raw_lines = text.splitlines()
    lines = _strip_kotlin_comments(raw_lines)
    findings: list[Finding] = []
    claimed_lines: set[int] = set()

    # Pass 1: Detect Elvis fallbacks (getenv / getProperty ?: "literal") across single & adjacent lines
    for idx in range(len(lines)):
        line_no = idx + 1
        if line_no in claimed_lines:
            continue
        cur = lines[idx]
        window = cur
        end_line = line_no
        if "?:" not in cur and ("getenv(" in cur or "getProperty(" in cur) and idx + 1 < len(lines) and "?:" in lines[idx + 1]:
            window = f"{cur} {lines[idx + 1].strip()}"
            end_line = line_no + 1
        m = _ENV_FALLBACK_RE.search(window)
        if not m:
            continue
        env_name, fallback_val = m.group(1), m.group(2)
        if _NON_SECRET_ENV_RE.match(env_name) and not _is_plausible_secret(fallback_val, strict_entropy=True):
            continue
        if _is_plausible_secret(fallback_val) or (
            _TOKEN_NAME_RE.search(env_name) or _PASSWORD_NAME_RE.search(env_name) or _API_KEY_NAME_RE.search(env_name)
        ) and not _is_placeholder(fallback_val) and len(fallback_val) >= 6:
            claimed_lines.add(line_no)
            claimed_lines.add(end_line)
            findings.append(
                Finding(
                    category="SECRET",
                    path=rel_path,
                    **{"class": "secret-fallback"},
                    line=line_no,
                    endLine=end_line,
                    severity="LOW",
                    description=f"Hardcoded fallback credential used when environment property '{env_name}' is unset",
                    remediation=f"Remove the fallback literal for '{env_name}' and fail or disable integration when unset",
                    rule_id="secret-env-fallback",
                    evidence=_safe_evidence(fallback_val),
                )
            )

    # Pass 2: Track local string literals, header/auth sinks, and concatenated fragments (recoverable-token)
    # Map var_name -> (line_no, literal_value)
    local_literals: dict[str, tuple[int, str]] = {}
    # Map var_name -> (start_line, end_line, combined_value, constituent_lines)
    concat_vars: dict[str, tuple[int, int, str, set[int]]] = {}
    # Map var_name -> list of header names / sink lines
    var_sinks: dict[str, list[tuple[str, int]]] = {}

    for idx, line in enumerate(lines, start=1):
        # Inline "a" + "b"
        m_ic = _KOTLIN_INLINE_CONCAT_RE.search(line)
        if m_ic:
            vname, p1, p2 = m_ic.group(1), m_ic.group(2), m_ic.group(3)
            combined = p1 + p2
            if _is_plausible_secret(combined):
                concat_vars[vname] = (idx, idx, combined, {idx})

        m_assign = _KOTLIN_STR_ASSIGN_RE.match(line)
        if m_assign and idx not in claimed_lines:
            vname, lit = m_assign.group(1), m_assign.group(2)
            if lit and not _is_placeholder(lit):
                local_literals[vname] = (idx, lit)

        m_concat = _KOTLIN_CONCAT_ASSIGN_RE.match(line)
        if m_concat:
            target_var = m_concat.group(1)
            expr = m_concat.group(2)
            parts = [p.strip() for p in expr.split("+")]
            if all(p in local_literals for p in parts) and len(parts) >= 2:
                combined = "".join(local_literals[p][1] for p in parts)
                part_lines = {local_literals[p][0] for p in parts}
                start_l = min(part_lines)
                end_l = idx
                concat_vars[target_var] = (start_l, end_l, combined, part_lines | {idx})

        m_tmpl_concat = _KOTLIN_TEMPLATE_CONCAT_RE.match(line)
        if m_tmpl_concat:
            target_var = m_tmpl_concat.group(1)
            tmpl = m_tmpl_concat.group(2)
            parts = re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", tmpl)
            if all(p in local_literals for p in parts) and len(parts) >= 2:
                combined = "".join(local_literals[p][1] for p in parts)
                part_lines = {local_literals[p][0] for p in parts}
                concat_vars[target_var] = (min(part_lines), idx, combined, part_lines | {idx})

        # Also catch inline literal function/constructor params like `val foo: String = "secret"`
        for m_param in re.finditer(r"""\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"\r\n]+)" """, line + " "):
            pname, pval = m_param.group(1), m_param.group(2)
            if pname not in local_literals and pval and not _is_placeholder(pval):
                local_literals[pname] = (idx, pval)

        # Sinks: headers & bearer auth
        for m_hdr in _KOTLIN_HEADER_CALL_RE.finditer(line):
            hdr_name = m_hdr.group(1) or "Authorization"
            arg = m_hdr.group(2).strip()
            if arg.startswith('"') and arg.endswith('"'):
                lit = arg[1:-1]
                if idx not in claimed_lines and _is_plausible_secret(lit):
                    cls_sev = _classify_key_name(hdr_name, lit) or ("api-key", "MEDIUM")
                    claimed_lines.add(idx)
                    findings.append(
                        Finding(
                            category="SECRET",
                            path=rel_path,
                            **{"class": cls_sev[0]},
                            line=idx,
                            endLine=idx,
                            severity=cls_sev[1],
                            description=f"Hardcoded secret literal passed directly into '{hdr_name}' header",
                            remediation="Load credential from environment configuration or secret manager",
                            rule_id=f"secret-inline-{cls_sev[0]}",
                            evidence=_safe_evidence(lit),
                        )
                    )
            else:
                var_sinks.setdefault(arg, []).append((hdr_name, idx))

        for m_map in _KOTLIN_MAP_ENTRY_RE.finditer(line):
            hdr_name = m_map.group(1) or "Authorization"
            arg = m_map.group(2).strip()
            if not arg.startswith('"'):
                var_sinks.setdefault(arg, []).append((hdr_name, idx))

        for m_br in _KOTLIN_BEARER_CALL_RE.finditer(line):
            arg = m_br.group(1).strip()
            if arg.startswith('"') and arg.endswith('"'):
                lit = arg[1:-1]
                if idx not in claimed_lines and _is_plausible_secret(lit):
                    claimed_lines.add(idx)
                    findings.append(
                        Finding(
                            category="SECRET",
                            path=rel_path,
                            **{"class": "configuration-token"},
                            line=idx,
                            endLine=idx,
                            severity="HIGH",
                            description="Hardcoded bearer credential passed to setBearerAuth",
                            remediation="Inject bearer token from secret storage",
                            rule_id="secret-bearer-literal",
                            evidence=_safe_evidence(lit),
                        )
                    )
            else:
                var_sinks.setdefault(arg, []).append(("Authorization", idx))

    # Emit recoverable-token findings for concatenated vars
    for target_var, (start_l, end_l, combined, used_lines) in concat_vars.items():
        if not _is_plausible_secret(combined):
            continue
        sinks = var_sinks.get(target_var, [])
        has_auth_sink = bool(sinks)
        has_auth_name = bool(
            _TOKEN_NAME_RE.search(target_var) or _API_KEY_NAME_RE.search(target_var) or _PASSWORD_NAME_RE.search(target_var)
        )
        if not (has_auth_sink or has_auth_name or _is_plausible_secret(combined, strict_entropy=True)):
            continue
        final_end = end_l
        if sinks:
            sink_line = max(sl for _, sl in sinks)
            if sink_line >= start_l and sink_line - start_l <= 14:
                final_end = max(end_l, sink_line)
        claimed_lines.update(used_lines)
        findings.append(
            Finding(
                category="SECRET",
                path=rel_path,
                **{"class": "recoverable-token"},
                line=start_l,
                endLine=final_end,
                severity="MEDIUM",
                description=f"Assembled secret value in '{target_var}' built from concatenated string literals",
                remediation="Provide the complete credential from a single runtime secret source instead of assembling fragments in code",
                rule_id="secret-recoverable-concat",
                evidence=_safe_evidence(combined),
            )
        )

    # Emit password / api-key / configuration-token for single-literal vars
    for vname, (line_no, lit) in local_literals.items():
        if line_no in claimed_lines:
            continue
        if not _is_plausible_secret(lit):
            continue
        sinks = var_sinks.get(vname, [])
        cls_sev = _classify_key_name(vname, lit)
        if cls_sev is None and sinks:
            for hdr_name, _ in sinks:
                cls_sev = _classify_key_name(hdr_name, lit)
                if cls_sev:
                    break
        if cls_sev is None:
            continue

        secret_cls, severity = cls_sev
        # In Kotlin source files, bearer/auth literal without config is typically api-key or configuration-token
        claimed_lines.add(line_no)
        findings.append(
            Finding(
                category="SECRET",
                path=rel_path,
                **{"class": secret_cls},
                line=line_no,
                endLine=line_no,
                severity=severity,
                description=f"Hardcoded {secret_cls} literal stored in '{vname}'",
                remediation=f"Move '{vname}' out of source code into environment variables or secret vault",
                rule_id=f"secret-kotlin-{secret_cls}",
                evidence=_safe_evidence(lit),
            )
        )

    return findings


def _walk_yaml_scalars(node: yaml.Node, prefix: str = "") -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    if isinstance(node, yaml.MappingNode):
        for k_node, v_node in node.value:
            key = str(k_node.value) if isinstance(k_node, yaml.ScalarNode) else ""
            full_key = f"{prefix}.{key}" if prefix else key
            out.extend(_walk_yaml_scalars(v_node, full_key))
    elif isinstance(node, yaml.SequenceNode):
        for idx, item in enumerate(node.value):
            out.extend(_walk_yaml_scalars(item, f"{prefix}[{idx}]"))
    elif isinstance(node, yaml.ScalarNode):
        if node.tag == "tag:yaml.org,2002:str" and isinstance(node.value, str):
            line_no = int(node.start_mark.line) + 1
            out.append((prefix, node.value, line_no))
    return out


def _scan_yaml_file(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root_node = yaml.compose(text)
    except yaml.YAMLError:
        return findings
    if root_node is None:
        return findings

    for key_path, val, line_no in _walk_yaml_scalars(root_node):
        m_fb = _SPRING_PROP_FALLBACK_RE.match(val.strip())
        if m_fb:
            env_name, fb_val = m_fb.group(1), m_fb.group(2).strip()
            if _is_plausible_secret(fb_val) and not _NON_SECRET_ENV_RE.match(env_name):
                findings.append(
                    Finding(
                        category="SECRET",
                        path=rel_path,
                        **{"class": "secret-fallback"},
                        line=line_no,
                        endLine=line_no,
                        severity="LOW",
                        description=f"Spring property '{key_path}' defines an inline fallback secret for '{env_name}'",
                        remediation=f"Remove the fallback after ':' and reference '${{{env_name}}}' directly",
                        rule_id="secret-yaml-fallback",
                        evidence=_safe_evidence(fb_val),
                    )
                )
            continue
        if not _is_plausible_secret(val):
            continue
        leaf = key_path.rsplit(".", 1)[-1]
        cls_sev = _classify_key_name(leaf, val) or _classify_key_name(key_path, val)
        if cls_sev is None:
            continue
        secret_cls, severity = cls_sev
        # In configuration files (YAML), bearer/auth/token maps to configuration-token
        if secret_cls == "configuration-token":
            rule_id = "secret-yaml-configuration-token"
        else:
            rule_id = f"secret-yaml-{secret_cls}"
        findings.append(
            Finding(
                category="SECRET",
                path=rel_path,
                **{"class": secret_cls},
                line=line_no,
                endLine=line_no,
                severity=severity,
                description=f"Hardcoded credential configured at YAML key '{key_path}'",
                remediation=f"Replace literal in '{key_path}' with an environment variable placeholder like '${{...}}'",
                rule_id=rule_id,
                evidence=_safe_evidence(val),
            )
        )
    return findings


def _scan_properties_file(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for idx, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        if "=" in stripped:
            k, v = stripped.split("=", 1)
        elif ":" in stripped:
            k, v = stripped.split(":", 1)
        else:
            continue
        key_path = k.strip()
        val = v.strip().strip('"').strip("'")
        if not _is_plausible_secret(val):
            continue
        cls_sev = _classify_key_name(key_path, val)
        if cls_sev is None:
            continue
        secret_cls, severity = cls_sev
        findings.append(
            Finding(
                category="SECRET",
                path=rel_path,
                **{"class": secret_cls},
                line=idx,
                endLine=idx,
                severity=severity,
                description=f"Hardcoded credential configured at property '{key_path}'",
                remediation=f"Replace literal value for '{key_path}' with an environment reference",
                rule_id=f"secret-prop-{secret_cls}",
                evidence=_safe_evidence(val),
            )
        )
    return findings


def scan(root: Path, params: dict[str, Any] | None = None) -> list[Finding]:
    params = params or {}
    ext_param = params.get("include_extensions")
    allowed_exts = {str(e).lower() for e in ext_param} if ext_param else DEFAULT_EXTENSIONS
    # Never scan markdown documentation files unless explicitly requested
    if not ext_param:
        allowed_exts.discard(".md")

    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.relative_to(root).parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in allowed_exts:
            continue
        # Gradle build scripts don't typically contain runtime secrets unless explicit; skip lockfiles
        if path.name in ("gradle.lockfile", "gradlew", "gradlew.bat"):
            continue

        rel_path = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if suffix in (".kt", ".kts"):
            findings.extend(_scan_kotlin_file(rel_path, text))
        elif suffix in (".yml", ".yaml"):
            findings.extend(_scan_yaml_file(rel_path, text))
        elif suffix == ".properties":
            findings.extend(_scan_properties_file(rel_path, text))

    return findings
