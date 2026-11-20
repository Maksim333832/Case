from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.models import Finding

SKIP_DIR_NAMES = {".git", ".gradle", ".idea", ".kotlin", "build", "target", "node_modules", "dist", "out", "__pycache__"}

_OWNER_FIELD_RE = re.compile(
    r"(?i)^(?:customer_?id|user_?id|owner_?id|account_?id|member_?id|tenant_?id|client_?id|author_?id|created_?by)$"
)
_SQL_KEYWORD_RE = re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b")
_JDBC_SINK_RE = re.compile(
    r"""\.\s*(queryForList|queryForObject|queryForMap|query|update|execute|executeQuery|executeUpdate|createNativeQuery)\s*\("""
)
_HTTP_METHOD_MAP_RE = re.compile(
    r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(([^)]*)\)"""
)
_CLASS_REQ_MAP_RE = re.compile(r"""@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""")
_AUTH_GUARD_RE = re.compile(
    r"""(?i)(?:@PreAuthorize|@Secured|@RolesAllowed|SecurityContextHolder|hasRole\s*\(|hasAuthority\s*\(|isUserInRole|principal\.name|authentication\.name)"""
)
_PRINCIPAL_PARAM_RE = re.compile(r"""\b(?:Principal|Authentication|Jwt|UserDetails)\b|@AuthenticationPrincipal""")


@dataclass
class KotlinFunction:
    path: str
    class_name: str
    class_prefix: str
    injected_fields: dict[str, str]
    name: str
    start_line: int
    end_line: int
    header_text: str
    body_text: str
    body_lines: list[tuple[int, str]]
    annotations: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class SecurityRule:
    path: str
    line: int
    http_method: str | None
    pattern: str
    decision: str  # "permitAll", "denyAll", "authenticated", "hasRole", "other"
    role: str | None = None


def _strip_kotlin_comments(lines: list[str]) -> list[str]:
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


def _extract_balanced_parens(text: str, open_idx: int) -> tuple[str, int]:
    depth = 0
    in_str = False
    quote_char = ""
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == quote_char and (i == 0 or text[i - 1] != "\\"):
                in_str = False
        else:
            if ch in ('"', "'"):
                in_str = True
                quote_char = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1 : i], i + 1
        i += 1
    return text[open_idx + 1 :], len(text)


def _extract_balanced_braces(text: str, open_idx: int) -> tuple[str, int]:
    depth = 0
    in_str = False
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == '"' and (i == 0 or text[i - 1] != "\\"):
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1 : i], i + 1
        i += 1
    return text[open_idx + 1 :], len(text)


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _clamp_range(start_line: int, end_line: int) -> tuple[int, int]:
    s = max(1, start_line)
    e = max(s, end_line)
    if e > s + 14:
        e = s + 14
    return s, e


def _normalize_url_path(prefix: str, sub: str) -> str:
    joined = "/" + "/".join(part.strip("/") for part in (prefix, sub) if part.strip("/"))
    return joined if joined != "/" else "/"


def _ant_matches(pattern: str, concrete_path: str) -> bool:
    """Check whether Spring Ant pattern (like /api/pickup/**) covers a concrete path (/api/pickup/export)."""
    pat = pattern.strip()
    if pat == concrete_path:
        return False
    regex_parts = []
    i = 0
    while i < len(pat):
        if pat[i : i + 2] == "**":
            regex_parts.append(".*")
            i += 2
        elif pat[i] == "*":
            regex_parts.append("[^/]*")
            i += 1
        else:
            regex_parts.append(re.escape(pat[i]))
            i += 1
    return bool(re.fullmatch("".join(regex_parts), concrete_path))


def _collect_schema_and_models(root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return (table_name -> owner_columns, kotlin_class_name -> owner_properties)."""
    table_owners: dict[str, set[str]] = {}
    model_owners: dict[str, set[str]] = {}

    for sql_file in sorted(root.rglob("*.sql")):
        if any(part in SKIP_DIR_NAMES for part in sql_file.relative_to(root).parts):
            continue
        text = sql_file.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
            tbl = m.group(1).lower()
            cols_block, _ = _extract_balanced_parens(text, m.end() - 1)
            owners: set[str] = set()
            for raw_col in cols_block.split(","):
                col_tokens = raw_col.strip().split()
                if col_tokens:
                    col_name = col_tokens[0].strip('`"[]')
                    if _OWNER_FIELD_RE.match(col_name):
                        owners.add(col_name.lower())
            if owners:
                table_owners[tbl] = owners

    for kt_file in sorted(root.rglob("*.kt")):
        if any(part in SKIP_DIR_NAMES for part in kt_file.relative_to(root).parts):
            continue
        text = kt_file.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"\b(?:data\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", text, flags=re.DOTALL):
            cls_name = m.group(1)
            params_str = m.group(2)
            owners = set()
            for p in re.finditer(r"\b(?:val|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", params_str):
                pname = p.group(1)
                if _OWNER_FIELD_RE.match(pname):
                    owners.add(pname)
            if owners:
                model_owners[cls_name] = owners

    return table_owners, model_owners


def _parse_kotlin_functions(rel_path: str, cleaned_text: str) -> list[KotlinFunction]:
    lines = cleaned_text.splitlines()
    functions: list[KotlinFunction] = []

    # Find classes and their constructor dependencies / @RequestMapping
    class_blocks: list[tuple[int, int, str, str, dict[str, str]]] = []
    for m_cls in re.finditer(
        r"(?:(@[A-Za-z0-9_]+(?:\([^)]*\))?(?:\s+@[A-Za-z0-9_]+(?:\([^)]*\))?)*)\s+)?(?:(?:internal|public|private|open|abstract|data)\s+)*class\s+([A-Za-z_][A-Za-z0-9_]*)",
        cleaned_text,
    ):
        cls_name = m_cls.group(2)
        ann_text = m_cls.group(1) or ""
        prefix = ""
        m_rm = _CLASS_REQ_MAP_RE.search(ann_text)
        if m_rm:
            prefix = m_rm.group(1)

        # Parse constructor params if present
        pos = m_cls.end()
        injected: dict[str, str] = {}
        while pos < len(cleaned_text) and cleaned_text[pos].isspace():
            pos += 1
        if pos < len(cleaned_text) and cleaned_text[pos] == "(":
            ctor_str, pos = _extract_balanced_parens(cleaned_text, pos)
            for pm in re.finditer(r"(?:private|val|var|\s)*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_<>,\s?]*)", ctor_str):
                field_name = pm.group(1)
                field_type = pm.group(2).split("<", 1)[0].strip().rstrip("?")
                injected[field_name] = field_type

        # Check if class has a body '{' (ignoring supertype clause on same header; do not cross into next class/fun)
        rest_pos = pos
        brace_pos = -1
        while rest_pos < len(cleaned_text):
            ch = cleaned_text[rest_pos]
            if ch == "{":
                brace_pos = rest_pos
                break
            if cleaned_text[rest_pos : rest_pos + 1] == "\n":
                # Check if next non-empty line starts a new declaration or annotation rather than '{'
                next_slice = cleaned_text[rest_pos + 1 :].lstrip()
                if next_slice and not next_slice.startswith(("{", ":")):
                    break
            rest_pos += 1
        if brace_pos == -1:
            class_blocks.append((m_cls.start(), pos, cls_name, prefix, injected))
            continue
        _, cls_end = _extract_balanced_braces(cleaned_text, brace_pos)
        class_blocks.append((m_cls.start(), cls_end, cls_name, prefix, injected))

    # Find functions in file
    for m_fun in re.finditer(r"\bfun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", cleaned_text):
        fun_name = m_fun.group(1)
        fun_start_offset = m_fun.start()
        fun_line = _line_of_offset(cleaned_text, fun_start_offset)

        # Look backwards up to 5 lines for annotations, stopping at any non-annotation line (class/brace/previous code)
        anns: list[tuple[int, str]] = []
        for look in range(fun_line - 1, max(0, fun_line - 6), -1):
            ann_line = lines[look - 1].strip()
            if not ann_line:
                continue
            if ann_line.startswith("@"):
                anns.append((look, ann_line))
            else:
                break
        anns.reverse()

        params_str, after_params = _extract_balanced_parens(cleaned_text, m_fun.end() - 1)
        # Find '=' or '{' after return type
        cursor = after_params
        while cursor < len(cleaned_text):
            ch = cleaned_text[cursor]
            if ch == "{":
                body_str, body_end = _extract_balanced_braces(cleaned_text, cursor)
                end_line = _line_of_offset(cleaned_text, body_end - 1)
                header_text = cleaned_text[fun_start_offset:cursor]
                break
            elif ch == "=":
                # Expression body until next blank line, next fun/class/@ annotation, or closing class brace
                expr_start = cursor + 1
                expr_line = _line_of_offset(cleaned_text, cursor)
                end_l = expr_line
                depth_p = 0
                depth_b = 0
                for li in range(expr_line - 1, len(lines)):
                    ltxt = lines[li]
                    if li > expr_line - 1:
                        st = ltxt.strip()
                        if st == "}" and depth_b == 0 and depth_p == 0:
                            break
                        if (st.startswith("fun ") or st.startswith("@") or st.startswith("class ")) and depth_b == 0 and depth_p == 0:
                            break
                    for c in ltxt:
                        if c == "(":
                            depth_p += 1
                        elif c == ")":
                            depth_p = max(0, depth_p - 1)
                        elif c == "{":
                            depth_b += 1
                        elif c == "}":
                            depth_b = max(0, depth_b - 1)
                    end_l = li + 1
                    if depth_p == 0 and depth_b == 0 and li >= expr_line - 1 and ltxt.strip() and not ltxt.rstrip().endswith(("=", "+", ",", ".", "(")):
                        # Peek next line to check fluent call continuation like `.firstOrNull()`
                        if li + 1 < len(lines) and lines[li + 1].lstrip().startswith("."):
                            continue
                        break
                body_str = "\n".join(lines[expr_line - 1 : end_l])
                end_line = end_l
                header_text = cleaned_text[fun_start_offset:cursor]
                break
            cursor += 1
        else:
            continue

        # Resolve enclosing class
        cls_name, cls_prefix, injected = "", "", {}
        for cs, ce, cn, cp, cinj in class_blocks:
            if cs <= fun_start_offset <= ce:
                cls_name, cls_prefix, injected = cn, cp, cinj
                break

        b_lines = [(ln, lines[ln - 1]) for ln in range(fun_line, min(end_line, len(lines)) + 1)]
        functions.append(
            KotlinFunction(
                path=rel_path,
                class_name=cls_name,
                class_prefix=cls_prefix,
                injected_fields=injected,
                name=fun_name,
                start_line=fun_line,
                end_line=end_line,
                header_text=header_text,
                body_text=body_str,
                body_lines=b_lines,
                annotations=anns,
            )
        )
    return functions


def _split_top_level_args(args_str: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_str = False
    quote_char = ""
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if in_str:
            cur.append(ch)
            if ch == quote_char and (i == 0 or args_str[i - 1] != "\\"):
                in_str = False
        else:
            if ch in ('"', "'"):
                in_str = True
                quote_char = ch
                cur.append(ch)
            elif ch in ("(", "[", "{"):
                depth += 1
                cur.append(ch)
            elif ch in (")", "]", "}"):
                depth = max(0, depth - 1)
                cur.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        i += 1
    if cur or parts:
        parts.append("".join(cur).strip())
    return parts


def _sql_expr_is_dynamic(expr: str) -> bool:
    if not _SQL_KEYWORD_RE.search(expr):
        return False
    has_interp = bool(re.search(r"\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)", expr))
    has_concat = bool(re.search(r"""["']\s*\+\s*[A-Za-z_]|([A-Za-z_][A-Za-z0-9_.]*\s*\+\s*["'])""", expr))
    has_format = bool(re.search(r"""(?:\.format\s*\(|String\s*\.\s*format\s*\()""", expr))
    return has_interp or has_concat or has_format


def _analyze_sql_injection(fn: KotlinFunction) -> list[Finding]:
    findings: list[Finding] = []
    full_fn_text = fn.header_text + "\n" + fn.body_text

    local_sql_vars: dict[str, tuple[int, bool]] = {}
    for ln, ltxt in fn.body_lines:
        m_var = re.match(r"""^\s*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$""", ltxt)
        if m_var:
            vname, expr = m_var.group(1), m_var.group(2)
            if _SQL_KEYWORD_RE.search(expr):
                local_sql_vars[vname] = (ln, _sql_expr_is_dynamic(expr))

    for m_sink in _JDBC_SINK_RE.finditer(full_fn_text):
        args_str, _ = _extract_balanced_parens(full_fn_text, m_sink.end() - 1)
        top_args = _split_top_level_args(args_str)
        first_arg = top_args[0] if top_args else ""
        sink_offset_in_body = m_sink.start()
        sink_line = fn.start_line + full_fn_text[:sink_offset_in_body].count("\n")

        is_vulnerable = False
        start_line = fn.start_line
        end_line = sink_line

        if _sql_expr_is_dynamic(first_arg):
            is_vulnerable = True
        elif first_arg in local_sql_vars:
            v_line, is_dyn = local_sql_vars[first_arg]
            if is_dyn:
                is_vulnerable = True
                start_line = min(fn.start_line, v_line)

        if is_vulnerable:
            if sink_line - fn.start_line > 5:
                start_line = sink_line
            s_l, e_l = _clamp_range(start_line, end_line)
            findings.append(
                Finding(
                    category="SAST",
                    path=fn.path,
                    **{"class": "sql-injection"},
                    line=s_l,
                    endLine=e_l,
                    severity="HIGH",
                    description=f"Dynamic SQL query constructed via string interpolation/concatenation in '{fn.name}' and passed to JDBC '{m_sink.group(1)}'.",
                    remediation="Replace interpolated/concatenated variables with parameterized '?' placeholders and pass values as separate JDBC arguments.",
                    rule_id="sast-kotlin-sql-injection",
                    evidence=f"{fn.name} -> {m_sink.group(1)}(...)",
                )
            )
    return findings


def _analyze_tls_verification(rel_path: str, cleaned_text: str) -> list[Finding]:
    findings: list[Finding] = []
    # 1. Permissive HostnameVerifier lambda: HostnameVerifier { _, _ -> true }
    for m in re.finditer(r"""HostnameVerifier\s*\{[^}]*->\s*true\s*\}""", cleaned_text, flags=re.DOTALL):
        s_l = _line_of_offset(cleaned_text, m.start())
        e_l = _line_of_offset(cleaned_text, m.end() - 1)
        s_l, e_l = _clamp_range(s_l, e_l)
        findings.append(
            Finding(
                category="SAST",
                path=rel_path,
                **{"class": "tls-verification"},
                line=s_l,
                endLine=e_l,
                severity="MEDIUM",
                description="TLS hostname verification is disabled using an unconditional 'true' HostnameVerifier.",
                remediation="Remove the permissive HostnameVerifier and rely on standard JVM hostname verification.",
                rule_id="sast-tls-hostname-verifier",
                evidence="HostnameVerifier { ... -> true }",
            )
        )

    # 2. Anonymous object HostnameVerifier returning true
    for m in re.finditer(
        r"""object\s*:\s*HostnameVerifier\s*\{[\s\S]{0,400}?\bverify\s*\([^)]*\)(?:\s*:\s*Boolean)?\s*(?:=\s*true|\{\s*return\s+true\s*\})""",
        cleaned_text,
    ):
        s_l = _line_of_offset(cleaned_text, m.start())
        e_l = _line_of_offset(cleaned_text, m.end() - 1)
        s_l, e_l = _clamp_range(s_l, e_l)
        findings.append(
            Finding(
                category="SAST",
                path=rel_path,
                **{"class": "tls-verification"},
                line=s_l,
                endLine=e_l,
                severity="MEDIUM",
                description="TLS hostname verification is bypassed via custom HostnameVerifier returning true.",
                remediation="Remove custom trust-all HostnameVerifier and validate server hostnames against TLS certificates.",
                rule_id="sast-tls-object-hostname-verifier",
                evidence="object : HostnameVerifier { verify -> true }",
            )
        )

    # 3. Empty checkServerTrusted in X509TrustManager
    for m in re.finditer(
        r"""\bcheckServerTrusted\s*\([^)]*\)\s*\{\s*\}""",
        cleaned_text,
    ):
        s_l = _line_of_offset(cleaned_text, m.start())
        findings.append(
            Finding(
                category="SAST",
                path=rel_path,
                **{"class": "tls-verification"},
                line=s_l,
                endLine=s_l,
                severity="HIGH",
                description="TLS certificate chain verification is disabled by empty checkServerTrusted implementation.",
                remediation="Use default system TrustManager instead of accepting all TLS certificates.",
                rule_id="sast-tls-trust-manager",
                evidence="checkServerTrusted(...) {}",
            )
        )
    return findings


def _analyze_credentialed_cors(rel_path: str, cleaned_text: str) -> list[Finding]:
    findings: list[Finding] = []
    # 1. CorsConfiguration blocks
    for m in re.finditer(r"""CorsConfiguration\s*\(\s*\)\s*\.apply\s*\{""", cleaned_text):
        block, _ = _extract_balanced_braces(cleaned_text, m.end() - 1)
        block_offset = m.end() - 1
        m_origin = re.search(
            r"""(?:allowedOriginPatterns\s*=\s*listOf\([^)]*"\*"[^)]*\)|allowedOrigins\s*=\s*listOf\([^)]*"\*"[^)]*\)|addAllowedOriginPattern\(\s*"\*"\s*\)|addAllowedOrigin\(\s*"\*"\s*\))""",
            block,
        )
        m_cred = re.search(r"""(?:allowCredentials\s*=\s*true|setAllowCredentials\s*\(\s*true\s*\))""", block)
        if m_origin and m_cred:
            l1 = _line_of_offset(cleaned_text, block_offset + m_origin.start())
            l2 = _line_of_offset(cleaned_text, block_offset + m_cred.start())
            s_l, e_l = _clamp_range(min(l1, l2), max(l1, l2))
            findings.append(
                Finding(
                    category="SAST",
                    path=rel_path,
                    **{"class": "credentialed-cors"},
                    line=s_l,
                    endLine=e_l,
                    severity="MEDIUM",
                    description="CORS configuration allows wildcard origin patterns with allowCredentials=true.",
                    remediation="Restrict allowedOriginPatterns/allowedOrigins to explicit trusted frontend origins.",
                    rule_id="sast-spring-credentialed-cors",
                    evidence='allowedOriginPatterns=["*"] + allowCredentials=true',
                )
            )

    # 2. Imperative CorsConfiguration variable style: cfg.allowedOriginPatterns = ...; cfg.allowCredentials = true
    if not findings and "CorsConfiguration" in cleaned_text:
        m_origin = re.search(
            r"""(?:allowedOriginPatterns\s*=\s*listOf\([^)]*"\*"[^)]*\)|allowedOrigins\s*=\s*listOf\([^)]*"\*"[^)]*\)|addAllowedOriginPattern\(\s*"\*"\s*\)|addAllowedOrigin\(\s*"\*"\s*\))""",
            cleaned_text,
        )
        m_cred = re.search(r"""(?:allowCredentials\s*=\s*true|setAllowCredentials\s*\(\s*true\s*\))""", cleaned_text)
        if m_origin and m_cred:
            l1 = _line_of_offset(cleaned_text, m_origin.start())
            l2 = _line_of_offset(cleaned_text, m_cred.start())
            s_l, e_l = _clamp_range(min(l1, l2), max(l1, l2))
            findings.append(
                Finding(
                    category="SAST",
                    path=rel_path,
                    **{"class": "credentialed-cors"},
                    line=s_l,
                    endLine=e_l,
                    severity="MEDIUM",
                    description="Wildcard CORS origin combined with allowCredentials=true.",
                    remediation="Configure explicit allowed origins instead of '*'.",
                    rule_id="sast-spring-credentialed-cors-imperative",
                    evidence='allowedOriginPatterns=["*"] + allowCredentials=true',
                )
            )

    # 3. @CrossOrigin(origins = ["*"], allowCredentials = "true")
    for m in re.finditer(r"""@CrossOrigin\s*\(([^)]*)\)""", cleaned_text, flags=re.DOTALL):
        args = m.group(1)
        if '"*"' in args and re.search(r"""allowCredentials\s*=\s*["']?true["']?""", args):
            l1 = _line_of_offset(cleaned_text, m.start())
            l2 = _line_of_offset(cleaned_text, m.end() - 1)
            s_l, e_l = _clamp_range(l1, l2)
            findings.append(
                Finding(
                    category="SAST",
                    path=rel_path,
                    **{"class": "credentialed-cors"},
                    line=s_l,
                    endLine=e_l,
                    severity="MEDIUM",
                    description="@CrossOrigin permits wildcard origins with credentials enabled.",
                    remediation="Restrict @CrossOrigin origins to trusted origins.",
                    rule_id="sast-spring-cross-origin-wildcard",
                    evidence="@CrossOrigin(origins=*, allowCredentials=true)",
                )
            )
    return findings


def _extract_security_rules(rel_path: str, cleaned_text: str) -> list[SecurityRule]:
    rules: list[SecurityRule] = []
    for m_auth in re.finditer(r"""\.authorizeHttpRequests\s*\{""", cleaned_text):
        block, _ = _extract_balanced_braces(cleaned_text, m_auth.end() - 1)
        base_offset = m_auth.end() - 1
        for m_rule in re.finditer(
            r"""\b(?:requestMatchers|antMatchers|mvcMatchers)\s*\(([^)]*)\)\s*\.\s*(permitAll|anonymous|denyAll|authenticated|hasRole|hasAnyRole|hasAuthority)\s*\(([^)]*)\)""",
            block,
        ):
            matcher_args = m_rule.group(1)
            m_method = re.search(r"""\b(?:HttpMethod\s*\.\s*)?(GET|POST|PUT|DELETE|PATCH)\b""", matcher_args)
            method = m_method.group(1) if m_method else None
            patterns = re.findall(r"""["']([^"']+)["']""", matcher_args)
            action = m_rule.group(2)
            action_arg = m_rule.group(3).strip().strip('"').strip("'")
            line_no = _line_of_offset(cleaned_text, base_offset + m_rule.start())
            for pattern in patterns:
                rules.append(
                    SecurityRule(
                        path=rel_path,
                        line=line_no,
                        http_method=method,
                        pattern=pattern,
                        decision=action,
                        role=action_arg or None,
                    )
                )
    return rules


def _extract_endpoints(functions: list[KotlinFunction]) -> list[tuple[str, str, KotlinFunction]]:
    """Return list of (http_method, full_url_path, KotlinFunction)."""
    endpoints: list[tuple[str, str, KotlinFunction]] = []
    for fn in functions:
        for _, ann in fn.annotations:
            m_map = _HTTP_METHOD_MAP_RE.search(ann)
            if not m_map:
                continue
            ann_name = m_map.group(1)
            args = m_map.group(2)
            m_path = re.search(r"""["']([^"']+)["']""", args)
            sub_path = m_path.group(1) if m_path else ""
            method = {
                "GetMapping": "GET",
                "PostMapping": "POST",
                "PutMapping": "PUT",
                "DeleteMapping": "DELETE",
                "PatchMapping": "PATCH",
                "RequestMapping": "ANY",
            }[ann_name]
            full_path = _normalize_url_path(fn.class_prefix, sub_path)
            endpoints.append((method, full_path, fn))
    return endpoints


def _endpoint_looks_sensitive_without_auth(fn: KotlinFunction) -> bool:
    full_fn = fn.header_text + "\n" + fn.body_text + "\n" + " ".join(a for _, a in fn.annotations)
    if _AUTH_GUARD_RE.search(full_fn) or _PRINCIPAL_PARAM_RE.search(fn.header_text):
        return False
    # Check if controller method reads DB / JDBC / Repository / Reader / Service
    if _JDBC_SINK_RE.search(fn.body_text) or _SQL_KEYWORD_RE.search(fn.body_text):
        return True
    for field_name, field_type in fn.injected_fields.items():
        if re.search(rf"\b{re.escape(field_name)}\s*\.", fn.body_text):
            if any(k in field_type.lower() for k in ("jdbc", "repo", "reader", "dao", "service", "store")):
                return True
    return False


def _analyze_route_authorization(
    security_rules: list[SecurityRule],
    endpoints: list[tuple[str, str, KotlinFunction]],
) -> list[Finding]:
    findings: list[Finding] = []
    for idx, rule in enumerate(security_rules):
        if rule.decision not in ("permitAll", "anonymous"):
            continue
        # Check if a later rule restricts a broader overlapping pattern (e.g. /api/pickup/** hasRole("MECHANIC"))
        shadowed_by = [
            later
            for later in security_rules[idx + 1 :]
            if later.decision in ("hasRole", "hasAnyRole", "hasAuthority", "authenticated")
            and _ant_matches(later.pattern, rule.pattern)
        ]

        # Find matching controller handler(s)
        matching_handlers = [
            (m, p, fn)
            for (m, p, fn) in endpoints
            if p == rule.pattern and (rule.http_method is None or m == "ANY" or m == rule.http_method)
        ]

        handler_sensitive = any(_endpoint_looks_sensitive_without_auth(fn) for _, _, fn in matching_handlers)
        if shadowed_by and (handler_sensitive or not matching_handlers):
            req_role = shadowed_by[0].role or shadowed_by[0].decision
            findings.append(
                Finding(
                    category="SAST",
                    path=rule.path,
                    **{"class": "route-authorization"},
                    line=rule.line,
                    endLine=rule.line,
                    severity="HIGH",
                    description=(
                        f"Route '{rule.pattern}' is explicitly exposed with {rule.decision}() before stricter "
                        f"rule '{shadowed_by[0].pattern}' ({req_role}) while handler accesses backend data without authorization checks."
                    ),
                    remediation=f"Remove {rule.decision}() on '{rule.pattern}' or enforce '{req_role}' access control.",
                    rule_id="sast-spring-route-permit-all-shadowed",
                    evidence=f"{rule.pattern} -> {rule.decision}() before {shadowed_by[0].pattern}",
                )
            )
    return findings


def _method_checks_owner(fn: KotlinFunction) -> bool:
    full = fn.header_text + "\n" + fn.body_text + "\n" + " ".join(a for _, a in fn.annotations)
    if _AUTH_GUARD_RE.search(full):
        return True
    # Check if SQL WHERE clause filters by an owner column (supports both "..." and """...""")
    for m_sql in re.finditer(r'(?:"""([\s\S]*?)"""|"([^"\r\n]*)")', fn.body_text):
        sql_str = m_sql.group(1) if m_sql.group(1) is not None else m_sql.group(2)
        if not re.search(r"\bWHERE\b", sql_str, flags=re.IGNORECASE):
            continue
        where_part = re.split(r"\bWHERE\b", sql_str, maxsplit=1, flags=re.IGNORECASE)[1]
        for tok in re.findall(r"""\b([A-Za-z_][A-Za-z0-9_]*)\b""", where_part):
            if _OWNER_FIELD_RE.match(tok):
                return True
    return False


def _method_queries_owned_resource(
    fn: KotlinFunction,
    table_owners: dict[str, set[str]],
    model_owners: dict[str, set[str]],
) -> tuple[bool, int, int]:
    """Return (is_unscoped_owned_query, start_line, end_line)."""
    # Must query SQL / repository data
    if not (_JDBC_SINK_RE.search(fn.body_text) or _SQL_KEYWORD_RE.search(fn.body_text)):
        return False, fn.start_line, fn.start_line

    # Check if SQL touches a table with an owner column or selects an owner column or returns an owned model
    owned_hit = False
    for m_from in re.finditer(r"""(?i)\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)""", fn.body_text):
        tbl = m_from.group(1).lower()
        if tbl in table_owners:
            owned_hit = True
            break

    if not owned_hit:
        for m_sel in re.finditer(r"""(?i)\bSELECT\s+(.+?)\s+\bFROM\b""", fn.body_text):
            cols = re.findall(r"""\b([A-Za-z_][A-Za-z0-9_]*)\b""", m_sel.group(1))
            if any(_OWNER_FIELD_RE.match(c) for c in cols):
                owned_hit = True
                break

    if not owned_hit:
        for m_ret in re.finditer(r""":\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*(?:=|\{)""", fn.header_text):
            if m_ret.group(1) in model_owners:
                owned_hit = True
                break

    if not owned_hit:
        return False, fn.start_line, fn.start_line

    if _method_checks_owner(fn):
        return False, fn.start_line, fn.start_line

    # Find first SQL/query line inside fn
    query_line = fn.start_line
    for ln, ltxt in fn.body_lines:
        if _JDBC_SINK_RE.search(ltxt) or _SQL_KEYWORD_RE.search(ltxt):
            query_line = ln
            break
    s_l, e_l = _clamp_range(fn.start_line, max(fn.start_line + 1, query_line))
    return True, s_l, e_l


def _analyze_object_authorization(
    functions: list[KotlinFunction],
    endpoints: list[tuple[str, str, KotlinFunction]],
    security_rules: list[SecurityRule],
    table_owners: dict[str, set[str]],
    model_owners: dict[str, set[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    # Index methods by (class_name, method_name)
    methods_by_class: dict[tuple[str, str], KotlinFunction] = {
        (fn.class_name, fn.name): fn for fn in functions if fn.class_name
    }

    for _, full_path, ctrl_fn in endpoints:
        # Look for path-variable object identifier endpoints like /tickets/{ticketId}
        if "{" not in full_path or "}" not in full_path:
            continue
        if "@PathVariable" not in ctrl_fn.header_text:
            continue

        # Skip explicitly role-restricted admin/staff endpoints (e.g. hasRole("MECHANIC")/hasRole("ADMIN"))
        is_staff_only = any(
            rule.decision in ("hasRole", "hasAnyRole", "hasAuthority")
            and (_ant_matches(rule.pattern, full_path) or rule.pattern == full_path)
            for rule in security_rules
        )
        if is_staff_only:
            continue

        # If controller already extracts Principal/Authentication or checks ownership, skip
        if _PRINCIPAL_PARAM_RE.search(ctrl_fn.header_text) or _AUTH_GUARD_RE.search(ctrl_fn.header_text + ctrl_fn.body_text):
            continue

        # Case A: Controller directly queries DB by path variable without owner check
        direct_vuln, d_s, d_e = _method_queries_owned_resource(ctrl_fn, table_owners, model_owners)
        if direct_vuln:
            findings.append(
                Finding(
                    category="SAST",
                    path=ctrl_fn.path,
                    **{"class": "object-authorization"},
                    line=d_s,
                    endLine=d_e,
                    severity="HIGH",
                    description=(
                        f"Endpoint '{full_path}' retrieves an owned record by path ID without filtering or verifying object ownership."
                    ),
                    remediation="Pass authenticated Principal identifier into the query predicate and restrict results to the owner.",
                    rule_id="sast-kotlin-idor-direct",
                    evidence=f"{ctrl_fn.name} ({full_path})",
                )
            )
            continue

        # Case B: Inter-procedural call from controller to injected Repository/Reader/Service method
        for field_name, field_type in ctrl_fn.injected_fields.items():
            for m_call in re.finditer(rf"\b{re.escape(field_name)}\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", ctrl_fn.body_text):
                callee_name = m_call.group(1)
                target_fn = methods_by_class.get((field_type, callee_name))
                if target_fn is None:
                    continue
                is_vuln, t_s, t_e = _method_queries_owned_resource(target_fn, table_owners, model_owners)
                if is_vuln:
                    findings.append(
                        Finding(
                            category="SAST",
                            path=target_fn.path,
                            **{"class": "object-authorization"},
                            line=t_s,
                            endLine=t_e,
                            severity="HIGH",
                            description=(
                                f"Repository method '{field_type}.{callee_name}' called from '{full_path}' fetches an owner-scoped record without checking Principal ownership."
                            ),
                            remediation="Include authenticated Principal ownership in the repository query WHERE clause.",
                            rule_id="sast-kotlin-idor-interprocedural",
                            evidence=f"{ctrl_fn.name} -> {field_type}.{callee_name}",
                        )
                    )
    return findings


def scan(root: Path, params: dict[str, Any] | None = None) -> list[Finding]:
    params = params or {}
    table_owners, model_owners = _collect_schema_and_models(root)

    all_functions: list[KotlinFunction] = []
    security_rules: list[SecurityRule] = []
    findings: list[Finding] = []

    for kt_file in sorted(root.rglob("*.kt")):
        if not kt_file.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in kt_file.relative_to(root).parts):
            continue
        rel_path = kt_file.relative_to(root).as_posix()
        try:
            raw_text = kt_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        cleaned_lines = _strip_kotlin_comments(raw_text.splitlines())
        cleaned_text = "\n".join(cleaned_lines)

        file_functions = _parse_kotlin_functions(rel_path, cleaned_text)
        all_functions.extend(file_functions)

        for fn in file_functions:
            findings.extend(_analyze_sql_injection(fn))

        findings.extend(_analyze_tls_verification(rel_path, cleaned_text))
        findings.extend(_analyze_credentialed_cors(rel_path, cleaned_text))
        security_rules.extend(_extract_security_rules(rel_path, cleaned_text))

    endpoints = _extract_endpoints(all_functions)
    findings.extend(_analyze_route_authorization(security_rules, endpoints))
    findings.extend(_analyze_object_authorization(all_functions, endpoints, security_rules, table_owners, model_owners))

    # Deduplicate identical detections on same (class, path, line)
    unique: list[Finding] = []
    seen: set[tuple[str | None, str, int | None]] = set()
    for f in findings:
        key = (f.class_, f.path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
