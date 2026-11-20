from __future__ import annotations

from collections import Counter
from typing import Any

import regex

from app.core.models import Finding
from app.core.severity import SEVERITY_ORDER, max_severity, severity_counts

MAX_REGEX_INPUT_LEN = 50_000
REGEX_TIMEOUT_SECONDS = 0.25


def extract_findings(raw_input: Any, fallback: list[Finding]) -> list[Finding]:
    if isinstance(raw_input, list):
        return [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_input]
    if isinstance(raw_input, dict) and isinstance(raw_input.get("findings"), list):
        return [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_input["findings"]]
    return list(fallback)


def resolve_selector(selector: str, findings: list[Finding], report_md_text: str = "") -> Any:
    key = selector.strip()
    if key == "findings.count":
        return len(findings)
    if key == "findings.max_severity":
        return max_severity(findings) or "NONE"
    if key == "findings.high_or_critical":
        return sum(1 for f in findings if (f.severity or "").upper() in ("HIGH", "CRITICAL"))
    if key.startswith("findings.by_category."):
        cat = key.split(".", 2)[2].strip().upper()
        counts = Counter(f.category for f in findings)
        return counts.get(cat, 0)
    if key.startswith("findings.by_severity."):
        sev = key.split(".", 2)[2].strip().upper()
        counts = severity_counts(findings)
        return counts.get(sev, 0)
    if key == "findings.paths":
        return "\n".join(f.path for f in findings)
    if key == "findings.descriptions":
        return "\n".join(f.description or "" for f in findings)
    if key == "findings.classes":
        return "\n".join((f.class_ or f.advisoryId or "") for f in findings)
    if key == "report.md":
        return report_md_text

    # Allow literal fallback if selector doesn't match a known path
    return selector


def safe_regex_search(pattern: str, text: str) -> bool:
    bounded_text = text[:MAX_REGEX_INPUT_LEN]
    try:
        compiled = regex.compile(pattern)
        return compiled.search(bounded_text, timeout=REGEX_TIMEOUT_SECONDS) is not None
    except TimeoutError as exc:
        raise ValueError("Regex evaluation timed out (potential ReDoS pattern)") from exc


def _coerce_comparable(left: Any, right: Any, is_severity: bool = False) -> tuple[Any, Any]:
    if is_severity:
        l_rank = SEVERITY_ORDER.get(None if str(left).upper() == "NONE" else str(left).upper(), 0)
        r_rank = SEVERITY_ORDER.get(None if str(right).upper() == "NONE" else str(right).upper(), 0)
        return l_rank, r_rank

    if isinstance(left, (int, float)) and not isinstance(left, bool):
        if isinstance(right, (int, float)) and not isinstance(right, bool):
            return left, right
        if isinstance(right, str):
            try:
                return left, float(right) if "." in right else int(right)
            except ValueError:
                pass
    return left, right


def evaluate_condition(left_selector: str, op: str, right_val: Any, findings: list[Finding], report_md_text: str = "") -> bool:
    left_val = resolve_selector(left_selector, findings, report_md_text=report_md_text)
    is_severity = left_selector.strip() == "findings.max_severity"

    if op == "regex":
        return safe_regex_search(str(right_val), str(left_val))

    if op == "in":
        if isinstance(right_val, (list, tuple, set)):
            return left_val in right_val
        return str(left_val) in str(right_val)

    l_cmp, r_cmp = _coerce_comparable(left_val, right_val, is_severity=is_severity)

    if op == "==":
        return l_cmp == r_cmp
    if op == "!=":
        return l_cmp != r_cmp
    if op == ">":
        return l_cmp > r_cmp
    if op == ">=":
        return l_cmp >= r_cmp
    if op == "<":
        return l_cmp < r_cmp
    if op == "<=":
        return l_cmp <= r_cmp

    raise ValueError(f"Unsupported operator: {op}")
