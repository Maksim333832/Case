from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.core.masking import contains_raw_secret, mask_text
from app.core.models import Finding
from app.nodes.ai.prompts import build_finding_ref_map

_CODE_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL | re.IGNORECASE)
_FILE_REF_RE = re.compile(
    r"\b(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:kt|kts|yml|yaml|properties|sql|md|lockfile|java|xml)\b"
)
_LINE_WORD_RE = re.compile(r"(?i)\b(?:lines?|строк[аеуи]?)\s+(\d+)(?:\s*[-–]\s*(\d+))?")
_FILE_COLON_LINE_RE = re.compile(r"(?i)(?:\.kt|\.kts|\.yml|\.yaml|\.properties|\.sql|\.md):(\d+)\b")
_HASH_LINE_RE = re.compile(r"#L(\d+)\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)


class AIReportItemSchema(BaseModel):
    finding_ref: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    risk: str = Field(min_length=1)
    fix_steps: list[str] = Field(min_length=1)


class AIReportSchema(BaseModel):
    summary: str = Field(min_length=1)
    items: list[AIReportItemSchema] = Field(default_factory=list)


@dataclass
class AIValidationStats:
    passed: bool
    retried: bool = False
    dropped_items: int = 0
    dropped_cve: int = 0
    used_fallback: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "retried": self.retried,
            "dropped_items": self.dropped_items,
            "dropped_cve": self.dropped_cve,
            "used_fallback": self.used_fallback,
        }


@dataclass
class AIValidationResult:
    report: dict[str, Any] | None
    stats: AIValidationStats


def _strip_code_fences(raw: str) -> str:
    m = _CODE_FENCE_RE.match(raw)
    return m.group(1) if m else raw.strip()


def _item_mentions_wrong_location(item: AIReportItemSchema, finding: Finding) -> str | None:
    combined = " ".join([item.explanation, item.risk, *item.fix_steps])
    target_norm = finding.path.replace("\\", "/")
    target_name = Path(target_norm).name

    for m in _FILE_REF_RE.finditer(combined):
        mentioned = m.group(0).replace("\\", "/")
        if "/" in mentioned:
            if mentioned != target_norm and not target_norm.endswith("/" + mentioned):
                return f"wrong_file:{mentioned}"
        else:
            if mentioned != target_name:
                return f"wrong_file:{mentioned}"

    if finding.line is not None:
        lo = finding.line
        hi = finding.endLine if finding.endLine is not None else finding.line
        mentioned_lines: list[int] = []
        for m in _LINE_WORD_RE.finditer(combined):
            mentioned_lines.append(int(m.group(1)))
            if m.group(2):
                mentioned_lines.append(int(m.group(2)))
        for m in _FILE_COLON_LINE_RE.finditer(combined):
            mentioned_lines.append(int(m.group(1)))
        for m in _HASH_LINE_RE.finditer(combined):
            mentioned_lines.append(int(m.group(1)))

        for ln in mentioned_lines:
            if ln < lo or ln > hi:
                return f"wrong_line:{ln}"

    return None


def _strip_hallucinated_advisories(text: str, allowed_upper: set[str]) -> tuple[str, int]:
    dropped = 0

    def _replace_match(m: re.Match[str]) -> str:
        nonlocal dropped
        token = m.group(0)
        if token.upper() in allowed_upper:
            return token
        dropped += 1
        return "[removed-advisory]"

    cleaned = _CVE_RE.sub(_replace_match, text)
    cleaned = _GHSA_RE.sub(_replace_match, cleaned)
    return cleaned, dropped


def validate_ai_response(
    raw_text: str,
    findings: list[Finding],
    extra_secrets: tuple[str, ...] = (),
) -> AIValidationResult:
    cleaned_raw = _strip_code_fences(raw_text)
    try:
        parsed_json = json.loads(cleaned_raw)
        schema_obj = AIReportSchema.model_validate(parsed_json)
    except (json.JSONDecodeError, ValidationError) as exc:
        return AIValidationResult(
            report=None,
            stats=AIValidationStats(passed=False, reasons=[f"invalid_schema:{exc.__class__.__name__}"]),
        )

    if contains_raw_secret(cleaned_raw, extra_secrets):
        return AIValidationResult(
            report=None,
            stats=AIValidationStats(passed=False, reasons=["raw_secret_detected"]),
        )

    ref_map = build_finding_ref_map(findings)
    allowed_advisories: set[str] = set()
    for f in findings:
        if f.advisoryId:
            allowed_advisories.add(f.advisoryId.upper())
        for alias in f.aliases:
            allowed_advisories.add(alias.upper())

    dropped_items = 0
    dropped_cve = 0
    reasons: list[str] = []

    clean_summary, cve_drops_sum = _strip_hallucinated_advisories(
        mask_text(schema_obj.summary, extra_secrets), allowed_advisories
    )
    dropped_cve += cve_drops_sum
    if cve_drops_sum:
        reasons.append(f"dropped_summary_cve:{cve_drops_sum}")

    valid_items: list[dict[str, Any]] = []
    for item in schema_obj.items:
        target = ref_map.get(item.finding_ref)
        if target is None:
            dropped_items += 1
            reasons.append(f"unknown_ref:{item.finding_ref}")
            continue

        loc_err = _item_mentions_wrong_location(item, target)
        if loc_err is not None:
            dropped_items += 1
            reasons.append(f"{item.finding_ref}:{loc_err}")
            continue

        expl, d1 = _strip_hallucinated_advisories(mask_text(item.explanation, extra_secrets), allowed_advisories)
        risk, d2 = _strip_hallucinated_advisories(mask_text(item.risk, extra_secrets), allowed_advisories)
        clean_steps: list[str] = []
        d3 = 0
        for step in item.fix_steps:
            st, ds = _strip_hallucinated_advisories(mask_text(step, extra_secrets), allowed_advisories)
            d3 += ds
            clean_steps.append(st)
        dropped_cve += d1 + d2 + d3

        valid_items.append(
            {
                "finding_ref": item.finding_ref,
                "explanation": expl,
                "risk": risk,
                "fix_steps": clean_steps,
            }
        )

    if findings and not valid_items:
        return AIValidationResult(
            report=None,
            stats=AIValidationStats(
                passed=False,
                dropped_items=dropped_items,
                dropped_cve=dropped_cve,
                reasons=reasons + ["no_valid_items_remaining"],
            ),
        )

    return AIValidationResult(
        report={"summary": clean_summary, "items": valid_items},
        stats=AIValidationStats(
            passed=True,
            dropped_items=dropped_items,
            dropped_cve=dropped_cve,
            reasons=reasons,
        ),
    )


def build_fallback_ai_report(
    findings: list[Finding],
    language: str = "ru",
    extra_secrets: tuple[str, ...] = (),
) -> dict[str, Any]:
    ref_map = build_finding_ref_map(findings)
    if not findings:
        msg = "Уязвимости не обнаружены." if language.startswith("ru") else "No security findings detected."
        return {"summary": msg, "items": []}

    items: list[dict[str, Any]] = []
    for ref, f in ref_map.items():
        if f.category == "SCA":
            expl = (
                f"Обнаружена уязвимая зависимость {f.group}:{f.artifact}:{f.version} ({f.advisoryId}) в {f.path}."
                if language.startswith("ru")
                else f"Vulnerable dependency {f.group}:{f.artifact}:{f.version} ({f.advisoryId}) declared in {f.path}."
            )
            default_fix = (
                f"Обновите {f.group}:{f.artifact} до исправленной версии, указанной в advisory {f.advisoryId}."
                if language.startswith("ru")
                else f"Upgrade {f.group}:{f.artifact} to a patched version addressing {f.advisoryId}."
            )
        else:
            line_txt = f"{f.line}" if f.endLine in (None, f.line) else f"{f.line}-{f.endLine}"
            expl = (
                f"Проблема класса '{f.class_}' обнаружена в {f.path} (строка {line_txt})."
                if language.startswith("ru")
                else f"Issue of class '{f.class_}' detected in {f.path} (line {line_txt})."
            )
            default_fix = (
                f"Устраните уязвимость '{f.class_}' в {f.path}:{f.line}."
                if language.startswith("ru")
                else f"Remediate '{f.class_}' in {f.path}:{f.line}."
            )

        desc = mask_text(f.description or expl, extra_secrets)
        fix = mask_text(f.remediation or default_fix, extra_secrets)
        sev = f.severity or "MEDIUM"
        risk_txt = (
            f"Уровень критичности: {sev}. Потенциальный риск безопасности приложения."
            if language.startswith("ru")
            else f"Severity: {sev}. Potential application security exposure."
        )
        items.append(
            {
                "finding_ref": ref,
                "explanation": desc,
                "risk": risk_txt,
                "fix_steps": [fix],
            }
        )

    summary = (
        f"Детерминированный шаблонный отчёт: выявлено находок — {len(findings)}. Проверьте критичные записи и примените рекомендации."
        if language.startswith("ru")
        else f"Deterministic fallback report: {len(findings)} security findings require review."
    )
    return {"summary": summary, "items": items}
