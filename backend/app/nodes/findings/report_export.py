from __future__ import annotations

import json
from collections import Counter
from typing import Any

from pydantic import BaseModel, Field

from app.core.masking import mask_secret, mask_text
from app.core.models import Finding
from app.core.severity import severity_counts
from app.nodes.base import BaseNode, NodeContext, Port
from app.nodes.registry import register_node


def _extract_findings_and_ai(payload: Any, fallback_findings: list[Finding], fallback_ai: dict[str, Any] | None) -> tuple[list[Finding], dict[str, Any] | None]:
    ai_report = fallback_ai
    findings: list[Finding] = []

    if isinstance(payload, dict):
        if "ai_report" in payload and isinstance(payload["ai_report"], dict):
            ai_report = payload["ai_report"]
        elif "summary" in payload and "items" in payload:
            ai_report = payload
        raw_findings = payload.get("findings")
        if isinstance(raw_findings, list):
            findings = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in raw_findings]
    elif isinstance(payload, list):
        findings = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in payload]

    if not findings and fallback_findings:
        findings = list(fallback_findings)

    return findings, ai_report


def _sanitize_for_export(findings: list[Finding], extra_secrets: tuple[str, ...]) -> list[Finding]:
    sanitized: list[Finding] = []
    for f in findings:
        updates: dict[str, Any] = {}
        if f.evidence:
            updates["evidence"] = mask_secret(f.evidence)
        if f.description:
            updates["description"] = mask_text(f.description, extra_secrets)
        if f.remediation:
            updates["remediation"] = mask_text(f.remediation, extra_secrets)
        sanitized.append(f.model_copy(update=updates) if updates else f)
    return sanitized


def render_markdown_report(
    title: str,
    findings: list[Finding],
    ai_report: dict[str, Any] | None = None,
    extra_secrets: tuple[str, ...] = (),
) -> str:
    lines: list[str] = [f"# {title}", ""]
    sev_counts = severity_counts(findings)
    cat_counts = Counter(f.category for f in findings)

    lines.append("## Сводка")
    lines.append("")
    lines.append(f"- Всего находок: **{len(findings)}**")
    if findings:
        cat_str = ", ".join(f"{k}: {cat_counts[k]}" for k in ("SECRET", "SAST", "SCA") if cat_counts.get(k))
        sev_str = ", ".join(f"{k}: {sev_counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if sev_counts.get(k))
        lines.append(f"- По категориям: {cat_str}")
        lines.append(f"- По критичности: {sev_str}")
    else:
        lines.append("- Находок не обнаружено.")
    lines.append("")

    if findings:
        lines.append("## Таблица находок")
        lines.append("")
        lines.append("| # | Категория | Критичность | Тип / Advisory | Местоположение | Описание |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for idx, f in enumerate(findings, start=1):
            sev = f.severity or "-"
            if f.category == "SCA":
                kind_label = f"`{f.group}:{f.artifact}:{f.version}` ({f.advisoryId})"
                loc = f"`{f.path}`"
            else:
                kind_label = f"`{f.class_}`"
                line_part = f"{f.line}" if f.endLine in (None, f.line) else f"{f.line}-{f.endLine}"
                loc = f"`{f.path}:{line_part}`"
            desc = mask_text(f.description or "-", extra_secrets).replace("\n", " ").replace("|", "\\|")
            lines.append(f"| {idx} | {f.category} | {sev} | {kind_label} | {loc} | {desc} |")
        lines.append("")

        lines.append("## Детали и рекомендации")
        lines.append("")
        for idx, f in enumerate(findings, start=1):
            if f.category == "SCA":
                header = f"### {idx}. [{f.category}] {f.group}:{f.artifact}:{f.version} ({f.advisoryId})"
                loc = f"`{f.path}`"
            else:
                line_part = f"{f.line}" if f.endLine in (None, f.line) else f"{f.line}-{f.endLine}"
                header = f"### {idx}. [{f.category}] {f.class_}"
                loc = f"`{f.path}:{line_part}`"
            lines.append(header)
            lines.append(f"- **Место:** {loc}")
            if f.severity:
                lines.append(f"- **Критичность:** {f.severity}")
            if f.description:
                lines.append(f"- **Описание:** {mask_text(f.description, extra_secrets)}")
            if f.remediation:
                lines.append(f"- **Исправление:** {mask_text(f.remediation, extra_secrets)}")
            lines.append("")

    if ai_report:
        lines.append("## AI-анализ и рекомендации")
        lines.append("")
        summary = mask_text(str(ai_report.get("summary", "")), extra_secrets)
        if summary:
            lines.append(summary)
            lines.append("")
        items = ai_report.get("items") or []
        for item in items:
            ref = item.get("finding_ref", "")
            expl = mask_text(str(item.get("explanation", "")), extra_secrets)
            risk = mask_text(str(item.get("risk", "")), extra_secrets)
            steps = item.get("fix_steps") or []
            lines.append(f"### Находка `{ref}`")
            if expl:
                lines.append(f"- **Суть:** {expl}")
            if risk:
                lines.append(f"- **Риск:** {risk}")
            if steps:
                lines.append("- **Шаги исправления:**")
                for step in steps:
                    lines.append(f"  - {mask_text(str(step), extra_secrets)}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


class ReportExportParams(BaseModel):
    title: str = Field(default="Security Analysis Report", description="Header title for Markdown report")
    include_ai_summary: bool = Field(default=True, description="Include AI explanation block in Markdown report if available")


@register_node
class ReportExportNode(BaseNode):
    type = "findings.export"
    label = "Export Reports"
    group = "findings"
    description = "Generates consistent report.json (submission format) and readable report.md from the same findings."
    inputs = [Port(name="in", kind="Any", description="Findings list or AI report bundle")]
    outputs = [Port(name="report", kind="Report", description="Exported report metadata and findings")]
    Params = ReportExportParams

    async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
        assert isinstance(params, ReportExportParams)
        findings, ai_report = _extract_findings_and_ai(
            inputs.get("in"),
            ctx.last_findings,
            ctx.ai_report if params.include_ai_summary else None,
        )
        extra = tuple(ctx.extra_secrets)
        safe_findings = _sanitize_for_export(findings, extra)
        ctx.last_findings = safe_findings

        ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
        json_path = ctx.artifacts_dir / "report.json"
        md_path = ctx.artifacts_dir / "report.md"

        submission_obj = {"findings": [f.to_submission() for f in safe_findings]}
        json_path.write_text(json.dumps(submission_obj, ensure_ascii=False, indent=2), encoding="utf-8")

        md_text = render_markdown_report(
            title=params.title,
            findings=safe_findings,
            ai_report=ai_report if params.include_ai_summary else None,
            extra_secrets=extra,
        )
        md_path.write_text(md_text, encoding="utf-8")

        ctx.report_files["json"] = json_path
        ctx.report_files["md"] = md_path

        return {
            "report": {
                "findings": safe_findings,
                "ai_report": ai_report,
                "formats": ["json", "md"],
                "report_json_path": str(json_path),
                "report_md_path": str(md_path),
            }
        }
