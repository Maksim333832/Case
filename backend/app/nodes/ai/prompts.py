from __future__ import annotations

import json
from typing import Any

from app.core.masking import mask_secret, mask_text
from app.core.models import Finding


def build_finding_ref_map(findings: list[Finding]) -> dict[str, Finding]:
    return {f"F-{idx:03d}": f for idx, f in enumerate(findings, start=1)}


def build_ai_prompts(findings: list[Finding], language: str = "ru", extra_secrets: tuple[str, ...] = ()) -> tuple[str, str]:
    lang_label = "Russian" if language.lower().startswith("ru") else "English"
    system_prompt = (
        "You are an application security engineer assisting developers. "
        "You NEVER invent vulnerabilities, file paths, line numbers, or CVE/GHSA identifiers. "
        "You ONLY explain the exact findings provided in the input JSON. "
        f"Write explanations in {lang_label}. "
        "Respond strictly with valid JSON matching this schema: "
        '{"summary": string, "items": [{"finding_ref": string, "explanation": string, "risk": string, "fix_steps": [string]}]}.'
    )

    ref_map = build_finding_ref_map(findings)
    sanitized_items: list[dict[str, Any]] = []
    for ref, f in ref_map.items():
        item: dict[str, Any] = {
            "finding_ref": ref,
            "category": f.category,
            "path": f.path,
            "severity": f.severity or "MEDIUM",
        }
        if f.category in ("SECRET", "SAST"):
            item["class"] = f.class_
            item["line"] = f.line
            if f.endLine is not None:
                item["endLine"] = f.endLine
        elif f.category == "SCA":
            item["group"] = f.group
            item["artifact"] = f.artifact
            item["version"] = f.version
            item["advisoryId"] = f.advisoryId
            if f.aliases:
                item["aliases"] = f.aliases
        if f.description:
            item["description"] = mask_text(f.description, extra_secrets)
        if f.evidence:
            item["evidence"] = mask_secret(f.evidence)
        sanitized_items.append(item)

    user_prompt = (
        "Analyze and explain the following masked security findings. "
        "Keep every finding_ref exact, never cite files/lines/CVEs not present in the input, and never include raw secrets.\n"
        f"INPUT_FINDINGS={json.dumps(sanitized_items, ensure_ascii=False)}"
    )
    return system_prompt, user_prompt
