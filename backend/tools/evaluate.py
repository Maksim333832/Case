from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.masking import contains_raw_secret
from app.core.models import Finding

ALLOWED_SUBMISSION_KEYS = {
    "category",
    "path",
    "class",
    "line",
    "endLine",
    "group",
    "artifact",
    "version",
    "advisoryId",
    "severity",
    "description",
    "remediation",
}


@dataclass
class EvaluationResult:
    matched: list[dict[str, Any]] = field(default_factory=list)
    missed: list[dict[str, Any]] = field(default_factory=list)
    control_false_positives: list[dict[str, Any]] = field(default_factory=list)
    extra_findings: list[dict[str, Any]] = field(default_factory=list)
    schema_errors: list[str] = field(default_factory=list)
    total_truth: int = 0
    total_reported: int = 0
    total_controls: int = 0

    @property
    def recall(self) -> float:
        if self.total_truth == 0:
            return 1.0
        return len(self.matched) / self.total_truth

    @property
    def precision(self) -> float:
        if self.total_reported == 0:
            return 1.0 if self.total_truth == 0 else 0.0
        return len(self.matched) / self.total_reported

    @property
    def passed(self) -> bool:
        return (
            not self.schema_errors
            and not self.missed
            and not self.control_false_positives
        )


def _norm_path(p: str) -> str:
    return p.strip().replace("\\", "/")


def _ranges_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start <= b_end and b_start <= a_end


def _validate_submission_payload(report_data: Any) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    if not isinstance(report_data, dict) or not isinstance(report_data.get("findings"), list):
        return [], ["Root JSON must be an object with a 'findings' array"]

    valid_items: list[dict[str, Any]] = []
    for idx, raw in enumerate(report_data["findings"]):
        if not isinstance(raw, dict):
            errors.append(f"findings[{idx}] must be an object")
            continue
        extra_keys = set(raw.keys()) - ALLOWED_SUBMISSION_KEYS
        if extra_keys:
            errors.append(f"findings[{idx}] has non-specification keys: {sorted(extra_keys)}")
        try:
            Finding.model_validate(raw)
        except ValidationError as exc:
            errors.append(f"findings[{idx}] schema error: {exc.errors()[0]['msg']}")
            continue

        # Check no raw secret leaked into description/remediation
        for field_name in ("description", "remediation"):
            val = raw.get(field_name)
            if isinstance(val, str) and contains_raw_secret(val):
                errors.append(f"findings[{idx}].{field_name} appears to contain an unmasked secret")

        valid_items.append(raw)
    return valid_items, errors


def _matches_truth_finding(rep: dict[str, Any], truth: dict[str, Any]) -> bool:
    if rep.get("category") != truth.get("category"):
        return False

    cat = truth["category"]
    if cat in ("SECRET", "SAST"):
        if rep.get("class") != truth.get("class"):
            return False
        r_path = _norm_path(rep["path"])
        r_start = int(rep["line"])
        r_end = int(rep.get("endLine") or r_start)

        locations = [{"path": truth["path"], "line": truth["line"], "endLine": truth.get("endLine") or truth["line"]}]
        locations.extend(truth.get("alternateLocations") or [])

        for loc in locations:
            t_path = _norm_path(loc["path"])
            t_start = int(loc["line"])
            t_end = int(loc.get("endLine") or t_start)
            if r_path == t_path and _ranges_overlap(r_start, r_end, t_start, t_end):
                return True
        return False

    if cat == "SCA":
        if _norm_path(rep["path"]) != _norm_path(truth["path"]):
            return False
        return (
            rep.get("group") == truth.get("group")
            and rep.get("artifact") == truth.get("artifact")
            and rep.get("version") == truth.get("version")
            and rep.get("advisoryId") in (truth.get("advisoryIds") or [])
        )

    return False


def _matches_control(rep: dict[str, Any], ctrl: dict[str, Any]) -> bool:
    if rep.get("category") != ctrl.get("category"):
        return False
    cat = ctrl["category"]
    if cat in ("SECRET", "SAST"):
        if _norm_path(rep["path"]) != _norm_path(ctrl["path"]):
            return False
        r_start = int(rep["line"])
        r_end = int(rep.get("endLine") or r_start)
        c_start = int(ctrl["line"])
        c_end = int(ctrl.get("endLine") or c_start)
        return _ranges_overlap(r_start, r_end, c_start, c_end)
    if cat == "SCA":
        return (
            rep.get("group") == ctrl.get("group")
            and rep.get("artifact") == ctrl.get("artifact")
            and rep.get("version") == ctrl.get("version")
        )
    return False


def evaluate_report(report_data: Any, truth_data: dict[str, Any]) -> EvaluationResult:
    valid_reports, schema_errors = _validate_submission_payload(report_data)
    truth_findings = list(truth_data.get("findings") or [])
    controls = list(truth_data.get("controls") or [])

    result = EvaluationResult(
        schema_errors=schema_errors,
        total_truth=len(truth_findings),
        total_reported=len(valid_reports),
        total_controls=len(controls),
    )

    matched_report_indices: set[int] = set()
    for truth_item in truth_findings:
        matched_idx: int | None = None
        for idx, rep_item in enumerate(valid_reports):
            if _matches_truth_finding(rep_item, truth_item):
                matched_idx = idx
                break
        if matched_idx is not None:
            matched_report_indices.add(matched_idx)
            result.matched.append({"truth": truth_item, "reported": valid_reports[matched_idx]})
        else:
            result.missed.append(truth_item)

    for ctrl in controls:
        for idx, rep_item in enumerate(valid_reports):
            if _matches_control(rep_item, ctrl):
                result.control_false_positives.append({"control": ctrl, "reported": rep_item})
                break

    for idx, rep_item in enumerate(valid_reports):
        if idx not in matched_report_indices:
            result.extra_findings.append(rep_item)

    return result


def format_evaluation_summary(res: EvaluationResult) -> str:
    lines = [
        "=== Evaluation Report ===",
        f"Matched: {len(res.matched)}/{res.total_truth} | Reported: {res.total_reported} | "
        f"Precision: {res.precision:.2%} | Recall: {res.recall:.2%}",
        f"Control False Positives: {len(res.control_false_positives)}/{res.total_controls}",
    ]
    if res.schema_errors:
        lines.append("\n[SCHEMA ERRORS]")
        for err in res.schema_errors:
            lines.append(f"  - {err}")
    if res.missed:
        lines.append("\n[MISSED FINDINGS]")
        for m in res.missed:
            loc = (
                f"{m.get('group')}:{m.get('artifact')}:{m.get('version')} ({m.get('advisoryIds')})"
                if m.get("category") == "SCA"
                else f"{m.get('class')} @ {m.get('path')}:{m.get('line')}"
            )
            lines.append(f"  - {m.get('id', '?')} [{m.get('category')}] {loc}")
    if res.control_false_positives:
        lines.append("\n[CONTROL FALSE POSITIVES]")
        for fp in res.control_false_positives:
            c = fp["control"]
            lines.append(
                f"  - {c.get('id', '?')} [{c.get('category')}] @ {c.get('path')}:{c.get('line')} "
                f"(reason: {c.get('reason')})"
            )
    if res.extra_findings:
        lines.append(f"\n[UNMATCHED EXTRA FINDINGS: {len(res.extra_findings)}]")
        for ex in res.extra_findings[:10]:
            lines.append(f"  - [{ex.get('category')}] {ex.get('path')}:{ex.get('line', '')} {ex.get('class', ex.get('advisoryId', ''))}")
    lines.append(f"\nSTATUS: {'PASS' if res.passed else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate report.json against ground-truth findings and controls")
    parser.add_argument("--report", required=True, help="Path to generated report.json")
    parser.add_argument("--truth", required=True, help="Path to ground-truth/training-findings.json")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    truth_path = Path(args.truth)

    if not report_path.is_file():
        print(f"Report file not found: {report_path}", file=sys.stderr)
        return 2
    if not truth_path.is_file():
        print(f"Truth file not found: {truth_path}", file=sys.stderr)
        return 2

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    truth_data = json.loads(truth_path.read_text(encoding="utf-8"))
    res = evaluate_report(report_data, truth_data)
    print(format_evaluation_summary(res))
    return 0 if res.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
