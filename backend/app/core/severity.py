from __future__ import annotations

from collections import Counter
from typing import Iterable, Literal

SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_ORDER: dict[str | None, int] = {
    None: 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def severity_rank(severity: str | None) -> int:
    if severity is None:
        return 0
    return SEVERITY_ORDER.get(severity.upper(), 0)


def max_severity(findings: Iterable[object]) -> SeverityLevel | None:
    best: SeverityLevel | None = None
    best_rank = 0
    for f in findings:
        sev = getattr(f, "severity", None) if not isinstance(f, dict) else f.get("severity")
        if sev:
            sev_upper = str(sev).upper()
            rank = SEVERITY_ORDER.get(sev_upper, 0)
            if rank > best_rank:
                best_rank = rank
                best = sev_upper  # type: ignore[assignment]
    return best


def severity_counts(findings: Iterable[object]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for f in findings:
        sev = getattr(f, "severity", None) if not isinstance(f, dict) else f.get("severity")
        key = str(sev).upper() if sev else "UNKNOWN"
        counter[key] += 1
    return dict(counter)
