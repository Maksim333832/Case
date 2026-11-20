from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from typing import Any, Callable, Protocol

from app.config import Settings
from app.core.masking import mask_secret, mask_text
from app.core.models import Finding


class ScannerNotConfiguredError(RuntimeError):
    """Raised when teammate scanner implementation is not connected and USE_STUB_SCANNERS is disabled."""


class ScannerCallable(Protocol):
    def __call__(self, root: Path, params: dict[str, Any]) -> list[Finding]: ...


def _load_callable_from_spec(spec: str) -> ScannerCallable:
    if ":" in spec:
        module_name, attr_name = spec.split(":", 1)
    else:
        module_name, attr_name = spec, "scan"
    module = importlib.import_module(module_name)
    fn = getattr(module, attr_name, None)
    if not callable(fn):
        raise ImportError(f"Scanner entry point '{spec}' is not callable")
    return fn


def resolve_scanner_callable(kind: str, settings: Settings) -> ScannerCallable:
    """Resolve teammate scanner `scan(root, params)` or optional dev stub under USE_STUB_SCANNERS=1."""
    configured_spec = {
        "secrets": settings.scanner_secrets_impl,
        "sca": settings.scanner_sca_impl,
        "sast": settings.scanner_sast_impl,
    }.get(kind, "").strip()

    if configured_spec:
        return _load_callable_from_spec(configured_spec)

    # Check standard team drop-in module path: app.scanners_impl.<kind>:scan
    dropin_module = f"app.scanners_impl.{kind}"
    try:
        mod = importlib.import_module(dropin_module)
        fn = getattr(mod, "scan", None)
        if callable(fn):
            return fn
    except ModuleNotFoundError:
        pass

    # Strictly guarded dev-only stubs (disabled by default)
    if settings.use_stub_scanners:
        from app.nodes.scanners import _stubs

        stub_map: dict[str, ScannerCallable] = {
            "secrets": _stubs.scan_secrets_stub,
            "sca": _stubs.scan_sca_stub,
            "sast": _stubs.scan_sast_stub,
        }
        return stub_map[kind]

    raise ScannerNotConfiguredError(
        f"Scanner implementation for '{kind}' is not connected yet. "
        f"Provide app/scanners_impl/{kind}.py with scan(root, params) or configure "
        f"SCANNER_{kind.upper()}_IMPL. Development stubs are disabled by default (USE_STUB_SCANNERS=0)."
    )


def sanitize_findings(raw_items: list[Any], project_root: Path) -> list[Finding]:
    """Validate Finding contract and enforce secret masking defense-in-depth."""
    validated: list[Finding] = []
    for item in raw_items:
        finding = item if isinstance(item, Finding) else Finding.model_validate(item)
        updates: dict[str, Any] = {}
        if finding.evidence:
            updates["evidence"] = mask_secret(finding.evidence)
        if finding.description:
            updates["description"] = mask_text(finding.description)
        if finding.remediation:
            updates["remediation"] = mask_text(finding.remediation)
        if updates:
            finding = finding.model_copy(update=updates)
        validated.append(finding)
    return validated


async def run_scanner_adapter(
    kind: str,
    workspace_input: Any,
    params: dict[str, Any],
    settings: Settings,
) -> list[Finding]:
    if isinstance(workspace_input, dict) and "project_root" in workspace_input:
        root = Path(str(workspace_input["project_root"]))
    elif isinstance(workspace_input, (str, Path)):
        root = Path(str(workspace_input))
    else:
        raise ValueError(f"Scanner '{kind}' requires Workspace input with 'project_root'")

    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Project root directory does not exist: {root}")

    scan_fn = resolve_scanner_callable(kind, settings)
    raw_findings = await asyncio.to_thread(scan_fn, root, params)
    return sanitize_findings(raw_findings, root)
