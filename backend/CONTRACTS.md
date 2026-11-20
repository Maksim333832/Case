# AI Security Workflow — Team Contracts

> Frozen baseline contracts for Frontend (React + React Flow) and Scanner developers (Secrets / SCA / SAST).  
> Verified against organizer specification `docs/submission-format.md` and `ground-truth/training-findings.json`.

---

## 1. Scanner Interface (for Team Members 3 & 4)

Every scanner module exposes a single synchronous function:

```python
from pathlib import Path
from app.core.models import Finding

def scan(root: Path, params: dict) -> list[Finding]:
    ...
```

### Integration Paths
Place implementations in `app/scanners_impl/` or configure via env vars:
- `app/scanners_impl/secrets.py` (`SCANNER_SECRETS_IMPL=module:scan`)
- `app/scanners_impl/sca.py` (`SCANNER_SCA_IMPL=module:scan`)
- `app/scanners_impl/sast.py` (`SCANNER_SAST_IMPL=module:scan`)

### Scanner Rules
1. `root` is the resolved project root (e.g., `training-project/`, containing `build.gradle.kts` / `settings.gradle.kts`).
2. `path` in each `Finding` MUST be relative to `root` with `/` separators (e.g., `src/main/resources/application.yml`), no leading `/`, no `..`, no `:`.
3. For **SECRET / SAST**:
   - `category`: `"SECRET"` or `"SAST"`
   - `class` (alias `class_`): required exact class code (e.g., `password`, `api-key`, `configuration-token`, `secret-fallback`, `recoverable-token`, `sql-injection`, `tls-verification`, `credentialed-cors`, `route-authorization`, `object-authorization`).
   - `line`: strict integer `>= 1` (never string or bool).
   - `endLine`: optional strict integer with `line <= endLine <= line + 14`.
4. For **SCA**:
   - `category`: `"SCA"`
   - `path`: dependency declaration file (e.g., `build.gradle.kts`).
   - `group`, `artifact`, `version`, `advisoryId`: all required strings (one finding per advisory; `advisoryId` is either `GHSA-...` or `CVE-...`).
   - `params` receives `vuln_db_path` (path to JSON vulnerability database — **never hardcode it!**) and `lockfile_priority` (`bool`, prefer version from `gradle.lockfile` when present).
5. **Secret Masking**: Never store raw secret literals in `Finding.description`, `Finding.remediation`, or `Finding.evidence`. Mask secrets with `app.core.masking.mask_secret(...)`.
6. **Stubs Rule**: Development stub scanners are strictly disabled by default (`USE_STUB_SCANNERS=0`).

---

## 2. `Finding` Model & Submission Format

`Finding.to_submission()` emits **only** organizer-specified JSON keys:
```json
{
  "findings": [
    {
      "category": "SECRET",
      "path": "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
      "class": "api-key",
      "line": 7,
      "severity": "MEDIUM",
      "description": "Embedded API key used in X-Api-Key header",
      "remediation": "Read API key from environment configuration"
    },
    {
      "category": "SCA",
      "path": "build.gradle.kts",
      "group": "org.apache.commons",
      "artifact": "commons-text",
      "version": "1.9",
      "advisoryId": "CVE-2022-42889"
    }
  ]
}
```
Internal fields (`id`, `rule_id`, `evidence`, `confidence`, `aliases`) are stripped from submission export.

---

## 3. Workflow JSON (React Flow Compatible)

```json
{
  "nodes": [
    {
      "id": "n1",
      "type": "trigger.manual",
      "params": {},
      "position": {"x": 0, "y": 0}
    },
    {
      "id": "n2",
      "type": "source.upload_zip",
      "params": {"upload_id": "u_123", "subdir": ""},
      "position": {"x": 220, "y": 0}
    }
  ],
  "edges": [
    {
      "id": "e1",
      "source": "n1",
      "sourceHandle": "out",
      "target": "n2",
      "targetHandle": "trigger"
    }
  ]
}
```
Note: React Flow nodes passing `data.params` are also accepted automatically.

---

## 4. Node Registry (`GET /api/node-types`)

Returns list of registered nodes for building the UI palette and dynamic parameter forms:
```json
[
  {
    "type": "logic.if_else",
    "label": "If / Else",
    "group": "logic",
    "description": "...",
    "inputs": [{"name": "in", "kind": "Any", "required": true, "multiple": false}],
    "outputs": [
      {"name": "true", "kind": "Any", "required": true, "multiple": false},
      {"name": "false", "kind": "Any", "required": true, "multiple": false}
    ],
    "params_schema": { "type": "object", "properties": { ... } }
  }
]
```

---

## 5. Execution Events (`WS /ws/runs/{run_id}`)

New WebSocket subscribers receive accumulated run history first, then live events:
- `run_started`
- `node_started`
- `node_finished`
- `node_failed`
- `node_skipped`
- `run_finished`

Payload example:
```json
{
  "event": "node_finished",
  "run_id": "run_...",
  "node_id": "n3",
  "status": "success",
  "started_at": "2026-11-20T12:00:00Z",
  "finished_at": "2026-11-20T12:00:01Z",
  "duration_ms": 412,
  "output_preview": {"kind": "Findings", "count": 5, "by_severity": {"HIGH": 3, "MEDIUM": 2}},
  "error": null
}
```

Node status lifecycle: `pending -> running -> success | failed | skipped`.

---

## 6. REST API Endpoints

- `GET /health`
- `GET /api/node-types`
- `GET / POST /api/workflows`, `GET / PUT / DELETE /api/workflows/{id}`
- `POST /api/workflows/{id}/run` (supports `?wait=true` for CI)
- `GET /api/runs`, `GET /api/runs/{id}`, `GET /api/runs/{id}/report.json`, `GET /api/runs/{id}/report.md`
- `WS /ws/runs/{run_id}`
- `POST /api/uploads`
- `GET / POST / DELETE /api/credentials` (write-only secret values, preview returns `"****"` + suffix)
- `GET /api/templates`, `POST /api/templates/{id}/copy`
