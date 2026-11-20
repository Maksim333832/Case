# Changelog

## [0.2.0] - 2026-11-20
### Added
- `REPOSITORY_ANALYSIS.md`, ADRs (`docs/adr/`), `DEVELOPMENT_LOG.md`, `FINAL_REPORT.md`.
- Собственные обобщённые анализаторы без заглушек: `backend/app/scanners_impl/secrets.py`, `sca.py`, `sast.py`.
- Полноценный React + TypeScript + Vite + React Flow frontend (`frontend/`): Dashboard, Workflow Editor, Run Details, Run History, Templates, Settings.

## [0.1.0] - 2026-11-20
### Added
- FastAPI backend, контракты `Finding`/`BaseNode`, авто-реестр нод (`1 файл = 1 нода`).
- DAG Workflow Engine (`graph.py`, `executor.py`, `events.py`, `scheduler.py`) + WebSocket `/ws/runs/{id}`.
- Источники `source.upload_zip` (zip-slip/symlink/limit protection, авто-поиск корня Gradle) и `source.git_clone` (allowlist).
- Логические ноды (`if_else`, `compare`, `regex` с ReDoS-защитой), `findings.merge`, `findings.export` (`report.json` + `report.md`).
- AI-нода `ai.explain` с OpenAI-совместимым клиентом (Gemini/Ollama/vLLM), `validator.py` и fallback.
- Каналы уведомлений `notify.telegram`, `notify.webhook`, `notify.smtp`, шаблоны, CI/CD-гейт.
- Инструменты `tools/evaluate.py`, `tools/mutate_project.py`, `tools/demo.py` и набор тестов `pytest`.
