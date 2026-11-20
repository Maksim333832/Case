# Changelog

## [0.2.0] - 2026-11-20
### Added
- `REPOSITORY_ANALYSIS.md`, ADRs (`docs/adr/`), `DEVELOPMENT_LOG.md`, `FINAL_REPORT.md`.
- Собственные обобщённые анализаторы без заглушек (`USE_STUB_SCANNERS=0`): `backend/app/scanners_impl/secrets.py`, `sca.py`, `sast.py` (15/15 ground truth, 0/6 controls, 15/15 на мутантах).
- API настроек провайдера LLM (`GET/PUT /api/settings/llm`) с шифрованием ключа и `GET /api/uploads`.
- Полноценный React + TypeScript + Vite + React Flow frontend (`frontend/`): Dashboard, Workflow Editor, Run Details, Run History, Templates, Settings.
- Полная тестовая батарея (41/41 `pytest -q`) и сборка фронтенда (`tsc -b && vite build`).

## [0.1.0] - 2026-11-20
### Added
- FastAPI backend, контракты `Finding`/`BaseNode`, авто-реестр нод (`1 файл = 1 нода`).
- DAG Workflow Engine (`graph.py`, `executor.py`, `events.py`, `scheduler.py`) + WebSocket `/ws/runs/{id}`.
- Источники `source.upload_zip` (zip-slip/symlink/limit protection, авто-поиск корня Gradle) и `source.git_clone` (allowlist).
- Логические ноды (`if_else`, `compare`, `regex` с ReDoS-защитой), `findings.merge`, `findings.export` (`report.json` + `report.md`).
- AI-нода `ai.explain` с OpenAI-совместимым клиентом (Gemini/Ollama/vLLM), `validator.py` и fallback.
- Каналы уведомлений `notify.telegram`, `notify.webhook`, `notify.smtp`, шаблоны, CI/CD-гейт.
- Инструменты `tools/evaluate.py`, `tools/mutate_project.py`, `tools/demo.py` и набор тестов `pytest`.
