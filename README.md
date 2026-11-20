# AI Security Workflow (Cyber Garden 2026 — «Центр-инвест»)

Полнофункциональная расширяемая платформа автоматизации проверок безопасности Kotlin / Spring Boot / Gradle-проектов: собственные статические анализаторы (**Secrets**, **SCA**, **SAST**), DAG-движок выполнения сценариев с ветвлением и WebSocket-мониторингом, валидация AI-объяснений от галлюцинаций и визуальный редактор на React + TypeScript + React Flow.

## Основные возможности

- **Расширяемость «1 файл = 1 нода»:** новые ноды авто-обнаруживаются через `@register_node`, а `GET /api/node-types` отдаёт JSON Schema параметров, по которой React-интерфейс сам строит палитру и формы настроек.
- **Собственные обобщённые анализаторы (`backend/app/scanners_impl/`):**
  - `secrets.py` (`password`, `api-key`, `configuration-token`, `secret-fallback`, `recoverable-token` в Kotlin/YAML/Properties, с маскированием и исключением плейсхолдеров);
  - `sca.py` (`build.gradle.kts`, `gradle.properties`, `val`/`by project`, многострочные `add(...)`, `gradle.lockfile`, строгое числовое сравнение с `vulnerabilities.json`);
  - `sast.py` (`sql-injection`, `tls-verification`, `credentialed-cors`, `route-authorization`, межпроцедурный `object-authorization`).
- **Надёжный DAG Engine:** валидация циклов и портов, топологический запуск на `asyncio` + `asyncio.to_thread`, ветвление (`skipped`), изоляция падений, ReDoS-защита для regex, защита от Zip-Slip/симлинков и allowlist для Git.
- **AI Explain & Hallucination Guard:** OpenAI-совместимый клиент (Gemini, Ollama, vLLM), переключение провайдера в Settings, проверка существования `finding_ref`, файлов/строк и CVE/GHSA, 1 повтор + детерминированный fallback.
- **Безопасность по умолчанию:** шифрование credentials (Fernet AES), автоматическое маскирование секретов во всех логах, событиях, ошибках и отчётах.

## Быстрый старт (чистая машина)

### 1. Backend (Python 3.11+)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend (Node.js 20+)
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```
Откройте `http://localhost:5173`. Swagger API доступен на `http://localhost:8000/docs`.

## Проверка качества и точности
```bash
cd backend
pytest -q
python -m tools.demo --project /path/to/training-project --truth /path/to/training-findings.json
python -m tools.mutate_project --source /path/to/training-project --truth /path/to/training-findings.json --out /tmp/mutants
```

## Документация проекта
- [`FINAL_REPORT.md`](./FINAL_REPORT.md) — итоговый технический отчёт (архитектура, алгоритмы, метрики 15/15 и mutation testing)
- [`REPOSITORY_ANALYSIS.md`](./REPOSITORY_ANALYSIS.md) — анализ учебного репозитория `TBagirov/training`
- [`CONTRACTS.md`](./CONTRACTS.md) — контракты `Finding`, портов, графа и WebSocket-событий
- [`docs/adr/`](./docs/adr/) — Architecture Decision Records
- [`CHANGELOG.md`](./CHANGELOG.md) и [`DEVELOPMENT_LOG.md`](./DEVELOPMENT_LOG.md)
