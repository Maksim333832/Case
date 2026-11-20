# Case — AI Security Workflow (Cyber Garden 2026)

Платформа визуальной автоматизации проверок безопасности для Kotlin / Spring Boot (Gradle Kotlin DSL) проектов.

## Структура репозитория
- [`backend/`](backend/) — FastAPI backend, workflow-движок (DAG), планировщик, адаптеры сканеров, валидатор AI-рекомендаций, шаблоны, CI/CD-интеграция и тесты.
  - [Руководство по запуску (`backend/README.md`)](backend/README.md)
  - [Контракты для Frontend и сканеров (`backend/CONTRACTS.md`)](backend/CONTRACTS.md)
  - [Архитектура (`backend/ARCHITECTURE.md`)](backend/ARCHITECTURE.md)

## Быстрый старт Backend
```bash
cd backend
cp .env.example .env
pip install -r requirements.txt
pytest -q
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
