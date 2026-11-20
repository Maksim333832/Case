# AI Security Workflow — Backend

Платформа визуальной автоматизации проверок безопасности для Kotlin / Spring Boot (Gradle Kotlin DSL) приложений.

## Возможности
- **Workflow Engine (DAG):** топологическая сортировка, асинхронное исполнение, таймауты, ветвления (`logic.if_else`, `logic.compare`, `logic.regex` с ReDoS-защитой), изоляция ошибок (`failed` / `skipped` / `partial`).
- **Планировщик (APScheduler):** cron и интервальные запуски (`trigger.schedule`), автоматическое восстановление расписаний из SQLite при старте.
- **Источники кода:** безопасная распаковка ZIP (`source.upload_zip`, защита от zip-slip, симлинков, лимиты размера) и `source.git_clone` по allowlist; автоопределение корня Gradle-проекта.
- **Адаптер сканеров (`scanner.secrets`, `scanner.sca`, `scanner.sast`):** единый контракт `scan(root: Path, params: dict) -> list[Finding]`. Заглушки строго выключены по умолчанию (`USE_STUB_SCANNERS=0`).
- **Два согласованных отчёта:** `report.json` в формате организаторов и читаемый `report.md` с маскированием секретов.
- **AI-анализ с валидацией и fallback (`ai.explain`):** OpenAI-совместимый клиент (переключение между облачным API и локальными Ollama/vLLM через `.env`), проверка JSON-схемы, `finding_ref`, файлов/строк и CVE/GHSA против справочника, 1 ретрай и детерминированный fallback.
- **Безопасность секретов:** шифрование Fernet (`credentials`), маскирование `"****"` в API и фильтр маскирования в логах/WS-событиях.
- **Расширяемость (1 файл = 1 нода):** автообнаружение `@register_node` в `app/nodes/` без правок движка и API.
- **Шаблоны и CI/CD:** готовые шаблоны в `templates/*.json`, копирование и публикация, CI/CD-гейт (`POST /api/ci/workflows/{id}/run`) и генерация конфигов GitHub Actions / GitLab CI.

---

## Быстрый старт (< 5 минут)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Запуск сервера:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Проверка здоровья и доступных нод:
```bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/node-types | head -c 500
```

---

## Подключение сканеров команды (участники 3 и 4)

Реализации сканеров должны экспортировать функцию:
```python
from pathlib import Path
from app.core.models import Finding

def scan(root: Path, params: dict) -> list[Finding]:
    ...
```

Разместите модули:
- `app/scanners_impl/secrets.py` (или `SCANNER_SECRETS_IMPL=pkg.mod:scan`)
- `app/scanners_impl/sca.py` (или `SCANNER_SCA_IMPL=pkg.mod:scan`)
- `app/scanners_impl/sast.py` (или `SCANNER_SAST_IMPL=pkg.mod:scan`)

Подробный контракт — в `CONTRACTS.md`.  
Только для локальной разработки без готовых сканеров можно временно задать `USE_STUB_SCANNERS=1` (в демо и финальной сборке флаг выключен!).

---

## Переключение LLM (Облако ↔ Закрытый контур Ollama / vLLM)

Логика `ai.explain` не меняется при переключении провайдера — меняются только переменные окружения:

### Вариант 1: Google Gemini (OpenAI-compatible endpoint)
```env
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-3.5-flash-lite
LLM_API_KEY=<ваш_ключ>
```

### Вариант 2: Локальная Ollama (закрытый контур)
```env
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=qwen2.5-coder:7b
LLM_API_KEY=ollama
```

### Вариант 3: Локальный vLLM
```env
LLM_BASE_URL=http://localhost:8001/v1
LLM_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
LLM_API_KEY=EMPTY
```

---

## Тестирование, оценка по эталону и мутации

Запуск всех unit/integration/E2E тестов:
```bash
pytest -q
```

Оценка сгенерированного `report.json` по эталону организаторов:
```bash
python -m tools.evaluate --report out.json --truth /path/to/training/ground-truth/training-findings.json
```

Генерация мутированных копий проекта против переобучения сканеров:
```bash
python -m tools.mutate_project \
  --source /path/to/training/training-project \
  --truth /path/to/training/ground-truth/training-findings.json \
  --out /tmp/mutated-projects
```

Сквозной демонстрационный прогон:
```bash
python -m tools.demo --project /path/to/training/training-project --truth /path/to/training/ground-truth/training-findings.json --use-stubs
```
(уберите `--use-stubs` после подключения реальных сканеров команды).
