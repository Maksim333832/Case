# FINAL REPORT — AI Security Workflow (Cyber Garden 2026)

## 1. Что реализовано

Разработан полноценный продукт **AI Security Workflow** — расширяемая визуальная платформа автоматизации проверок безопасности приложений (Kotlin / Spring Boot / Gradle) с собственными анализаторами Secrets, SCA и SAST, собственным DAG-движком сценариев, валидацией и агрегацией результатов через LLM, real-time мониторингом по WebSocket и React + React Flow веб-интерфейсом.

Ключевые реализованные возможности:
- Загрузка проектов через защищённый ZIP-архив (`source.upload_zip`) и разрешённый Git-клон (`source.git_clone`, allowlist по умолчанию `https://github.com/TBagirov/training`), автоматическое определение корня Kotlin/Gradle-проекта даже во вложенных директориях.
- Визуальный конструктор workflow на React Flow (`frontend/`) с динамической палитрой и формами параметров из `GET /api/node-types`, сохранением в SQLite и живой потоковой индикацией статусов и ошибок нод по WebSocket (`/ws/runs/{run_id}`).
- Три собственных обобщённых статических анализатора (`backend/app/scanners_impl/{secrets,sca,sast}.py`) без сторонних сканеров (`USE_STUB_SCANNERS=0`).
- Дедупликация и экспорт в строгий формат организаторов (`report.json` + `report.md`).
- AI-объяснение (`ai.explain`) с OpenAI-совместимым клиентом (переключение Gemini / Ollama / vLLM через настройки БД или `.env`), строгим `validator.py` против галлюцинаций и детерминированным fallback-отчётом.
- Логическое ветвление (`logic.if_else`, `logic.compare`, `logic.regex` с ReDoS-защитой), планировщик `trigger.schedule` (APScheduler), шифрование credentials (Fernet AES) и каналы уведомлений (`notify.telegram`, `notify.webhook`, `notify.smtp`).
- CI/CD-гейт (`POST /api/ci/workflows/{id}/run`) и генерация конфигов GitHub Actions / GitLab CI.

---

## 2. Архитектура

```text
+-----------------------------------------------------------------------+
|                       React + TypeScript + Vite                       |
|  Dashboard | Workflow Editor (React Flow) | Run Details | Templates   |
|  Run History | Settings (LLM Provider & Fernet Credentials Vault)     |
+-------------------------------+---------------------------------------+
                                | HTTP REST (/api/*) & WS (/ws/runs/*)
+-------------------------------v---------------------------------------+
|                           FastAPI Backend                             |
|  /api/node-types   /api/workflows   /api/runs   /api/templates        |
|  /api/uploads      /api/credentials /api/settings/llm   /api/ci/*     |
+-------------------------------+---------------------------------------+
                                |
+-------------------------------v---------------------------------------+
|                   Custom DAG Workflow Engine (asyncio)                |
|  - Graph & Port Validation     - Topological Sort & Branch Skipping   |
|  - asyncio.to_thread Scanners  - Timeouts & Failure Isolation         |
|  - EventBroker -> WebSocket    - APScheduler Cron/Interval Triggers   |
+------+------------------------+--------------------------+------------+
       |                        |                          |
+------v------+         +-------v-------+          +-------v-------+
| NodePlugin  |         | Custom Engines|          | AI & Security |
| Registry    |         | secrets.py    |          | Fernet Crypto |
| (16 nodes,  |         | sca.py        |          | MaskingFilter |
| 1 file/node)|         | sast.py       |          | validator.py  |
+-------------+         +---------------+          +---------------+
```

---

## 3. Структура файлов

```text
Case/
├── README.md
├── CONTRACTS.md
├── REPOSITORY_ANALYSIS.md
├── CHANGELOG.md
├── DEVELOPMENT_LOG.md
├── FINAL_REPORT.md
├── .env.example
├── .gitignore
├── docs/adr/
│   ├── 0001-node-registry-and-dag-engine.md
│   ├── 0002-custom-generalized-scanners.md
│   └── 0003-ai-validation-and-secret-masking.md
├── backend/
│   ├── requirements.txt
│   ├── pyproject.toml
│   ├── data/vulnerabilities.json
│   ├── templates/*.json
│   ├── tools/{evaluate.py,mutate_project.py,demo.py}
│   ├── tests/*.py
│   └── app/
│       ├── main.py, config.py
│       ├── api/{workflows,runs,node_types,credentials,uploads,templates,settings,ci,ws}.py
│       ├── core/{models,severity,masking,crypto,db,logging}.py
│       ├── engine/{graph,executor,events,scheduler}.py
│       ├── scanners_impl/{secrets,sca,sast}.py
│       └── nodes/{base,registry,triggers/*,source/*,scanners/*,logic/*,findings/*,ai/*,notify/*}
└── frontend/
    ├── package.json, tsconfig.json, vite.config.ts, index.html
    └── src/
        ├── App.tsx, main.tsx, index.css
        ├── types/workflow.ts
        ├── api/client.ts
        ├── hooks/useRunWebSocket.ts
        ├── nodes/WorkflowNode.tsx
        ├── components/{Layout,StatusBadge,SeverityBadge,NodePalette,NodeInspector}.tsx
        └── pages/{DashboardPage,WorkflowEditorPage,RunDetailsPage,RunHistoryPage,TemplatesPage,SettingsPage}.tsx
```

---

## 4. Реализованные ноды (16 авто-регистрируемых типов)

| Группа | Тип ноды | Входы -> Выходы | Назначение |
| --- | --- | --- | --- |
| `trigger` | `trigger.manual` | — -> `out` | Ручной запуск сценария |
| `trigger` | `trigger.schedule` | — -> `out` | Периодический запуск (APScheduler interval/cron) |
| `source` | `source.upload_zip` | `trigger` -> `workspace` | Распаковка ZIP (Zip-Slip/symlink/size/count checks) + поиск корня Gradle |
| `source` | `source.git_clone` | `trigger` -> `workspace` | Клонирование разрешённых репозиториев из allowlist |
| `scanner` | `scanner.secrets` | `workspace` -> `findings` | Адаптер собственного анализатора `scanners_impl/secrets.py` |
| `scanner` | `scanner.sca` | `workspace` -> `findings` | Адаптер собственного анализатора `scanners_impl/sca.py` |
| `scanner` | `scanner.sast` | `workspace` -> `findings` | Адаптер собственного анализатора `scanners_impl/sast.py` |
| `logic` | `logic.if_else` | `in` -> `true`, `false` | Условное ветвление с `skipped` для неактивной ветки |
| `logic` | `logic.compare` | `in` -> `match`, `no_match` | Пороговое сравнение количества или критичности находок |
| `logic` | `logic.regex` | `in` -> `match`, `no_match` | Проверка регулярным выражением с таймаутом (ReDoS-защита) |
| `findings` | `findings.merge` | `in` (multi) -> `findings` | Объединение потоков и дедупликация |
| `findings` | `findings.export` | `in` -> `report`, `findings` | Экспорт `report.json` и `report.md` в UTF-8 |
| `ai` | `ai.explain` | `in` -> `report`, `findings` | Агрегация и объяснение находок через LLM + `validator.py` |
| `notify` | `notify.telegram` | `in` -> `result` | Отправка сводки и отчёта в Telegram Bot API |
| `notify` | `notify.webhook` | `in` -> `result` | HTTP Webhook (добавлена отдельным файлом без правки ядра) |
| `notify` | `notify.smtp` | `in` -> `result` | Email-уведомление SMTP (добавлена отдельным файлом без правки ядра) |

---

## 5. Алгоритмы Secrets, SCA, SAST

### 5.1 Secrets (`app/scanners_impl/secrets.py`)
- **Kotlin (с вырезанием комментариев и сохранением номеров строк):**
  - `secret-fallback`: выделение правой части Elvis-оператора `System.getenv(...) ?: "..."` и `System.getProperty(...) ?: "..."` (однострочных и перенесённых), а также Spring-фолбэков `${VAR:literal}` в конфигах с фильтрацией несекретных параметров (`PORT`, `HOST`) и заглушек.
  - `recoverable-token`: построение карты локальных строковых переменных в области видимости и свёртка операций `+` и строковых шаблонов `"$p1$p2"` с отслеживанием передачи результата в заголовки/Bearer-методы (`setBearerAuth`, `header(...)`, `mapOf(...)`).
  - `password` / `api-key` / `configuration-token`: анализ присваиваний переменных, параметров конструкторов и прямых вызовов заголовков с проверкой энтропии Шеннона, разнообразия классов символов и исключением плейсхолдеров (`YOUR_API_KEY`, `${...}`, `<...>`) и markdown-документации.
- **YAML / Properties:** разбор AST PyYAML (`yaml.compose`) с сохранением точных номеров строк и вложенных путей ключей. Все значения маскируются до возврата `Finding`.

### 5.2 SCA (`app/scanners_impl/sca.py`)
- Загружает базу `vulnerabilities.json` строго по пути из параметров/конфига (`VULN_DB_PATH`).
- Собирает свойства из `gradle.properties`, локальные `val`/`var`, `providers.gradleProperty(...).get()`, `by project` из `build.gradle.kts`/`build.gradle`, а также однострочные, многострочные `add("implementation", ...)` и именованные объявления зависимостей.
- При `lockfile_priority=True` сопоставляет координаты с `gradle.lockfile`.
- Исключает неизвестные версии и версии с квалификаторами (`-beta1`, `-SNAPSHOT`), сравнивает версии строго покомпонентно слева направо (`1.9 == 1.9.0`, `20230227`), проверяет `lower=null` и `lowerInclusive`/`upperInclusive`, и порождает отдельную находку на каждый сработавший advisory.

### 5.3 SAST (`app/scanners_impl/sast.py`)
- **`sql-injection`:** структурный разбор функций Kotlin и аргументов JDBC-методов (`queryForList`, `queryForObject`, `query`, `update`, `execute`), проверка интерполяции (`$var`, `${expr}`), конкатенации `+` и `.format(...)`, включая локальные SQL-переменные. Запросы с `?` и отдельными аргументами считаются безопасными.
- **`tls-verification`:** обнаружение `HostnameVerifier { ... -> true }`, анонимных `object : HostnameVerifier` и пустых `checkServerTrusted`. Штатный `HttpsURLConnection` не вызывает ложных срабатываний.
- **`credentialed-cors`:** обнаружение сочетания wildcard-паттернов (`"*"` в `allowedOriginPatterns`/`allowedOrigins`/`addAllowedOrigin*`/`@CrossOrigin`) с `allowCredentials = true`.
- **`route-authorization`:** сопоставление упорядоченных правил `.authorizeHttpRequests` с обработчиками контроллеров: срабатывает, когда `permitAll()`/`anonymous()` предшествует более строгому правилу на родительском префиксе (`/**`), а контроллер обращается к БД/репозиториям без дополнительной проверки роли. Статический публичный каталог не считается уязвимым.
- **`object-authorization`:** межпроцедурный анализ: извлекает таблицы с owner-колонками из `*.sql` и `data class` с owner-полями, сопоставляет контроллеры с `@PathVariable` ID (без `Principal` и без роли сотрудника) и вызываетмые методы репозитория/БД, проверяя наличие фильтрации по владельцу в `WHERE` или в коде.

---

## 6. AI-интеграция и валидация

- `ai.explain` отправляет в LLM **только** маскированные `Finding` (категория, класс/advisory, путь, строка, описание, маскированный `evidence`); исходный код и реальные секреты никогда не покидают платформу.
- Поддерживается любое OpenAI-совместимое API (`/chat/completions`): Gemini, Ollama, vLLM. Переключение доступно как в `.env`, так и через UI (`Settings` -> `PUT /api/settings/llm` с хранением зашифрованного ключа в SQLite).
- `app/nodes/ai/validator.py` проверяет: (1) JSON-схему ответа; (2) отсутствие сырых секретов; (3) существование `finding_ref`; (4) совпадение файла и строки находки (отклоняются чужие файлы/строки); (5) удаление выдуманных `CVE`/`GHSA`, не присутствующих во входных данных. При сбое выполняется 1 повторная попытка, затем — детерминированный fallback-отчёт.

---

## 7. Результаты тестирования

Полный прогон тестовой батареи выполнен при `USE_STUB_SCANNERS=0`:

```text
pytest -v  ->  41 passed, 1 warning in 3.89s
```

Состав проверок:
- Контракты `Finding` (`StrictInt`, запрет абсолютных/traversal-путей, `to_submission()`), шифрование Fernet, `SecretMaskingFilter` и `mask_text` (14 тестов).
- Графовый валидатор (циклы, недопустимые порты, отсутствие триггера), ZIP-безопасность (Zip-Slip, симлинки, авто-определение корня), Git allowlist, изоляция сбоев и таймаутов, WebSocket-стриминг (5 тестов).
- Логика (`if_else`, `compare`, ReDoS-защита `regex`), AI-валидатор (битый JSON, неизвестный `finding_ref`, выдуманный CVE, неверный файл/строка, fallback при ошибке LLM), шифрованный Vault, APScheduler и полный E2E-пайплайн с Telegram (5 тестов).
- Оценка точности на `training-project/` и контролях, работа `mutate_project`, маскирование токена Telegram при сетевой ошибке (4 теста).
- Детальные тесты собственных анализаторов Secrets, SCA (включая мульти-advisory и квалификаторы), SAST, а также API переключения LLM-провайдера и списка загрузок (5 тестов).
- Шаблоны, CI/CD-гейт (`422` при превышении порога), добавление `notify.webhook` / `notify.smtp` без правки ядра, CLI `tools.demo` без заглушек (8 тестов).
- Сборка фронтенда: `npm run build` (`tsc -b && vite build`) — **0 ошибок** (`1620 modules transformed`).
- Сквозной live-тест через Vite-прокси (`http://127.0.0.1:5173`) -> FastAPI -> WebSocket (`22` события) -> 15/15 находок в `report.json` и `report.md`.

---

## 8. Precision и Recall (`tools.evaluate`)

Запуск на `/home/user/training/training-project` относительно `/home/user/training/ground-truth/training-findings.json` с реальными анализаторами (`USE_STUB_SCANNERS=0`):

```text
=== Evaluation Report ===
Matched: 15/15 | Reported: 15 | Precision: 100.00% | Recall: 100.00%
Control False Positives: 0/6

STATUS: PASS
```

- **SECRET:** 5/5 (100% recall, 0 false positives на `A-CTRL-01`, `A-CTRL-02`)
- **SCA:** 5/5 (100% recall, 0 false positives на `A-CTRL-03`)
- **SAST:** 5/5 (100% recall, 0 false positives на `A-CTRL-04`, `A-CTRL-05`, `A-CTRL-06`)

---

## 9. Результаты mutation testing (`tools.mutate_project`)

Инструмент `python -m tools.mutate_project` формирует мутированные копии проекта с переименованием классов и переменных, заменой префиксов секретов, сдвигом строк, переносом методов и изменением синтаксиса `build.gradle.kts` / `gradle.properties`:

| Вариант | Matched | Reported | Precision | Recall | Control FP | Статус |
| --- | --- | --- | --- | --- | --- | --- |
| `mutant_rename_shift` | 15/15 | 15 | **100.00%** | **100.00%** | 0/6 | **PASS** |
| `mutant_gradle_styles` | 15/15 | 15 | **100.00%** | **100.00%** | 0/6 | **PASS** |

(Контрольные заглушки `_stubs.py` ожидаемо проваливают оба мутированных варианта.)

---

## 10. Безопасность

- **Шифрование секретов:** `credentials` и кастомный `llm_api_key` шифруются Fernet; ключ `APP_SECRET_KEY` или файл `~/.ai_security_workflow_secret.key` (`0600`) хранится строго вне Git-репозитория.
- **Защита от утечек:** REST API возвращает только маскированный суффикс (`****xxxx`), `SecretMaskingFilter` и `mask_text` очищают логи, исключения, `output_preview` и WebSocket-события.
- **ZIP и Git:** проверка канонического пути против Zip-Slip, запрет симлинков, ограничение суммарного размера (50 МБ) и числа файлов (2000), строгий allowlist для `git_clone`.
- **Regex:** модуль `regex` с жёстким таймаутом (0.2 с) и ограничением размера входа исключает ReDoS.

---

## 11. Инструкция запуска

### Backend (Python 3.11+)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env   # при необходимости задайте LLM_API_KEY
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend (Node 20+)
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```
Откройте `http://localhost:5173` в браузере (прокси `/api`, `/health`, `/ws` настроен в `vite.config.ts`).

### Оценка точности и демонстрация
```bash
cd backend
pytest -q
python -m tools.demo --project /path/to/training-project --truth /path/to/training-findings.json
```

---

## 12. Известные ограничения

- Анализаторы ориентированы на проекты Kotlin / Spring Boot / Gradle (`build.gradle.kts`, `build.gradle`, `application.yml`, `.properties`, `*.sql`) и справочник `vulnerabilities.json` формата numeric-dot-separated.
- Межпроцедурный IDOR-анализ (`object-authorization`) отслеживает прямые вызовы из контроллера в SQL/репозиторий (1 уровень делегирования) и требует наличия схемы/модели или SELECT-колонок с идентификатором владельца.
- В бесплатном тарифе Gemini API периодически возвращает HTTP 503 при пиковой нагрузке — платформа автоматически выполняет 1 повтор и переходит на детерминированный fallback без срыва отчёта.
- Встроенный `chat_id` для Telegram-бота в `.env` не задаётся заранее и вводится пользователем после `/start` боту.

---

## 13. Какие дополнительные ноды можно подключить без изменения ядра

Благодаря авто-реестру `@register_node` в `app/nodes/` (принцип «1 файл = 1 нода») и генерации UI-форм по `params_schema` из `GET /api/node-types` без изменения ядра, API и фронтенда можно добавить:
- **Source:** `source.gitlab_mr`, `source.s3_bundle`, `source.docker_image`
- **Scanners:** `scanner.iac_terraform`, `scanner.dockerfile`, `scanner.openapi_lint`
- **Findings / Policy:** `findings.sarif_export`, `findings.severity_gate`, `findings.jira_sync`
- **AI:** `ai.pr_summary`, `ai.patch_suggest`
- **Notify:** `notify.slack`, `notify.mattermost`, `notify.github_pr_comment`
