# ADR-0002: Собственные обобщённые анализаторы Secrets, SCA и SAST

- **Статус:** Принято
- **Контекст:** Запрещены Semgrep, Gitleaks, Trivy, готовые security-правила detekt и поиск уязвимостей через LLM. На финале возможна скрытая вариация с изменёнными именами, литералами, структурой Gradle и сдвинутыми строками.
- **Решение:**
  1. Анализаторы реализуются в `backend/app/scanners_impl/{secrets,sca,sast}.py` по единому контракту `scan(root: Path, params: dict) -> list[Finding]`.
  2. **Secrets:** лексико-синтаксический разбор Kotlin и YAML/properties (пароли, API-ключи, Bearer-токены конфигурации, Elvis-фолбэки после `getenv`, конкатенация локальных строковых переменных) с проверкой энтропии/формата и фильтром плейсхолдеров (`YOUR_*`, `${...}`) и markdown-документации.
  3. **SCA:** разбор `build.gradle.kts`, `gradle.properties`, `val`-переменных, многострочных `add(...)` и `gradle.lockfile`, строгое покомпонентное числовое сравнение версий с `vulnerabilities.json` (путь берётся только из параметров/конфига).
  4. **SAST:** межпроцедурный и структурный анализ Kotlin/Spring Boot: интерполяция/конкатенация в JDBC SQL (с исключением параметризованных `?`), доверительные `HostnameVerifier`/`TrustManager`, `allowedOriginPatterns="*` + `allowCredentials=true`, порядок правил `authorizeHttpRequests` (`permitAll` под ограниченным префиксом + проверка контроллера), IDOR-трассировка `@PathVariable` -> DAO-запрос к таблице с owner-колонкой без фильтра владельца/Principal.
- **Последствия:** Анализаторы не содержат хардкода эталона и проходят как `training-project/`, так и мутированные копии `tools/mutate_project.py`.
