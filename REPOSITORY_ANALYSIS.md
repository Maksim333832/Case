# Repository Analysis — `TBagirov/training`

> Выполнен до написания собственных анализаторов на основе реального клона `https://github.com/TBagirov/training`.

## 1. Фактическая структура репозитория и сверка с брифом

| Путь | Фактическое содержимое | Сверка с предварительным описанием |
| --- | --- | --- |
| `training-project/` | Kotlin 2.2.21 / Spring Boot 4.0.9 / Gradle 8.14.6 (Kotlin DSL), приложение «Repair Desk» | Совпадает; уточнено точное число исходников: **16 `.kt` файлов** + **3 файла ресурсов** (`application.yml`, `schema.sql`, `data.sql`) = 19 файлов в `src/main/` |
| `training-project/build.gradle.kts`, `gradle.properties`, `gradle.lockfile` | 6 явно объявленных сторонних зависимостей (5 уязвимых + 1 контроль), `gradle.properties` с `legacyManifestJsonVersion=20230227`, lockfile с 64 зафиксированными артефактами `runtimeClasspath` | Совпадает полностью |
| `vulnerability-database/vulnerabilities.json` + `schema.json` | JSON Schema draft 2020-12, `ecosystem: Maven`, `versionFormat: numeric-dot-separated`, **41 запись advisory** по **21 уникальному `group:artifact`** | Совпадает полностью |
| `ground-truth/training-findings.json` + `.md` | **15 эталонных находок** (5 SECRET, 5 SCA, 5 SAST) + **6 безопасных контрольных примеров (`controls`)** | Совпадает полностью |
| `docs/submission-format.md` + `docs/training-result-example.json` | Обязательный формат итогового JSON (`{"findings":[...]}` в UTF-8), строгие правила для типов `line`/`endLine`, относительных `path` и `advisoryId` | Совпадает полностью |

## 2. Карта эталонных уязвимостей (15)

### SECRET (5)
1. `A-SEC-01` (`password`, `HIGH`) — `src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt:4`: строковый литерал в поле пароля `legacyImportPassword`.
2. `A-SEC-02` (`api-key`, `MEDIUM`) — `src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt:7`: встроенный API-ключ `pricingApiKey`, передаваемый в `X-Api-Key`.
3. `A-SEC-03` (`configuration-token`, `HIGH`) — `src/main/resources/application.yml:13`: `pickup.callback.authorization: "Bearer <token>"`.
4. `A-SEC-04` (`secret-fallback`, `LOW`) — `src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt:8`: Elvis-фолбэк `System.getenv("DEPOT_STATUS_TOKEN") ?: "<literal>"`.
5. `A-SEC-05` (`recoverable-token`, `MEDIUM`) — `src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt:7-10`: токен собирается конкатенацией двух локальных строковых литералов (`series + grant`) и передаётся в `setBearerAuth(...)`.

### SCA (5)
1. `A-SCA-01` (`CRITICAL`) — `build.gradle.kts:31`: `org.apache.commons:commons-text:1.9` (`CVE-2022-42889` / `GHSA-599f-7c49-w659`), прямое строковое объявление.
2. `A-SCA-02` (`HIGH`) — `build.gradle.kts:32`: `org.jsoup:jsoup:1.14.1` (`CVE-2021-37714` / `GHSA-m72m-mhq2-9p6c`), прямое строковое объявление.
3. `A-SCA-03` (`MEDIUM`) — `build.gradle.kts:33` (и строка 21): `org.apache.commons:commons-compress:1.25.0` (`CVE-2024-25710` / `GHSA-4g9r-vxhx-9pgx`), версия через Kotlin `val archiveFormatVersion`.
4. `A-SCA-04` (`MEDIUM`) — `build.gradle.kts:36`: `commons-net:commons-net:3.8.0` (`CVE-2021-37533` / `GHSA-cgp8-4m63-fhh5`), многострочный вызов `add("implementation", "...")`.
5. `A-SCA-05` (`HIGH`) — `build.gradle.kts:38` (и `gradle.properties:1`): `org.json:json:20230227` (`CVE-2023-5072` / `GHSA-4jq9-2xhw-jpx7`), версия через `providers.gradleProperty("legacyManifestJsonVersion").get()`.

### SAST (5)
1. `A-SAST-01` (`sql-injection`, `HIGH`) — `RepairLookupController.kt:13-14`: HTTP `@RequestParam` интерполируется (`'$frameTag'`) в SQL-строку `JdbcTemplate.queryForList`.
2. `A-SAST-02` (`tls-verification`, `MEDIUM`) — `SupplierHttpsClient.kt:13`: установка `HostnameVerifier { _, _ -> true }` на `HttpsURLConnection`.
3. `A-SAST-03` (`credentialed-cors`, `MEDIUM`) — `RepairCors.kt:13-14`: `allowedOriginPatterns = listOf("*")` в сочетании с `allowCredentials = true`.
4. `A-SAST-04` (`route-authorization`, `HIGH`) — `RepairSecurity.kt:18` (+ `PickupExportController.kt:10`): явный `permitAll()` на `GET /api/pickup/export` перед правилом `requestMatchers("/api/pickup/**").hasRole("MECHANIC")`, при этом контроллер выгружает данные БД без проверки роли.
5. `A-SAST-05` (`object-authorization`, `HIGH`) — `RepairTicketReader.kt:10-11` (+ `RepairTicketController.kt:14-15`): `@PathVariable` ID передаётся в SQL-запрос таблицы с колонкой `customer_id`, но предикат `WHERE ticket_id = ?` не проверяет владельца (`Principal`).

## 3. Карта безопасных контрольных примеров (6)

1. `A-CTRL-01` (`README.md:9`) — документационный плейсхолдер `YOUR_API_KEY`.
2. `A-CTRL-02` (`application.yml:17`) — ссылка на переменную окружения `${INVENTORY_TOKEN}` без встроенного секрета.
3. `A-CTRL-03` (`build.gradle.kts:39`) — `org.apache.commons:commons-lang3:3.20.0` выше уязвимой границы `< 3.18.0` (`CVE-2025-48924` не применяется).
4. `A-CTRL-04` (`RepairLookupController.kt:17-18`) — параметризованный SQL с `?` и отдельным аргументом `ticketCode`.
5. `A-CTRL-05` (`RepairSecurity.kt:17`) — `permitAll()` на публичном каталоге `/api/catalog/services`, возвращающем статический список услуг.
6. `A-CTRL-06` (`ManualsHttpsClient.kt:7-8`) — штатный `HttpsURLConnection` без отключения проверки имени хоста и сертификатов.

## 4. Требования к обобщению на скрытую вариацию

Анализаторы не должны опираться на имена классов/переменных (`PartsImportSettings`, `legacyImportPassword`, `RepairTicketReader`), значения литералов (`cg26_*`) или конкретные номера строк. Требуется:
- структурный анализ Kotlin-кода (классы/методы/аргументы вызовов/цепочки данных), YAML/properties, Gradle DSL (`val`, `gradleProperty`, многострочные `add(...)`, `gradle.lockfile`);
- фильтрация плейсхолдеров и безопасных паттернов для исключения ложных срабатываний на контролях.
