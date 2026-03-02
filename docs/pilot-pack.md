# RouterGo Pilot Pack

## Quickstart

1. Подготовьте переменные окружения для API ключей:
   - `ROUTERGO_ADMIN_TOKEN`
   - `ROUTERGO_READ_TOKEN`
2. Проверьте `config/config.yaml`:
   - `security.enabled: true`
   - `security.require_auth: true`
   - `security.tls.enabled: true` для production.
3. Запустите сервис:
   - `go run cmd/router/main.go --config config/config.yaml`
4. Откройте Dashboard:
   - `/dashboard`
   - вставьте API key в поле `API key`.
5. Для первичной настройки используйте вкладку `Setup Wizard`.

## Runbook

- **Ротация ключей**:
  - `POST /api/security/keys/{id}/rotate`
  - раздайте новый ключ операторам, старый пометьте revoked.
- **Отзыв ключа**:
  - `POST /api/security/keys/{id}/revoke`
- **Backup/restore конфигурации**:
  - `GET /api/config/backup`
  - `POST /api/config/restore`
- **Проверка роли и scope**:
  - `GET /api/auth/me`

## Troubleshooting

- **401 unauthorized**
  - Проверьте `X-API-Key`, статус ключа (`disabled`) и роль.
- **403 forbidden**
  - Недостаточная роль/scope для операции.
- **Ошибка TLS/mTLS**
  - Проверьте `cert_file`, `key_file`, `client_ca_file`.
  - При `require_client_cert=true` `client_ca_file` обязателен.
- **Ошибка восстановления backup**
  - Проверьте целостность `checksum` и валидность JSON backup bundle.

## Pilot KPI

- Успешность применения конфигурации (`config_apply_failed_total`) < 1% за 7 дней.
- Среднее время восстановления из backup < 60 сек.
- 0 несанкционированных операций (401/403 анализируются в audit logs).
- 95% операций NOC выполняются через role `ops` без `admin`.
