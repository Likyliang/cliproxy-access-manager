# cliproxy-access-manager

Sidecar plugin for CLIProxyAPI that adds:
- per-API-key expiration management
- durable usage snapshot persistence
- restart recovery for usage statistics
- Telegram bot operations for key and usage management
- multi-user identity RBAC for HTTP and Telegram

This plugin is built as a companion extension for the upstream project:
- https://github.com/router-for-me/CLIProxyAPI

## What this sidecar does

1. Stores API key metadata in SQLite (`status`, `expires_at`, `note`, `audit`).
2. Periodically computes active keys and syncs them to CLIProxyAPI via:
   - `PUT /v0/management/api-keys`
3. Periodically fetches usage snapshot from:
   - `GET /v0/management/usage/export`
   and persists it.
4. Restores usage after restarts using:
   - `POST /v0/management/usage/import`
5. Exposes HTTP operations API and optional Telegram bot commands.

## Required CLIProxyAPI settings

- `remote-management.secret-key` must be configured.
- `usage-statistics-enabled: true` (otherwise usage export is empty/minimal).
- Sidecar must be able to reach CLIProxyAPI management endpoint.

## Environment variables

Required:
- `CLIPROXY_MGMT_BASE_URL` (example: `http://127.0.0.1:8317`, Docker example: `http://host.docker.internal:8317`)
- `CLIPROXY_MGMT_KEY`

Recommended:
- `APIM_DATA_DIR` (default `./data`)
- `APIM_DB_PATH` (default `${APIM_DATA_DIR}/apim.db`)
- `APIM_HTTP_ADDR` (default `127.0.0.1:8390`)
- `APIM_HTTP_AUTH_TOKEN` (optional bearer token for sidecar HTTP API)
- `APIM_KEY_SYNC_INTERVAL` (default `30s`)
- `APIM_USAGE_SYNC_INTERVAL` (default `2m`)
- `APIM_RECOVERY_CHECK_INTERVAL` (default `60s`)

Telegram (optional):
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ALLOWED_CHAT_IDS` (comma-separated int64)
- `TELEGRAM_ALLOWED_USER_IDS` (comma-separated int64)
- `TELEGRAM_POLL_INTERVAL` (default `3s`)

Main-project update tracking/control:
- `APIM_UPDATE_CHECK_ENABLED` (default `true`)
- `APIM_UPDATE_CHECK_TIME` (default `04:00`, UTC)
- current CLIProxyAPI version is auto-detected from management response header `X-CPA-VERSION`
- `APIM_MANAGEMENT_LATEST_VERSION_URL` (default `/v0/management/latest-version`)
- semver comparison is used (`latest > current` only)
- `APIM_UPDATE_AUTO_APPLY_ENABLED` (default `false`; when enabled, apply is triggered automatically after `update_available`)
- `APIM_UPDATE_APPLY_COMMAND` (optional custom apply command)
- `APIM_UPDATE_ALLOW_CUSTOM_COMMAND` (default `false`; must be true to allow `APIM_UPDATE_APPLY_COMMAND`)
- `APIM_AUTO_UPDATE_ENABLED` (default `true`)
- `APIM_AUTO_UPDATE_SERVICE` (default `cliproxy`)
- `APIM_AUTO_UPDATE_COMPOSE_FILE` (optional absolute compose file path)
- `APIM_AUTO_UPDATE_WORKING_DIR` (optional working directory for compose lookup)

Security hardening:
- `APIM_HTTP_UPDATE_REQUIRE_AUTH` (default `true`; blocks `/update/check` and `/update/apply` when `APIM_HTTP_AUTH_TOKEN` is empty)
- `APIM_TELEGRAM_DENY_HIGH_RISK_WHEN_ALLOWLIST_EMPTY` (default `true`; deny high-risk write/update commands if Telegram allowlist is empty)

Recovery hardening:
- `APIM_DB_RECOVER_ON_CORRUPT` (default `true`; backup corrupt DB and recreate)
- `APIM_RECOVERY_SNAPSHOT_SCAN_LIMIT` (default `10`; fallback scan depth for recovery snapshots)

## RBAC model

Identities are stored in SQLite table `auth_identities`:
- `provider`: `http` or `telegram`
- `subject`:
  - `http`: SHA-256 of token
  - `telegram`: Telegram user id string
- `role`: `admin` or `user`
- `email`: required for `user`, optional for `admin`
- `status`: currently active on upsert

Authorization:
- `healthz` is public.
- HTTP protected endpoints require either:
  - bootstrap token (`APIM_HTTP_AUTH_TOKEN`) => admin principal, or
  - mapped identity in `auth_identities`.
- Telegram requires **allowlist pass + identity mapping**.

Permission matrix:
- `admin`:
  - HTTP: all existing management endpoints + `/identities`
  - Telegram: all management commands
- `user`:
  - HTTP: only `GET /me`
  - Telegram: `/help`, `/start`, `/me` (self only)

## Telegram commands

Admin:
- `/help`
- `/key_add <key> <email> <ttl|expires_at> [note]`
- `/key_extend <key> <ttl|expires_at>`
- `/key_disable <key>` / `/key_enable <key>` / `/key_delete <key>`
- `/key_list [active|expired|all]`
- `/usage_key <key> [24h|7d|duration]`
- `/usage_top [24h|7d|duration]`
- `/me <email> [24h|7d|duration]`
- `/recharge <email> [plan_or_note]` (placeholder)
- `/sync_now`
- `/usage_sync_now`
- `/status`
- `/update_check`
- `/update_apply`

User:
- `/help`
- `/start`
- `/me [24h|7d|duration]`

TTL examples:
- `24h`
- `7d`
- `2026-03-01T00:00:00Z`
- `never`

## HTTP API

- `GET /healthz`
- `GET /status`
- `POST /sync_now`
- `POST /usage/sync_now`
- `POST /update/check`
- `POST /update/apply`
- `GET /keys?filter=all|active|expired`
- `POST /keys` (supports `owner_email`)
- `DELETE /keys?key=<api-key>`
- `PATCH /keys/status`
- `PATCH /keys/expiry`
- `GET /usage/top?since=24h|7d|<duration>`
- `GET /usage/key?key=<api-key>&since=24h|7d|<duration>`
- `GET /account/query?email=<email>&since=24h|7d|<duration>` (admin)
- `GET /me?since=24h|7d|<duration>` (user self, also available to admin if email is bound)
- `GET /identities?provider=http|telegram` (admin)
- `POST /identities` (admin)
- `DELETE /identities?provider=...&subject=...` (admin)
- `POST /recharge/request` (placeholder)

When authenticating to HTTP API, pass token via:
- `Authorization: Bearer <token>`
or
- `X-APIM-Token: <token>`

Notes:
- `APIM_HTTP_AUTH_TOKEN` acts as a bootstrap admin token for compatibility.
- Additional principals are managed via `/identities`.
- For `provider=http`, `/identities` accepts plaintext token in `subject` and stores SHA-256 only.

When `APIM_HTTP_UPDATE_REQUIRE_AUTH=true` and `APIM_HTTP_AUTH_TOKEN` is empty:
- `/update/check` and `/update/apply` are rejected (403)
- this enforces explicit auth configuration before exposing update actions

### RBAC smoke test (HTTP)

Example (real smoke run):

```bash
# 1) bootstrap admin token can access admin endpoint
curl -i -H "Authorization: Bearer bootstrap-smoke-token" http://127.0.0.1:18439/status
# -> 200

# 2) unauthenticated request is rejected
curl -i http://127.0.0.1:18439/status
# -> 401

# 3) create admin/user HTTP identities
curl -i -H "Authorization: Bearer bootstrap-smoke-token" -H "Content-Type: application/json" \
  -d '{"provider":"http","subject":"admin-http-token","role":"admin","email":"admin@example.com"}' \
  http://127.0.0.1:18439/identities
# -> 200

curl -i -H "Authorization: Bearer bootstrap-smoke-token" -H "Content-Type: application/json" \
  -d '{"provider":"http","subject":"user-http-token","role":"user","email":"user@example.com"}' \
  http://127.0.0.1:18439/identities
# -> 200

# 4) user token cannot access admin-only endpoint
curl -i -H "Authorization: Bearer user-http-token" http://127.0.0.1:18439/keys
# -> 403

# 5) user token can query self summary
curl -i -H "Authorization: Bearer user-http-token" "http://127.0.0.1:18439/me?since=24h"
# -> 200

# 6) user token cannot manage identities
curl -i -H "Authorization: Bearer user-http-token" "http://127.0.0.1:18439/identities?provider=http"
# -> 403

# 7) unknown token is rejected
curl -i -H "Authorization: Bearer no-such-token" http://127.0.0.1:18439/status
# -> 401
```

## Build (local Go)

```bash
go mod tidy
go build ./cmd/manager
```

If host does not have Go installed, use Docker build in `deploy/`.

For proxy networks (as you provided):
- HTTP proxy: `http://127.0.0.1:20171`
- SOCKS5 proxy: `socks5://127.0.0.1:20170`

When building inside Docker, use host-reachable proxy endpoints (for many Linux Docker setups):
- `HTTP_PROXY=http://172.17.0.1:20171`
- `HTTPS_PROXY=http://172.17.0.1:20171`

## Docker

### Option A: production deploy (recommended, pull image)

```bash
cd deploy
cp .env.production.example .env
mkdir -p data

# optional proxy for runtime
# export HTTP_PROXY=http://127.0.0.1:20171
# export HTTPS_PROXY=http://127.0.0.1:20171
# export ALL_PROXY=socks5://127.0.0.1:20170

docker compose -f docker-compose.deploy.yml up -d
```

Notes:
- Uses image from `APIM_IMAGE` (default: `moocher4097/cliproxy-access-manager:latest`).
- Telegram is optional. Configure in `.env`:
  - `TELEGRAM_BOT_TOKEN`
  - `TELEGRAM_ALLOWED_CHAT_IDS`
  - `TELEGRAM_ALLOWED_USER_IDS`
- Daily main-project update check runs at `APIM_UPDATE_CHECK_TIME` in UTC (default `04:00`).
- If `APIM_UPDATE_APPLY_COMMAND` is empty, `/update_apply` will auto-run:
  - `docker compose -f <compose-file> pull <service>`
  - `docker compose -f <compose-file> up -d <service>`
  with defaults `service=cliproxy`, and compose file auto-detected from common paths.

### Option B: build locally with Compose

```bash
cd deploy
cp .env.production.example .env
mkdir -p data

# choose one proxy mode when needed for build:
# HTTP proxy mode
export HTTP_PROXY=http://127.0.0.1:20171
export HTTPS_PROXY=http://127.0.0.1:20171

# OR SOCKS5 proxy mode
# export ALL_PROXY=socks5://127.0.0.1:20170

# optional go module proxy inside builder
export GOLANG_PROXY=https://proxy.golang.org,direct

docker compose -f docker-compose.apim.yml up -d --build
```

Use `deploy/.env.production.example` as the recommended production template.

## systemd

Use `deploy/cliproxy-access-manager.service` and put secrets in:
- `/etc/default/cliproxy-access-manager`

## Notes

- SQLite WAL mode is enabled for better durability.
- Sync and recovery operations are idempotent via persisted hashes.
- If Go toolchain is not installed on host, build via Dockerfile in `deploy/`.
