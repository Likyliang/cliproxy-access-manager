# cliproxy-access-manager

Sidecar plugin for CLIProxyAPI that adds:
- per-API-key expiration management
- durable usage snapshot persistence
- restart recovery for usage statistics
- Telegram bot operations for key and usage management

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

## Telegram commands

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
- `/status`

TTL examples:
- `24h`
- `7d`
- `2026-03-01T00:00:00Z`
- `never`

## HTTP API

- `GET /healthz`
- `GET /status`
- `POST /sync_now`
- `GET /keys?filter=all|active|expired`
- `POST /keys` (supports `owner_email`)
- `DELETE /keys?key=<api-key>`
- `PATCH /keys/status`
- `PATCH /keys/expiry`
- `GET /usage/top?since=24h|7d|<duration>`
- `GET /usage/key?key=<api-key>&since=24h|7d|<duration>`
- `GET /account/query?email=<email>&since=24h|7d|<duration>`
- `POST /recharge/request` (placeholder)

When `APIM_HTTP_AUTH_TOKEN` is set, pass token via:
- `Authorization: Bearer <token>`
or
- `X-APIM-Token: <token>`

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

The compose file expects this repository as project root:

```bash
cd deploy
cp .env.production.example .env
mkdir -p data

# choose one proxy mode when needed:
# HTTP proxy mode
export HTTP_PROXY=http://127.0.0.1:20171
export HTTPS_PROXY=http://127.0.0.1:20171

# OR SOCKS5 proxy mode
# export ALL_PROXY=socks5://127.0.0.1:20170

# optional go module proxy inside builder
export GOLANG_PROXY=https://proxy.golang.org,direct

docker compose -f docker-compose.apim.yml up -d --build
```

Use `deploy/docker-compose.apim.yml` with `deploy/.env.production.example` as the recommended production template.

## systemd

Use `deploy/cliproxy-access-manager.service` and put secrets in:
- `/etc/default/cliproxy-access-manager`

## Notes

- SQLite WAL mode is enabled for better durability.
- Sync and recovery operations are idempotent via persisted hashes.
- If Go toolchain is not installed on host, build via Dockerfile in `deploy/`.
