PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at DATETIME NULL,
    owner_email TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_status_expires ON api_keys(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_email ON api_keys(owner_email);

CREATE TABLE IF NOT EXISTS usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_hash TEXT NOT NULL UNIQUE,
    exported_at DATETIME NOT NULL,
    payload_json TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_applied_keys_hash TEXT NOT NULL DEFAULT '',
    last_applied_at DATETIME NULL,
    last_usage_snapshot_hash TEXT NOT NULL DEFAULT '',
    last_usage_snapshot_at DATETIME NULL,
    last_recover_import_hash TEXT NOT NULL DEFAULT '',
    last_recover_import_at DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO sync_state(id) VALUES (1) ON CONFLICT(id) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
