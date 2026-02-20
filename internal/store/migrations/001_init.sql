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
    last_update_check_at DATETIME NULL,
    last_known_latest TEXT NOT NULL DEFAULT '',
    last_known_current TEXT NOT NULL DEFAULT '',
    last_update_status TEXT NOT NULL DEFAULT '',
    last_update_message TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS purchase_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT '',
    plan_id TEXT NOT NULL DEFAULT '',
    plan_snapshot_json TEXT NOT NULL DEFAULT '',
    provisioned_api_key TEXT NOT NULL DEFAULT '',
    provisioning_status TEXT NOT NULL DEFAULT 'pending',
    activation_attempted_at DATETIME NULL,
    months INTEGER NOT NULL DEFAULT 1,
    note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    review_note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    reviewed_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at DATETIME NULL
);

CREATE INDEX IF NOT EXISTS idx_purchase_requests_status_created_at ON purchase_requests(status, created_at);
CREATE INDEX IF NOT EXISTS idx_purchase_requests_requester_email_created_at ON purchase_requests(requester_email, created_at);
