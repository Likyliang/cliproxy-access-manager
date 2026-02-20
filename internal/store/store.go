package store

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

const (
	passwordHashAlgo       = "pbkdf2_sha256"
	passwordHashIterations = 210000
	passwordHashSaltBytes  = 16
	passwordHashKeyBytes   = 32
	sessionTokenBytes      = 32
	minPurchaseMonths      = int64(1)
	maxPurchaseMonths      = int64(36)
)

func Open(databasePath string) (*Store, error) {
	return open(databasePath)
}

func OpenWithRecovery(databasePath string, recoverOnCorrupt bool) (*Store, error) {
	s, err := open(databasePath)
	if err == nil {
		return s, nil
	}
	if !recoverOnCorrupt || !isLikelyCorruptSQLiteError(err) {
		return nil, err
	}
	backupPath, backupErr := backupCorruptDatabase(databasePath)
	if backupErr != nil {
		return nil, fmt.Errorf("backup corrupt database before recovery: %w", backupErr)
	}
	_ = os.Remove(databasePath)
	recovered, reopenErr := open(databasePath)
	if reopenErr != nil {
		return nil, fmt.Errorf("rebuild sqlite after corrupt backup(%s): %w", backupPath, reopenErr)
	}
	log.Printf("[WARN] sqlite corruption detected, backed up to %s and recreated database", backupPath)
	return recovered, nil
}

func open(databasePath string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(2 * time.Minute)

	s := &Store{db: db}
	if err := s.healthCheck(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	queries := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			api_key TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'active',
			expires_at DATETIME NULL,
			owner_email TEXT NOT NULL DEFAULT '',
			note TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			plan_id TEXT NOT NULL DEFAULT '',
			plan_snapshot_json TEXT NOT NULL DEFAULT '',
			purchase_request_id INTEGER NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_status_expires ON api_keys(status, expires_at);`,
		`ALTER TABLE api_keys ADD COLUMN owner_email TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE api_keys ADD COLUMN plan_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE api_keys ADD COLUMN plan_snapshot_json TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE api_keys ADD COLUMN purchase_request_id INTEGER NULL;`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_owner_email ON api_keys(owner_email);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_purchase_request_id ON api_keys(purchase_request_id);`,
		`CREATE TABLE IF NOT EXISTS usage_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			snapshot_hash TEXT NOT NULL UNIQUE,
			exported_at DATETIME NOT NULL,
			payload_json TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS sync_state (
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
		);`,
		`ALTER TABLE sync_state ADD COLUMN last_update_check_at DATETIME NULL;`,
		`ALTER TABLE sync_state ADD COLUMN last_known_latest TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sync_state ADD COLUMN last_known_current TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sync_state ADD COLUMN last_update_status TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sync_state ADD COLUMN last_update_message TEXT NOT NULL DEFAULT '';`,
		`INSERT INTO sync_state(id) VALUES (1) ON CONFLICT(id) DO NOTHING;`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			detail TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS auth_identities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			provider TEXT NOT NULL,
			subject TEXT NOT NULL,
			role TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			note TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(provider, subject)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_identities_provider_role_status ON auth_identities(provider, role, status);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_identities_email ON auth_identities(email);`,
		`CREATE TABLE IF NOT EXISTS auth_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			role TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_by TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login_at DATETIME NULL
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_users_role_status ON auth_users(role, status);`,
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_hash TEXT NOT NULL UNIQUE,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at DATETIME NULL,
			client_ip TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			FOREIGN KEY(user_id) REFERENCES auth_users(id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_revoked ON auth_sessions(expires_at, revoked_at);`,
		`CREATE TABLE IF NOT EXISTS purchase_requests (
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
		);`,
		`ALTER TABLE purchase_requests ADD COLUMN plan_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE purchase_requests ADD COLUMN plan_snapshot_json TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE purchase_requests ADD COLUMN provisioned_api_key TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE purchase_requests ADD COLUMN provisioning_status TEXT NOT NULL DEFAULT 'pending';`,
		`ALTER TABLE purchase_requests ADD COLUMN activation_attempted_at DATETIME NULL;`,
		`ALTER TABLE purchase_requests ADD COLUMN months INTEGER NOT NULL DEFAULT 1;`,
		`CREATE INDEX IF NOT EXISTS idx_purchase_requests_status_created_at ON purchase_requests(status, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_purchase_requests_requester_email_created_at ON purchase_requests(requester_email, created_at);`,
		`CREATE TABLE IF NOT EXISTS plan_catalog (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			persona TEXT NOT NULL,
			billing_cycle TEXT NOT NULL,
			monthly_price_suggestion TEXT NOT NULL,
			included_tokens_total INTEGER NOT NULL,
			included_requests_total INTEGER NULL,
			overage_price_suggestion TEXT NOT NULL,
			usage_control_action TEXT NOT NULL DEFAULT 'disable_key',
			recommended INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			display_order INTEGER NOT NULL DEFAULT 0,
			description TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_plan_catalog_enabled_order ON plan_catalog(enabled, display_order);`,
		`INSERT OR IGNORE INTO plan_catalog(
			id, name, persona, billing_cycle, monthly_price_suggestion,
			included_tokens_total, included_requests_total,
			overage_price_suggestion, usage_control_action,
			recommended, enabled, display_order, description
		) VALUES
			('` + PlanIDWebChatMonthly + `', '网页对话套餐', 'web_chat', 'monthly', '¥49/月（建议价）', 3000000, 20000, '超额按建议价另议', 'disable_key', 1, 1, 10, '适合网页对话和轻量调用'),
			('` + PlanIDHybridMonthly + `', '通用混合套餐', 'hybrid', 'monthly', '¥199/月（建议价）', 20000000, 120000, '超额按建议价另议', 'disable_key', 1, 1, 20, '适合多场景混合访问'),
			('` + PlanIDHeavyAgentMonthly + `', '重度 Agent 套餐', 'heavy_agent', 'monthly', '¥699/月（建议价）', 120000000, 600000, '超额按建议价另议', 'disable_key', 0, 1, 30, '适合重度自动化 agent 任务');`,
		`CREATE TABLE IF NOT EXISTS usage_controls (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scope_type TEXT NOT NULL,
			scope_value TEXT NOT NULL DEFAULT '',
			window_seconds INTEGER NOT NULL,
			max_requests INTEGER NULL,
			max_tokens INTEGER NULL,
			action TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			note TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			updated_by TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_controls_scope_enabled ON usage_controls(scope_type, scope_value, enabled);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_controls_enabled ON usage_controls(enabled);`,
		`CREATE TABLE IF NOT EXISTS usage_control_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			control_id INTEGER NOT NULL,
			scope_type TEXT NOT NULL,
			scope_value TEXT NOT NULL DEFAULT '',
			window_seconds INTEGER NOT NULL,
			used_requests INTEGER NOT NULL DEFAULT 0,
			used_tokens INTEGER NOT NULL DEFAULT 0,
			threshold_requests INTEGER NULL,
			threshold_tokens INTEGER NULL,
			action TEXT NOT NULL,
			triggered INTEGER NOT NULL DEFAULT 0,
			result TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_control_events_control_created ON usage_control_events(control_id, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_control_events_created ON usage_control_events(created_at);`,
	}
	for _, query := range queries {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			lowerErr := strings.ToLower(err.Error())
			lowerQuery := strings.ToLower(query)
			if strings.Contains(lowerErr, "duplicate column name") && strings.Contains(lowerQuery, "alter table") {
				continue
			}
			return fmt.Errorf("migrate query failed: %w", err)
		}
	}
	return nil
}

func (s *Store) UpsertAPIKey(ctx context.Context, key string, expiresAt *time.Time, ownerEmail, note, createdBy string) error {
	return s.upsertAPIKeyWithOptions(ctx, key, expiresAt, ownerEmail, note, createdBy, KeyStatusActive, "", "", nil)
}

func (s *Store) upsertAPIKeyWithOptions(ctx context.Context, key string, expiresAt *time.Time, ownerEmail, note, createdBy, status, planID, planSnapshotJSON string, purchaseRequestID *int64) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("key is required")
	}
	ownerEmail = normalizeEmail(ownerEmail)
	if !isLikelyEmail(ownerEmail) {
		return errors.New("valid owner email is required")
	}
	note = strings.TrimSpace(note)
	createdBy = strings.TrimSpace(createdBy)
	if createdBy == "" {
		createdBy = "system"
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != KeyStatusActive && status != KeyStatusDisabled {
		return errors.New("invalid key status")
	}
	planID = strings.TrimSpace(planID)
	planSnapshotJSON = strings.TrimSpace(planSnapshotJSON)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys(api_key, status, expires_at, owner_email, note, created_by, plan_id, plan_snapshot_json, purchase_request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(api_key) DO UPDATE SET
			status = excluded.status,
			expires_at = excluded.expires_at,
			owner_email = excluded.owner_email,
			note = excluded.note,
			plan_id = excluded.plan_id,
			plan_snapshot_json = excluded.plan_snapshot_json,
			purchase_request_id = excluded.purchase_request_id,
			updated_at = CURRENT_TIMESTAMP
	`, key, status, toNullTime(expiresAt), ownerEmail, note, createdBy, planID, planSnapshotJSON, toNullInt64(purchaseRequestID))
	if err != nil {
		return fmt.Errorf("upsert api key: %w", err)
	}
	return nil
}

func (s *Store) SetAPIKeyStatus(ctx context.Context, key, status string) (bool, error) {
	key = strings.TrimSpace(key)
	status = strings.TrimSpace(status)
	if key == "" {
		return false, errors.New("key is required")
	}
	if status != KeyStatusActive && status != KeyStatusDisabled {
		return false, errors.New("invalid status")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE api_key = ?`, status, key)
	if err != nil {
		return false, fmt.Errorf("set api key status: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ExtendAPIKey(ctx context.Context, key string, expiresAt *time.Time) (bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return false, errors.New("key is required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE api_key = ?`, toNullTime(expiresAt), key)
	if err != nil {
		return false, fmt.Errorf("extend api key: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, key string) (bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return false, errors.New("key is required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE api_key = ?`, key)
	if err != nil {
		return false, fmt.Errorf("delete api key: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, api_key, status, expires_at, owner_email, note, created_by, plan_id, plan_snapshot_json, purchase_request_id, created_at, updated_at
		FROM api_keys
		ORDER BY created_at DESC, id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	result := make([]APIKey, 0)
	for rows.Next() {
		var item APIKey
		var expires sql.NullTime
		var purchaseRequestID sql.NullInt64
		if err := rows.Scan(
			&item.ID,
			&item.Key,
			&item.Status,
			&expires,
			&item.OwnerEmail,
			&item.Note,
			&item.CreatedBy,
			&item.PlanID,
			&item.PlanSnapshotJSON,
			&purchaseRequestID,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		if expires.Valid {
			t := expires.Time.UTC()
			item.ExpiresAt = &t
		}
		if purchaseRequestID.Valid {
			item.PurchaseRequestID = &purchaseRequestID.Int64
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api keys: %w", err)
	}
	return result, nil
}

func (s *Store) ListActiveKeys(ctx context.Context, now time.Time) ([]string, error) {
	now = now.UTC()
	rows, err := s.db.QueryContext(ctx, `
		SELECT api_key FROM api_keys
		WHERE status = ? AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY api_key ASC
	`, KeyStatusActive, now)
	if err != nil {
		return nil, fmt.Errorf("list active keys: %w", err)
	}
	defer rows.Close()

	keys := make([]string, 0)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan active key: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active keys: %w", err)
	}
	return keys, nil
}

func KeysHash(keys []string) string {
	normalized := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	sort.Strings(normalized)
	joined := strings.Join(normalized, "\n")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

func SnapshotHash(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func UsageHashFromExportPayload(payload []byte) (string, error) {
	usage, err := extractUsageJSON(payload)
	if err != nil {
		return "", err
	}
	normalizedUsage, err := normalizeJSON(usage)
	if err != nil {
		return "", err
	}
	return SnapshotHash(normalizedUsage), nil
}

func UsageHasDataFromExportPayload(payload []byte) (bool, error) {
	usage, err := extractUsageJSON(payload)
	if err != nil {
		return false, err
	}
	var usageObj struct {
		APIs map[string]json.RawMessage `json:"apis"`
	}
	if err := json.Unmarshal(usage, &usageObj); err != nil {
		return false, err
	}
	return len(usageObj.APIs) > 0, nil
}

func extractUsageJSON(payload []byte) (json.RawMessage, error) {
	var wrapped struct {
		Usage json.RawMessage `json:"usage"`
	}
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return nil, err
	}
	if len(wrapped.Usage) == 0 {
		return nil, errors.New("missing usage payload")
	}
	return wrapped.Usage, nil
}

func (s *Store) SaveUsageSnapshot(ctx context.Context, payload []byte, exportedAt time.Time) (bool, string, error) {
	if exportedAt.IsZero() {
		exportedAt = time.Now().UTC()
	}
	normalized, err := normalizeJSON(payload)
	if err != nil {
		return false, "", fmt.Errorf("normalize snapshot payload: %w", err)
	}
	usageHash, err := UsageHashFromExportPayload(payload)
	if err != nil {
		return false, "", fmt.Errorf("hash usage snapshot payload: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO usage_snapshots(snapshot_hash, exported_at, payload_json)
		VALUES (?, ?, ?)
		ON CONFLICT(snapshot_hash) DO NOTHING
	`, usageHash, exportedAt.UTC(), normalized)
	if err != nil {
		return false, "", fmt.Errorf("insert usage snapshot: %w", err)
	}
	rows, _ := res.RowsAffected()
	inserted := rows > 0

	state, err := s.GetSyncState(ctx)
	if err != nil {
		return false, "", err
	}
	if state.LastUsageSnapshotHash != usageHash {
		now := time.Now().UTC()
		if err := s.UpdateSyncStateUsageSnapshot(ctx, usageHash, &exportedAt, &now); err != nil {
			return false, "", err
		}
	}
	return inserted, usageHash, nil
}

func (s *Store) GetLatestUsageSnapshot(ctx context.Context) (*UsageSnapshot, error) {
	items, err := s.ListRecentUsageSnapshots(ctx, 1)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	item := items[0]
	return &item, nil
}

func (s *Store) ListRecentUsageSnapshots(ctx context.Context, limit int) ([]UsageSnapshot, error) {
	if limit <= 0 {
		limit = 1
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, snapshot_hash, exported_at, payload_json, created_at
		FROM usage_snapshots
		ORDER BY exported_at DESC, id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent usage snapshots: %w", err)
	}
	defer rows.Close()

	items := make([]UsageSnapshot, 0, limit)
	for rows.Next() {
		var item UsageSnapshot
		if err := rows.Scan(&item.ID, &item.SnapshotHash, &item.ExportedAt, &item.PayloadJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan usage snapshot: %w", err)
		}
		item.ExportedAt = item.ExportedAt.UTC()
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate usage snapshots: %w", err)
	}
	return items, nil
}

func (s *Store) GetSyncState(ctx context.Context) (SyncState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, last_applied_keys_hash, last_applied_at,
		       last_usage_snapshot_hash, last_usage_snapshot_at,
		       last_recover_import_hash, last_recover_import_at,
		       last_update_check_at, last_known_latest, last_known_current,
		       last_update_status, last_update_message, updated_at
		FROM sync_state WHERE id = 1
	`)
	var item SyncState
	var lastApplied, lastSnapshot, lastRecover, lastUpdateCheck sql.NullTime
	if err := row.Scan(
		&item.ID,
		&item.LastAppliedKeysHash,
		&lastApplied,
		&item.LastUsageSnapshotHash,
		&lastSnapshot,
		&item.LastRecoverImportHash,
		&lastRecover,
		&lastUpdateCheck,
		&item.LastKnownLatest,
		&item.LastKnownCurrent,
		&item.LastUpdateStatus,
		&item.LastUpdateMessage,
		&item.UpdatedAt,
	); err != nil {
		return SyncState{}, fmt.Errorf("get sync state: %w", err)
	}
	if lastApplied.Valid {
		t := lastApplied.Time.UTC()
		item.LastAppliedAt = &t
	}
	if lastSnapshot.Valid {
		t := lastSnapshot.Time.UTC()
		item.LastUsageSnapshotAt = &t
	}
	if lastRecover.Valid {
		t := lastRecover.Time.UTC()
		item.LastRecoverImportAt = &t
	}
	if lastUpdateCheck.Valid {
		t := lastUpdateCheck.Time.UTC()
		item.LastUpdateCheckAt = &t
	}
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item, nil
}

func (s *Store) UpdateSyncStateKeys(ctx context.Context, hash string, appliedAt *time.Time, updatedAt *time.Time) error {
	if updatedAt == nil {
		now := time.Now().UTC()
		updatedAt = &now
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_state
		SET last_applied_keys_hash = ?,
		    last_applied_at = ?,
		    updated_at = ?
		WHERE id = 1
	`, strings.TrimSpace(hash), toNullTime(appliedAt), updatedAt.UTC())
	if err != nil {
		return fmt.Errorf("update sync state keys: %w", err)
	}
	return nil
}

func (s *Store) UpdateSyncStateUsageSnapshot(ctx context.Context, hash string, snapshotAt *time.Time, updatedAt *time.Time) error {
	if updatedAt == nil {
		now := time.Now().UTC()
		updatedAt = &now
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_state
		SET last_usage_snapshot_hash = ?,
		    last_usage_snapshot_at = ?,
		    updated_at = ?
		WHERE id = 1
	`, strings.TrimSpace(hash), toNullTime(snapshotAt), updatedAt.UTC())
	if err != nil {
		return fmt.Errorf("update sync state usage snapshot: %w", err)
	}
	return nil
}

func (s *Store) UpdateSyncStateRecovery(ctx context.Context, hash string, importedAt *time.Time, updatedAt *time.Time) error {
	if updatedAt == nil {
		now := time.Now().UTC()
		updatedAt = &now
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_state
		SET last_recover_import_hash = ?,
		    last_recover_import_at = ?,
		    updated_at = ?
		WHERE id = 1
	`, strings.TrimSpace(hash), toNullTime(importedAt), updatedAt.UTC())
	if err != nil {
		return fmt.Errorf("update sync state recovery: %w", err)
	}
	return nil
}

func (s *Store) TouchSyncStateRecoveryHash(ctx context.Context, hash string, updatedAt *time.Time) error {
	if updatedAt == nil {
		now := time.Now().UTC()
		updatedAt = &now
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_state
		SET last_recover_import_hash = ?,
		    updated_at = ?
		WHERE id = 1
	`, strings.TrimSpace(hash), updatedAt.UTC())
	if err != nil {
		return fmt.Errorf("touch sync state recovery hash: %w", err)
	}
	return nil
}

func (s *Store) UpdateSyncStateUpdateCheck(ctx context.Context, checkedAt *time.Time, current, latest, status, message string, updatedAt *time.Time) error {
	if updatedAt == nil {
		now := time.Now().UTC()
		updatedAt = &now
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_state
		SET last_update_check_at = ?,
		    last_known_current = ?,
		    last_known_latest = ?,
		    last_update_status = ?,
		    last_update_message = ?,
		    updated_at = ?
		WHERE id = 1
	`, toNullTime(checkedAt), strings.TrimSpace(current), strings.TrimSpace(latest), strings.TrimSpace(status), strings.TrimSpace(message), updatedAt.UTC())
	if err != nil {
		return fmt.Errorf("update sync state update check: %w", err)
	}
	return nil
}

func (s *Store) InsertAuditLog(ctx context.Context, actor, action, detail string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs(actor, action, detail)
		VALUES (?, ?, ?)
	`, strings.TrimSpace(actor), strings.TrimSpace(action), strings.TrimSpace(detail))
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

func (s *Store) UpsertIdentity(ctx context.Context, provider, subject, role, email, note, createdBy string) error {
	provider, err := normalizeIdentityProvider(provider)
	if err != nil {
		return err
	}
	subject, err = normalizeIdentitySubject(provider, subject)
	if err != nil {
		return err
	}
	role, err = normalizeIdentityRole(role)
	if err != nil {
		return err
	}
	email = normalizeEmail(email)
	if role == IdentityRoleUser {
		if !isLikelyEmail(email) {
			return errors.New("valid email is required for user role")
		}
	} else if email != "" && !isLikelyEmail(email) {
		return errors.New("invalid email")
	}
	note = strings.TrimSpace(note)
	createdBy = strings.TrimSpace(createdBy)

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO auth_identities(provider, subject, role, email, status, note, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, subject) DO UPDATE SET
			role = excluded.role,
			email = excluded.email,
			status = excluded.status,
			note = excluded.note,
			updated_at = CURRENT_TIMESTAMP
	`, provider, subject, role, email, IdentityStatusActive, note, createdBy)
	if err != nil {
		return fmt.Errorf("upsert identity: %w", err)
	}
	return nil
}

func (s *Store) DeleteIdentity(ctx context.Context, provider, subject string) (bool, error) {
	provider, err := normalizeIdentityProvider(provider)
	if err != nil {
		return false, err
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return false, errors.New("subject is required")
	}
	var res sql.Result
	if provider == IdentityProviderHTTP {
		hashSubject := hashHTTPToken(subject)
		res, err = s.db.ExecContext(ctx, `
			DELETE FROM auth_identities
			WHERE provider = ? AND (subject = ? OR subject = ?)
		`, provider, hashSubject, strings.ToLower(subject))
	} else {
		normalizedSubject, normalizeErr := normalizeIdentitySubject(provider, subject)
		if normalizeErr != nil {
			return false, normalizeErr
		}
		res, err = s.db.ExecContext(ctx, `DELETE FROM auth_identities WHERE provider = ? AND subject = ?`, provider, normalizedSubject)
	}
	if err != nil {
		return false, fmt.Errorf("delete identity: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ListIdentities(ctx context.Context, providerFilter string) ([]Identity, error) {
	providerFilter = strings.TrimSpace(providerFilter)
	if providerFilter != "" {
		provider, err := normalizeIdentityProvider(providerFilter)
		if err != nil {
			return nil, err
		}
		providerFilter = provider
	}

	query := `
		SELECT id, provider, subject, role, email, status, note, created_by, created_at, updated_at
		FROM auth_identities
	`
	args := make([]any, 0, 1)
	if providerFilter != "" {
		query += ` WHERE provider = ?`
		args = append(args, providerFilter)
	}
	query += ` ORDER BY created_at DESC, id DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	defer rows.Close()

	result := make([]Identity, 0)
	for rows.Next() {
		var item Identity
		if err := rows.Scan(
			&item.ID,
			&item.Provider,
			&item.Subject,
			&item.Role,
			&item.Email,
			&item.Status,
			&item.Note,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan identity: %w", err)
		}
		item.Provider = strings.ToLower(strings.TrimSpace(item.Provider))
		item.Subject = strings.TrimSpace(item.Subject)
		item.Role = strings.ToLower(strings.TrimSpace(item.Role))
		item.Email = normalizeEmail(item.Email)
		item.Status = strings.ToLower(strings.TrimSpace(item.Status))
		item.Note = strings.TrimSpace(item.Note)
		item.CreatedBy = strings.TrimSpace(item.CreatedBy)
		item.CreatedAt = item.CreatedAt.UTC()
		item.UpdatedAt = item.UpdatedAt.UTC()
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identities: %w", err)
	}
	return result, nil
}

func (s *Store) ResolveHTTPPrincipal(ctx context.Context, rawToken string) (*Principal, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, nil
	}
	subject := hashHTTPToken(rawToken)
	return s.resolvePrincipal(ctx, IdentityProviderHTTP, subject)
}

func (s *Store) CreateUser(ctx context.Context, email, role, password, createdBy string) (*AuthUser, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return nil, errors.New("valid email is required")
	}
	role, err := normalizeIdentityRole(role)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	createdBy = strings.TrimSpace(createdBy)

	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_users(email, role, password_hash, status, created_by)
		VALUES (?, ?, ?, ?, ?)
	`, email, role, hash, UserStatusActive, createdBy)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, errors.New("email already exists")
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("create user id: %w", err)
	}
	return s.GetUserByID(ctx, id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*AuthUser, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return nil, errors.New("invalid email")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, email, role, password_hash, status, created_by, created_at, updated_at, last_login_at
		FROM auth_users
		WHERE email = ?
		LIMIT 1
	`, email)
	return scanAuthUser(row)
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (*AuthUser, error) {
	if id <= 0 {
		return nil, errors.New("id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, email, role, password_hash, status, created_by, created_at, updated_at, last_login_at
		FROM auth_users
		WHERE id = ?
		LIMIT 1
	`, id)
	return scanAuthUser(row)
}

func (s *Store) VerifyUserPassword(ctx context.Context, email, password string) (*AuthUser, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return nil, errors.New("invalid email")
	}
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	if user.Status != UserStatusActive {
		return nil, nil
	}
	ok, err := verifyPassword(user.PasswordHash, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		UPDATE auth_users
		SET last_login_at = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, now, user.ID); err != nil {
		return nil, fmt.Errorf("update user last login: %w", err)
	}
	user.LastLoginAt = &now
	return user, nil
}

func (s *Store) EnsureAdminUser(ctx context.Context, email, password, createdBy string) (*AuthUser, error) {
	email = normalizeEmail(email)
	password = strings.TrimSpace(password)
	if email == "" || password == "" {
		return nil, nil
	}
	existing, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.Role != IdentityRoleAdmin {
			return nil, errors.New("existing admin bootstrap email is not admin role")
		}
		if existing.Status != UserStatusActive {
			if _, err := s.db.ExecContext(ctx, `UPDATE auth_users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, UserStatusActive, existing.ID); err != nil {
				return nil, fmt.Errorf("enable existing admin user: %w", err)
			}
			existing.Status = UserStatusActive
		}
		return existing, nil
	}
	return s.CreateUser(ctx, email, IdentityRoleAdmin, password, createdBy)
}

func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration, clientIP, userAgent string) (string, *AuthSession, error) {
	if userID <= 0 {
		return "", nil, errors.New("user_id is required")
	}
	if ttl <= 0 {
		return "", nil, errors.New("ttl must be > 0")
	}
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	if user == nil || user.Status != UserStatusActive {
		return "", nil, errors.New("user is not active")
	}
	plain, hash, err := newSessionToken()
	if err != nil {
		return "", nil, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	clientIP = strings.TrimSpace(clientIP)
	userAgent = strings.TrimSpace(userAgent)

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_sessions(session_hash, user_id, expires_at, client_ip, user_agent)
		VALUES (?, ?, ?, ?, ?)
	`, hash, userID, expiresAt, clientIP, userAgent)
	if err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}
	sessionID, err := res.LastInsertId()
	if err != nil {
		return "", nil, fmt.Errorf("session id: %w", err)
	}
	return plain, &AuthSession{
		ID:          sessionID,
		SessionHash: hash,
		UserID:      userID,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
	}, nil
}

func (s *Store) ResolveSessionPrincipal(ctx context.Context, rawToken string) (*Principal, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, nil
	}
	hash := hashSessionToken(rawToken)
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.role, u.status, sess.id, sess.expires_at, sess.revoked_at
		FROM auth_sessions AS sess
		JOIN auth_users AS u ON u.id = sess.user_id
		WHERE sess.session_hash = ?
		LIMIT 1
	`, hash)
	var userID int64
	var email string
	var role string
	var status string
	var sessionID int64
	var expiresAt time.Time
	var revokedAt sql.NullTime
	if err := row.Scan(&userID, &email, &role, &status, &sessionID, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("resolve session principal: %w", err)
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != UserStatusActive {
		return nil, nil
	}
	now := time.Now().UTC()
	if revokedAt.Valid || !expiresAt.UTC().After(now) {
		return nil, nil
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?
	`, now, sessionID); err != nil {
		return nil, fmt.Errorf("touch session last seen: %w", err)
	}
	role = strings.ToLower(strings.TrimSpace(role))
	email = normalizeEmail(email)
	if role == IdentityRoleUser && !isLikelyEmail(email) {
		return nil, errors.New("invalid user email")
	}
	return &Principal{
		Provider: IdentityProviderSession,
		Subject:  strconv.FormatInt(userID, 10),
		Role:     role,
		Email:    email,
		UserID:   userID,
	}, nil
}

func (s *Store) RevokeSession(ctx context.Context, rawToken string) error {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil
	}
	hash := hashSessionToken(rawToken)
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		UPDATE auth_sessions
		SET revoked_at = ?, last_seen_at = ?
		WHERE session_hash = ? AND revoked_at IS NULL
	`, now, now, hash); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *Store) ResolveTelegramPrincipal(ctx context.Context, userID int64) (*Principal, error) {
	if userID <= 0 {
		return nil, nil
	}
	subject := strconv.FormatInt(userID, 10)
	return s.resolvePrincipal(ctx, IdentityProviderTelegram, subject)
}

func (s *Store) resolvePrincipal(ctx context.Context, provider, subject string) (*Principal, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT role, email
		FROM auth_identities
		WHERE provider = ? AND subject = ? AND status = ?
		LIMIT 1
	`, provider, subject, IdentityStatusActive)
	var role string
	var email string
	if err := row.Scan(&role, &email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("resolve principal: %w", err)
	}

	role = strings.ToLower(strings.TrimSpace(role))
	email = normalizeEmail(email)
	switch role {
	case IdentityRoleUser:
		if !isLikelyEmail(email) {
			return nil, errors.New("identity user role requires valid email")
		}
	case IdentityRoleAdmin:
		if email != "" && !isLikelyEmail(email) {
			return nil, errors.New("identity admin email is invalid")
		}
	default:
		return nil, fmt.Errorf("invalid identity role %q", role)
	}

	return &Principal{
		Provider: provider,
		Subject:  subject,
		Role:     role,
		Email:    email,
	}, nil
}

func normalizeIdentityProvider(raw string) (string, error) {
	provider := strings.ToLower(strings.TrimSpace(raw))
	switch provider {
	case IdentityProviderHTTP, IdentityProviderTelegram:
		return provider, nil
	default:
		return "", errors.New("invalid provider")
	}
}

func normalizeIdentityRole(raw string) (string, error) {
	role := strings.ToLower(strings.TrimSpace(raw))
	switch role {
	case IdentityRoleAdmin, IdentityRoleUser:
		return role, nil
	default:
		return "", errors.New("invalid role")
	}
}

func normalizeIdentitySubject(provider, raw string) (string, error) {
	subject := strings.TrimSpace(raw)
	if subject == "" {
		return "", errors.New("subject is required")
	}
	switch provider {
	case IdentityProviderHTTP:
		return hashHTTPToken(subject), nil
	case IdentityProviderTelegram:
		id, err := strconv.ParseInt(subject, 10, 64)
		if err != nil || id <= 0 {
			return "", errors.New("invalid telegram subject")
		}
		return strconv.FormatInt(id, 10), nil
	default:
		return "", errors.New("invalid provider")
	}
}

func hashHTTPToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func hashSessionToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func generateAPIKeyValue() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	return "apim_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func newSessionToken() (string, string, error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(buf)
	return plain, hashSessionToken(plain), nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, passwordHashSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, passwordHashIterations, passwordHashKeyBytes)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	saltEnc := base64.RawStdEncoding.EncodeToString(salt)
	hashEnc := base64.RawStdEncoding.EncodeToString(derived)
	return fmt.Sprintf("%s$%d$%s$%s", passwordHashAlgo, passwordHashIterations, saltEnc, hashEnc), nil
}

func verifyPassword(storedHash, password string) (bool, error) {
	algorithm, iterations, salt, expected, err := parsePasswordHash(storedHash)
	if err != nil {
		return false, err
	}
	if algorithm != passwordHashAlgo {
		return false, errors.New("unsupported password hash algorithm")
	}
	if iterations <= 0 {
		return false, errors.New("invalid password hash iterations")
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	if err != nil {
		return false, fmt.Errorf("derive password hash: %w", err)
	}
	if subtle.ConstantTimeCompare(derived, expected) == 1 {
		return true, nil
	}
	return false, nil
}

func parsePasswordHash(raw string) (string, int, []byte, []byte, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, "$")
	if len(parts) != 4 {
		return "", 0, nil, nil, errors.New("invalid password hash format")
	}
	algorithm := strings.TrimSpace(parts[0])
	iterations, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || iterations <= 0 {
		return "", 0, nil, nil, errors.New("invalid password hash iterations")
	}
	salt, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(parts[2]))
	if err != nil || len(salt) == 0 {
		return "", 0, nil, nil, errors.New("invalid password hash salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(parts[3]))
	if err != nil || len(expected) == 0 {
		return "", 0, nil, nil, errors.New("invalid password hash digest")
	}
	return algorithm, iterations, salt, expected, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuthUser(row rowScanner) (*AuthUser, error) {
	var item AuthUser
	var lastLogin sql.NullTime
	if err := row.Scan(
		&item.ID,
		&item.Email,
		&item.Role,
		&item.PasswordHash,
		&item.Status,
		&item.CreatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&lastLogin,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan auth user: %w", err)
	}
	item.Email = normalizeEmail(item.Email)
	if !isLikelyEmail(item.Email) {
		return nil, errors.New("invalid auth user email")
	}
	role, err := normalizeIdentityRole(item.Role)
	if err != nil {
		return nil, err
	}
	item.Role = role
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	if item.Status != UserStatusActive && item.Status != UserStatusDisabled {
		return nil, errors.New("invalid auth user status")
	}
	item.CreatedBy = strings.TrimSpace(item.CreatedBy)
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	if lastLogin.Valid {
		t := lastLogin.Time.UTC()
		item.LastLoginAt = &t
	}
	return &item, nil
}

func scanPlanCatalogItem(row rowScanner) (*PlanCatalogItem, error) {
	var item PlanCatalogItem
	var includedRequests sql.NullInt64
	var recommended int64
	var enabled int64
	if err := row.Scan(
		&item.ID,
		&item.Name,
		&item.Persona,
		&item.BillingCycle,
		&item.MonthlyPriceSuggestion,
		&item.IncludedTokensTotal,
		&includedRequests,
		&item.OveragePriceSuggestion,
		&item.UsageControlAction,
		&recommended,
		&enabled,
		&item.DisplayOrder,
		&item.Description,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan plan catalog item: %w", err)
	}
	item.ID = strings.TrimSpace(item.ID)
	item.Name = strings.TrimSpace(item.Name)
	item.Persona = strings.ToLower(strings.TrimSpace(item.Persona))
	item.BillingCycle = strings.ToLower(strings.TrimSpace(item.BillingCycle))
	item.MonthlyPriceSuggestion = strings.TrimSpace(item.MonthlyPriceSuggestion)
	item.OveragePriceSuggestion = strings.TrimSpace(item.OveragePriceSuggestion)
	item.UsageControlAction = strings.ToLower(strings.TrimSpace(item.UsageControlAction))
	item.Description = strings.TrimSpace(item.Description)
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	item.IncludedRequestsTotal = toInt64Ptr(includedRequests)
	item.Recommended = recommended != 0
	item.Enabled = enabled != 0
	if item.ID == "" {
		return nil, errors.New("invalid plan id")
	}
	if item.Name == "" {
		return nil, errors.New("invalid plan name")
	}
	persona, err := normalizePlanPersona(item.Persona)
	if err != nil {
		return nil, err
	}
	item.Persona = persona
	billingCycle, err := normalizePlanBillingCycle(item.BillingCycle)
	if err != nil {
		return nil, err
	}
	item.BillingCycle = billingCycle
	if item.MonthlyPriceSuggestion == "" || item.OveragePriceSuggestion == "" {
		return nil, errors.New("invalid plan suggestion fields")
	}
	if item.IncludedTokensTotal <= 0 {
		return nil, errors.New("invalid included_tokens_total")
	}
	if item.IncludedRequestsTotal != nil && *item.IncludedRequestsTotal <= 0 {
		return nil, errors.New("invalid included_requests_total")
	}
	action, err := normalizeUsageControlAction(item.UsageControlAction)
	if err != nil {
		return nil, err
	}
	item.UsageControlAction = action
	return &item, nil
}

func scanPurchaseRequest(row rowScanner) (*PurchaseRequest, error) {
	var item PurchaseRequest
	var reviewedAt sql.NullTime
	var activationAttemptedAt sql.NullTime
	if err := row.Scan(
		&item.ID,
		&item.RequesterEmail,
		&item.Plan,
		&item.PlanID,
		&item.PlanSnapshotJSON,
		&item.ProvisionedAPIKey,
		&item.ProvisioningStatus,
		&activationAttemptedAt,
		&item.Months,
		&item.Note,
		&item.Status,
		&item.ReviewNote,
		&item.CreatedBy,
		&item.ReviewedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&reviewedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan purchase request: %w", err)
	}
	item.RequesterEmail = normalizeEmail(item.RequesterEmail)
	item.Plan = strings.TrimSpace(item.Plan)
	item.PlanID = strings.TrimSpace(item.PlanID)
	if item.PlanID == "" {
		item.PlanID = item.Plan
	}
	item.PlanSnapshotJSON = strings.TrimSpace(item.PlanSnapshotJSON)
	item.ProvisionedAPIKey = strings.TrimSpace(item.ProvisionedAPIKey)
	months, err := normalizePurchaseMonths(item.Months)
	if err != nil {
		return nil, err
	}
	item.Months = months
	item.ProvisioningStatus = strings.ToLower(strings.TrimSpace(item.ProvisioningStatus))
	if item.ProvisioningStatus == "" {
		item.ProvisioningStatus = PurchaseRequestProvisioningPending
	}
	provisioningStatus, err := normalizePurchaseRequestProvisioningStatus(item.ProvisioningStatus)
	if err != nil {
		return nil, err
	}
	item.ProvisioningStatus = provisioningStatus
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	if reviewedAt.Valid {
		t := reviewedAt.Time.UTC()
		item.ReviewedAt = &t
	}
	if activationAttemptedAt.Valid {
		t := activationAttemptedAt.Time.UTC()
		item.ActivationAttemptedAt = &t
	}
	return &item, nil
}

func (s *Store) UsageTopSince(ctx context.Context, since time.Time, limit int) ([]APIUsageSummary, error) {
	since = since.UTC()
	snapshot, err := s.GetLatestUsageSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	var payload struct {
		Usage struct {
			APIs map[string]struct {
				TotalRequests int64 `json:"total_requests"`
				TotalTokens   int64 `json:"total_tokens"`
				Models        map[string]struct {
					Details []struct {
						Timestamp time.Time `json:"timestamp"`
						Failed    bool      `json:"failed"`
						Tokens    struct {
							TotalTokens int64 `json:"total_tokens"`
						} `json:"tokens"`
					} `json:"details"`
				} `json:"models"`
			} `json:"apis"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(snapshot.PayloadJSON), &payload); err != nil {
		return nil, fmt.Errorf("decode usage snapshot: %w", err)
	}

	result := make([]APIUsageSummary, 0, len(payload.Usage.APIs))
	for key, api := range payload.Usage.APIs {
		var totalReq int64
		var failedReq int64
		var totalTokens int64
		for _, model := range api.Models {
			for _, detail := range model.Details {
				if detail.Timestamp.IsZero() {
					continue
				}
				if detail.Timestamp.UTC().Before(since.UTC()) {
					continue
				}
				totalReq++
				if detail.Failed {
					failedReq++
				}
				totalTokens += detail.Tokens.TotalTokens
			}
		}
		if totalReq == 0 {
			continue
		}
		result = append(result, APIUsageSummary{
			APIKey:         key,
			TotalRequests:  totalReq,
			FailedRequests: failedReq,
			TotalTokens:    totalTokens,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TotalRequests == result[j].TotalRequests {
			return result[i].TotalTokens > result[j].TotalTokens
		}
		return result[i].TotalRequests > result[j].TotalRequests
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) UsageForKeySince(ctx context.Context, key string, since time.Time) (*APIUsageSummary, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errors.New("key is required")
	}
	summaries, err := s.UsageTopSince(ctx, since, 0)
	if err != nil {
		return nil, err
	}
	for _, summary := range summaries {
		if summary.APIKey == key {
			item := summary
			return &item, nil
		}
	}
	return &APIUsageSummary{APIKey: key}, nil
}

func (s *Store) AccountSummarySince(ctx context.Context, email string, since time.Time, now time.Time) (*AccountSummary, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return nil, errors.New("invalid email")
	}
	now = now.UTC()
	rows, err := s.db.QueryContext(ctx, `
		SELECT api_key, status, expires_at
		FROM api_keys
		WHERE owner_email = ?
		ORDER BY api_key ASC
	`, email)
	if err != nil {
		return nil, fmt.Errorf("query account keys: %w", err)
	}
	defer rows.Close()

	allKeys := make([]string, 0)
	activeKeys := make([]string, 0)
	seenAll := make(map[string]struct{})
	seenActive := make(map[string]struct{})
	var nearestExpiry *time.Time
	unlimited := false
	for rows.Next() {
		var key string
		var status string
		var expires sql.NullTime
		if err := rows.Scan(&key, &status, &expires); err != nil {
			return nil, fmt.Errorf("scan account key: %w", err)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := seenAll[key]; !ok {
			seenAll[key] = struct{}{}
			allKeys = append(allKeys, key)
		}
		if strings.TrimSpace(status) != KeyStatusActive {
			continue
		}
		if !expires.Valid {
			unlimited = true
			if _, ok := seenActive[key]; !ok {
				seenActive[key] = struct{}{}
				activeKeys = append(activeKeys, key)
			}
			continue
		}
		exp := expires.Time.UTC()
		if !exp.After(now) {
			continue
		}
		if _, ok := seenActive[key]; !ok {
			seenActive[key] = struct{}{}
			activeKeys = append(activeKeys, key)
		}
		if nearestExpiry == nil || exp.Before(*nearestExpiry) {
			t := exp
			nearestExpiry = &t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account keys: %w", err)
	}

	summaries, err := s.UsageTopSince(ctx, since, 0)
	if err != nil {
		return nil, err
	}
	usageByKey := make(map[string]APIUsageSummary, len(summaries))
	for _, summary := range summaries {
		usageByKey[summary.APIKey] = summary
	}

	result := &AccountSummary{
		Email:     email,
		Keys:      activeKeys,
		Unlimited: unlimited,
	}
	if nearestExpiry != nil {
		t := nearestExpiry.UTC()
		result.ValidUntil = &t
		remaining := t.Sub(now)
		if remaining <= 0 {
			result.ValidDays = 0
		} else {
			result.ValidDays = int64((remaining + (24*time.Hour - time.Nanosecond)) / (24 * time.Hour))
		}
	}
	if unlimited {
		result.ValidDays = -1
	}
	for _, key := range allKeys {
		item, ok := usageByKey[key]
		if !ok {
			continue
		}
		result.TotalRequests += item.TotalRequests
		result.FailedRequests += item.FailedRequests
		result.TotalTokens += item.TotalTokens
	}
	return result, nil
}

func (s *Store) ListAPIKeysByOwner(ctx context.Context, email string) ([]APIKey, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return nil, errors.New("invalid email")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, api_key, status, expires_at, owner_email, note, created_by, plan_id, plan_snapshot_json, purchase_request_id, created_at, updated_at
		FROM api_keys
		WHERE owner_email = ?
		ORDER BY created_at DESC, id DESC
	`, email)
	if err != nil {
		return nil, fmt.Errorf("list api keys by owner: %w", err)
	}
	defer rows.Close()

	items := make([]APIKey, 0)
	for rows.Next() {
		var item APIKey
		var expires sql.NullTime
		var purchaseRequestID sql.NullInt64
		if err := rows.Scan(
			&item.ID,
			&item.Key,
			&item.Status,
			&expires,
			&item.OwnerEmail,
			&item.Note,
			&item.CreatedBy,
			&item.PlanID,
			&item.PlanSnapshotJSON,
			&purchaseRequestID,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api key by owner: %w", err)
		}
		if expires.Valid {
			t := expires.Time.UTC()
			item.ExpiresAt = &t
		}
		if purchaseRequestID.Valid {
			item.PurchaseRequestID = &purchaseRequestID.Int64
		}
		item.OwnerEmail = normalizeEmail(item.OwnerEmail)
		item.PlanID = strings.TrimSpace(item.PlanID)
		item.PlanSnapshotJSON = strings.TrimSpace(item.PlanSnapshotJSON)
		item.CreatedAt = item.CreatedAt.UTC()
		item.UpdatedAt = item.UpdatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api keys by owner: %w", err)
	}
	return items, nil
}

func (s *Store) ListPlanCatalog(ctx context.Context, enabledOnly bool) ([]PlanCatalogItem, error) {
	query := `
		SELECT id, name, persona, billing_cycle, monthly_price_suggestion,
		       included_tokens_total, included_requests_total,
		       overage_price_suggestion, usage_control_action,
		       recommended, enabled, display_order, description,
		       created_at, updated_at
		FROM plan_catalog
	`
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY display_order ASC, id ASC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list plan catalog: %w", err)
	}
	defer rows.Close()

	items := make([]PlanCatalogItem, 0)
	for rows.Next() {
		item, scanErr := scanPlanCatalogItem(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate plan catalog: %w", err)
	}
	return items, nil
}

func (s *Store) GetPlanCatalogByID(ctx context.Context, id string) (*PlanCatalogItem, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("plan id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, persona, billing_cycle, monthly_price_suggestion,
		       included_tokens_total, included_requests_total,
		       overage_price_suggestion, usage_control_action,
		       recommended, enabled, display_order, description,
		       created_at, updated_at
		FROM plan_catalog
		WHERE id = ?
		LIMIT 1
	`, id)
	return scanPlanCatalogItem(row)
}

func (s *Store) CreatePurchaseRequest(ctx context.Context, requesterEmail, planID string, months int64, note, createdBy string) (*PurchaseRequest, error) {
	requesterEmail = normalizeEmail(requesterEmail)
	if !isLikelyEmail(requesterEmail) {
		return nil, errors.New("valid requester email is required")
	}
	planID = strings.TrimSpace(planID)
	if planID == "" {
		return nil, errors.New("plan_id is required")
	}
	normalizedMonths, err := normalizePurchaseMonths(months)
	if err != nil {
		return nil, err
	}
	note = strings.TrimSpace(note)
	createdBy = strings.TrimSpace(createdBy)
	if createdBy == "" {
		createdBy = "system"
	}
	return s.createPurchaseRequestWithProvisioning(ctx, requesterEmail, planID, normalizedMonths, note, createdBy)
}

func (s *Store) createPurchaseRequestWithProvisioning(ctx context.Context, requesterEmail, planID string, months int64, note, createdBy string) (*PurchaseRequest, error) {
	requesterEmail = normalizeEmail(requesterEmail)
	if !isLikelyEmail(requesterEmail) {
		return nil, errors.New("valid requester email is required")
	}
	planID = strings.TrimSpace(planID)
	if planID == "" {
		return nil, errors.New("plan_id is required")
	}
	normalizedMonths, err := normalizePurchaseMonths(months)
	if err != nil {
		return nil, err
	}
	months = normalizedMonths
	note = strings.TrimSpace(note)
	createdBy = strings.TrimSpace(createdBy)
	if createdBy == "" {
		createdBy = "system"
	}
	plan, err := s.GetPlanCatalogByID(ctx, planID)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, errors.New("plan not found")
	}
	if !plan.Enabled {
		return nil, errors.New("plan is disabled")
	}
	planSnapshotBytes, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal plan snapshot: %w", err)
	}
	planSnapshotJSON := string(planSnapshotBytes)

	generatedKey, err := generateAPIKeyValue()
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin purchase request create tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_keys(api_key, status, expires_at, owner_email, note, created_by, plan_id, plan_snapshot_json, purchase_request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
	`, generatedKey, KeyStatusDisabled, toNullTime(nil), requesterEmail, note, createdBy, plan.ID, planSnapshotJSON); err != nil {
		return nil, fmt.Errorf("create provisioned api key: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO purchase_requests(
			requester_email,
			plan,
			plan_id,
			plan_snapshot_json,
			provisioned_api_key,
			provisioning_status,
			months,
			note,
			status,
			created_by
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, requesterEmail, plan.ID, plan.ID, planSnapshotJSON, generatedKey, PurchaseRequestProvisioningReady, months, note, PurchaseRequestStatusPending, createdBy)
	if err != nil {
		return nil, fmt.Errorf("create purchase request: %w", err)
	}
	requestID, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get purchase request id: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE api_keys
		SET purchase_request_id = ?, updated_at = CURRENT_TIMESTAMP
		WHERE api_key = ?
	`, requestID, generatedKey); err != nil {
		return nil, fmt.Errorf("bind api key to purchase request: %w", err)
	}

	windowSeconds := int64(30 * 24 * 3600)
	var maxRequests *int64
	if plan.IncludedRequestsTotal != nil {
		maxRequests = cloneInt64Ptr(plan.IncludedRequestsTotal)
	}
	maxTokens := int64Ptr(plan.IncludedTokensTotal)
	scopeType, scopeValue, normalizedWindow, normalizedMaxRequests, normalizedMaxTokens, action, err := normalizeUsageControlInput(
		UsageControlScopeKey,
		generatedKey,
		windowSeconds,
		maxRequests,
		maxTokens,
		plan.UsageControlAction,
	)
	if err != nil {
		if _, markErr := tx.ExecContext(ctx, `
			UPDATE purchase_requests
			SET provisioning_status = ?,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, PurchaseRequestProvisioningFailed, requestID); markErr != nil {
			return nil, fmt.Errorf("normalize usage control: %w (mark failed: %v)", err, markErr)
		}
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO usage_controls(scope_type, scope_value, window_seconds, max_requests, max_tokens, action, enabled, note, created_by, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scopeType, scopeValue, normalizedWindow, toNullInt64(normalizedMaxRequests), toNullInt64(normalizedMaxTokens), action, 1, fmt.Sprintf("auto from purchase_request_id=%d plan_id=%s", requestID, plan.ID), createdBy, createdBy); err != nil {
		if _, markErr := tx.ExecContext(ctx, `
			UPDATE purchase_requests
			SET provisioning_status = ?,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, PurchaseRequestProvisioningFailed, requestID); markErr != nil {
			return nil, fmt.Errorf("create usage control: %w (mark failed: %v)", err, markErr)
		}
		return nil, fmt.Errorf("create usage control: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit purchase request create: %w", err)
	}
	committed = true
	return s.GetPurchaseRequestByID(ctx, requestID)
}

func (s *Store) GetPurchaseRequestByID(ctx context.Context, id int64) (*PurchaseRequest, error) {
	if id <= 0 {
		return nil, errors.New("id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, requester_email, plan, plan_id, plan_snapshot_json,
		       provisioned_api_key, provisioning_status, activation_attempted_at,
		       months, note, status, review_note, created_by, reviewed_by,
		       created_at, updated_at, reviewed_at
		FROM purchase_requests
		WHERE id = ?
		LIMIT 1
	`, id)
	item, err := scanPurchaseRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return item, nil
}

func (s *Store) ListPurchaseRequests(ctx context.Context, requesterEmail, status string, limit int) ([]PurchaseRequest, error) {
	requesterEmail = normalizeEmail(requesterEmail)
	if requesterEmail != "" && !isLikelyEmail(requesterEmail) {
		return nil, errors.New("invalid requester email")
	}
	status = strings.TrimSpace(status)
	if status != "" {
		normalizedStatus, err := normalizePurchaseRequestStatus(status)
		if err != nil {
			return nil, err
		}
		status = normalizedStatus
	}

	query := `
		SELECT id, requester_email, plan, plan_id, plan_snapshot_json,
		       provisioned_api_key, provisioning_status, activation_attempted_at,
		       months, note, status, review_note, created_by, reviewed_by,
		       created_at, updated_at, reviewed_at
		FROM purchase_requests
	`
	args := make([]any, 0, 3)
	clauses := make([]string, 0, 2)
	if requesterEmail != "" {
		clauses = append(clauses, "requester_email = ?")
		args = append(args, requesterEmail)
	}
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list purchase requests: %w", err)
	}
	defer rows.Close()

	items := make([]PurchaseRequest, 0)
	for rows.Next() {
		item, scanErr := scanPurchaseRequest(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate purchase requests: %w", err)
	}
	return items, nil
}

func (s *Store) UpdatePurchaseRequestStatus(ctx context.Context, id int64, status, reviewNote, reviewedBy string) (*PurchaseRequest, error) {
	if id <= 0 {
		return nil, errors.New("id is required")
	}
	status, err := normalizePurchaseRequestStatus(status)
	if err != nil {
		return nil, err
	}
	reviewNote = strings.TrimSpace(reviewNote)
	reviewedBy = strings.TrimSpace(reviewedBy)
	if reviewedBy == "" {
		reviewedBy = "system"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin purchase request status update tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	row := tx.QueryRowContext(ctx, `
		SELECT id, requester_email, plan, plan_id, plan_snapshot_json,
		       provisioned_api_key, provisioning_status, activation_attempted_at,
		       months, note, status, review_note, created_by, reviewed_by,
		       created_at, updated_at, reviewed_at
		FROM purchase_requests
		WHERE id = ?
		LIMIT 1
	`, id)
	current, err := scanPurchaseRequest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load purchase request for update: %w", err)
	}
	if current == nil {
		return nil, nil
	}
	if !isValidPurchaseRequestTransition(current.Status, status) {
		return nil, errors.New("invalid purchase request status transition")
	}

	reviewedAt := sql.NullTime{}
	reviewedAtValue := time.Time{}
	if status != PurchaseRequestStatusPending {
		now := time.Now().UTC()
		reviewedAt = sql.NullTime{Time: now, Valid: true}
		reviewedAtValue = now
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE purchase_requests
		SET status = ?,
		    review_note = ?,
		    reviewed_by = ?,
		    reviewed_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, reviewNote, reviewedBy, reviewedAt, id); err != nil {
		return nil, fmt.Errorf("update purchase request status: %w", err)
	}

	if status == PurchaseRequestStatusApproved {
		key := strings.TrimSpace(current.ProvisionedAPIKey)
		if key == "" {
			if _, err := tx.ExecContext(ctx, `
				UPDATE purchase_requests
				SET provisioning_status = ?,
				    activation_attempted_at = ?,
				    updated_at = CURRENT_TIMESTAMP
				WHERE id = ?
			`, PurchaseRequestProvisioningFailed, time.Now().UTC(), id); err != nil {
				return nil, fmt.Errorf("mark purchase request activation failed: %w", err)
			}
			return nil, errors.New("purchase request has no provisioned api key")
		}
		expiresAt := reviewedAtValue.AddDate(0, int(current.Months), 0)
		res, err := tx.ExecContext(ctx, `
			UPDATE api_keys
			SET status = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP
			WHERE api_key = ?
		`, KeyStatusActive, expiresAt, key)
		if err != nil {
			return nil, fmt.Errorf("activate provisioned api key: %w", err)
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			if _, err := tx.ExecContext(ctx, `
				UPDATE purchase_requests
				SET provisioning_status = ?,
				    activation_attempted_at = ?,
				    updated_at = CURRENT_TIMESTAMP
				WHERE id = ?
			`, PurchaseRequestProvisioningFailed, time.Now().UTC(), id); err != nil {
				return nil, fmt.Errorf("mark purchase request activation missing key: %w", err)
			}
			return nil, errors.New("provisioned api key not found")
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE purchase_requests
			SET provisioning_status = ?,
			    activation_attempted_at = ?,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, PurchaseRequestProvisioningReady, time.Now().UTC(), id); err != nil {
			return nil, fmt.Errorf("update purchase activation metadata: %w", err)
		}
	} else if status == PurchaseRequestStatusRejected || status == PurchaseRequestStatusCancelled {
		if key := strings.TrimSpace(current.ProvisionedAPIKey); key != "" {
			if _, err := tx.ExecContext(ctx, `
				UPDATE api_keys
				SET status = ?, updated_at = CURRENT_TIMESTAMP
				WHERE api_key = ?
			`, KeyStatusDisabled, key); err != nil {
				return nil, fmt.Errorf("disable provisioned api key: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit purchase request status update: %w", err)
	}
	committed = true
	return s.GetPurchaseRequestByID(ctx, id)
}

func (s *Store) ListUsers(ctx context.Context, role, status, q string, limit int) ([]AuthUser, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "" {
		normalizedRole, err := normalizeIdentityRole(role)
		if err != nil {
			return nil, err
		}
		role = normalizedRole
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "" && status != UserStatusActive && status != UserStatusDisabled {
		return nil, errors.New("invalid user status")
	}
	q = strings.ToLower(strings.TrimSpace(q))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	query := `
		SELECT id, email, role, status, created_by, created_at, updated_at, last_login_at
		FROM auth_users
	`
	clauses := make([]string, 0, 3)
	args := make([]any, 0, 4)
	if role != "" {
		clauses = append(clauses, "role = ?")
		args = append(args, role)
	}
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if q != "" {
		clauses = append(clauses, "(lower(email) LIKE ? OR lower(created_by) LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	items := make([]AuthUser, 0)
	for rows.Next() {
		var item AuthUser
		var lastLogin sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&item.Email,
			&item.Role,
			&item.Status,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
			&lastLogin,
		); err != nil {
			return nil, fmt.Errorf("scan user list item: %w", err)
		}
		item.Email = normalizeEmail(item.Email)
		normalizedRole, err := normalizeIdentityRole(item.Role)
		if err != nil {
			return nil, err
		}
		item.Role = normalizedRole
		item.Status = strings.ToLower(strings.TrimSpace(item.Status))
		if item.Status != UserStatusActive && item.Status != UserStatusDisabled {
			return nil, errors.New("invalid auth user status")
		}
		item.PasswordHash = ""
		item.CreatedBy = strings.TrimSpace(item.CreatedBy)
		item.CreatedAt = item.CreatedAt.UTC()
		item.UpdatedAt = item.UpdatedAt.UTC()
		if lastLogin.Valid {
			t := lastLogin.Time.UTC()
			item.LastLoginAt = &t
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users list: %w", err)
	}
	return items, nil
}

func (s *Store) CreateUsageControl(ctx context.Context, scopeType, scopeValue string, windowSeconds int64, maxRequests, maxTokens *int64, action string, enabled bool, note, actor string) (*UsageControl, error) {
	scopeType, scopeValue, windowSeconds, maxRequests, maxTokens, action, err := normalizeUsageControlInput(scopeType, scopeValue, windowSeconds, maxRequests, maxTokens, action)
	if err != nil {
		return nil, err
	}
	note = strings.TrimSpace(note)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO usage_controls(scope_type, scope_value, window_seconds, max_requests, max_tokens, action, enabled, note, created_by, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scopeType, scopeValue, windowSeconds, toNullInt64(maxRequests), toNullInt64(maxTokens), action, boolToInt(enabled), note, actor, actor)
	if err != nil {
		return nil, fmt.Errorf("create usage control: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get usage control id: %w", err)
	}
	return s.GetUsageControlByID(ctx, id)
}

func (s *Store) UpdateUsageControl(ctx context.Context, id int64, scopeType, scopeValue string, windowSeconds int64, maxRequests, maxTokens *int64, action string, enabled bool, note, actor string) (*UsageControl, error) {
	if id <= 0 {
		return nil, errors.New("id is required")
	}
	scopeType, scopeValue, windowSeconds, maxRequests, maxTokens, action, err := normalizeUsageControlInput(scopeType, scopeValue, windowSeconds, maxRequests, maxTokens, action)
	if err != nil {
		return nil, err
	}
	note = strings.TrimSpace(note)
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE usage_controls
		SET scope_type = ?,
		    scope_value = ?,
		    window_seconds = ?,
		    max_requests = ?,
		    max_tokens = ?,
		    action = ?,
		    enabled = ?,
		    note = ?,
		    updated_by = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, scopeType, scopeValue, windowSeconds, toNullInt64(maxRequests), toNullInt64(maxTokens), action, boolToInt(enabled), note, actor, id)
	if err != nil {
		return nil, fmt.Errorf("update usage control: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return nil, nil
	}
	return s.GetUsageControlByID(ctx, id)
}

func (s *Store) GetUsageControlByID(ctx context.Context, id int64) (*UsageControl, error) {
	if id <= 0 {
		return nil, errors.New("id is required")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, scope_type, scope_value, window_seconds, max_requests, max_tokens, action, enabled, note, created_by, updated_by, created_at, updated_at
		FROM usage_controls
		WHERE id = ?
		LIMIT 1
	`, id)
	var item UsageControl
	var maxRequests, maxTokens sql.NullInt64
	var enabled int64
	if err := row.Scan(
		&item.ID,
		&item.ScopeType,
		&item.ScopeValue,
		&item.WindowSeconds,
		&maxRequests,
		&maxTokens,
		&item.Action,
		&enabled,
		&item.Note,
		&item.CreatedBy,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get usage control by id: %w", err)
	}
	item.ScopeType = strings.ToLower(strings.TrimSpace(item.ScopeType))
	item.ScopeValue = strings.TrimSpace(item.ScopeValue)
	item.Action = strings.ToLower(strings.TrimSpace(item.Action))
	item.Enabled = enabled != 0
	item.MaxRequests = toInt64Ptr(maxRequests)
	item.MaxTokens = toInt64Ptr(maxTokens)
	item.Note = strings.TrimSpace(item.Note)
	item.CreatedBy = strings.TrimSpace(item.CreatedBy)
	item.UpdatedBy = strings.TrimSpace(item.UpdatedBy)
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return &item, nil
}

func (s *Store) ListUsageControls(ctx context.Context, enabledOnly bool) ([]UsageControl, error) {
	query := `
		SELECT id, scope_type, scope_value, window_seconds, max_requests, max_tokens, action, enabled, note, created_by, updated_by, created_at, updated_at
		FROM usage_controls
	`
	args := make([]any, 0, 1)
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY created_at DESC, id DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list usage controls: %w", err)
	}
	defer rows.Close()

	items := make([]UsageControl, 0)
	for rows.Next() {
		var item UsageControl
		var maxRequests, maxTokens sql.NullInt64
		var enabled int64
		if err := rows.Scan(
			&item.ID,
			&item.ScopeType,
			&item.ScopeValue,
			&item.WindowSeconds,
			&maxRequests,
			&maxTokens,
			&item.Action,
			&enabled,
			&item.Note,
			&item.CreatedBy,
			&item.UpdatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan usage control: %w", err)
		}
		item.ScopeType = strings.ToLower(strings.TrimSpace(item.ScopeType))
		item.ScopeValue = strings.TrimSpace(item.ScopeValue)
		item.Action = strings.ToLower(strings.TrimSpace(item.Action))
		item.Enabled = enabled != 0
		item.MaxRequests = toInt64Ptr(maxRequests)
		item.MaxTokens = toInt64Ptr(maxTokens)
		item.Note = strings.TrimSpace(item.Note)
		item.CreatedBy = strings.TrimSpace(item.CreatedBy)
		item.UpdatedBy = strings.TrimSpace(item.UpdatedBy)
		item.CreatedAt = item.CreatedAt.UTC()
		item.UpdatedAt = item.UpdatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate usage controls: %w", err)
	}
	return items, nil
}

func (s *Store) UsageUsersSince(ctx context.Context, since time.Time, limit int) ([]UserUsageSummary, error) {
	since = since.UTC()
	keySummaries, err := s.UsageTopSince(ctx, since, 0)
	if err != nil {
		return nil, err
	}
	if len(keySummaries) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(keySummaries))
	for _, summary := range keySummaries {
		keys = append(keys, summary.APIKey)
	}
	owners, err := s.ownerEmailForKeys(ctx, keys)
	if err != nil {
		return nil, err
	}

	byUser := make(map[string]*UserUsageSummary)
	for _, summary := range keySummaries {
		email := normalizeEmail(owners[summary.APIKey])
		if email == "" {
			email = "[unassigned]"
		}
		item, ok := byUser[email]
		if !ok {
			item = &UserUsageSummary{Email: email, Keys: make([]string, 0, 4)}
			byUser[email] = item
		}
		item.TotalRequests += summary.TotalRequests
		item.FailedRequests += summary.FailedRequests
		item.TotalTokens += summary.TotalTokens
		item.Keys = append(item.Keys, summary.APIKey)
	}

	result := make([]UserUsageSummary, 0, len(byUser))
	for _, item := range byUser {
		sort.Strings(item.Keys)
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TotalRequests == result[j].TotalRequests {
			if result[i].TotalTokens == result[j].TotalTokens {
				return result[i].Email < result[j].Email
			}
			return result[i].TotalTokens > result[j].TotalTokens
		}
		return result[i].TotalRequests > result[j].TotalRequests
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) UsageForUserSince(ctx context.Context, email string, since time.Time) (*UserUsageSummary, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return nil, errors.New("invalid email")
	}
	since = since.UTC()
	keySummaries, err := s.UsageTopSince(ctx, since, 0)
	if err != nil {
		return nil, err
	}
	if len(keySummaries) == 0 {
		return &UserUsageSummary{Email: email, Keys: nil}, nil
	}
	keys := make([]string, 0, len(keySummaries))
	for _, summary := range keySummaries {
		keys = append(keys, summary.APIKey)
	}
	owners, err := s.ownerEmailForKeys(ctx, keys)
	if err != nil {
		return nil, err
	}

	out := &UserUsageSummary{Email: email, Keys: make([]string, 0, 4)}
	seen := make(map[string]struct{})
	for _, summary := range keySummaries {
		if normalizeEmail(owners[summary.APIKey]) != email {
			continue
		}
		out.TotalRequests += summary.TotalRequests
		out.FailedRequests += summary.FailedRequests
		out.TotalTokens += summary.TotalTokens
		if _, ok := seen[summary.APIKey]; ok {
			continue
		}
		seen[summary.APIKey] = struct{}{}
		out.Keys = append(out.Keys, summary.APIKey)
	}
	sort.Strings(out.Keys)
	return out, nil
}

type usageWindowStats struct {
	Global APIUsageSummary
	ByKey  map[string]APIUsageSummary
	ByUser map[string]UserUsageSummary
}

func (s *Store) EvaluateUsageControls(ctx context.Context, now time.Time, actor string) ([]UsageControlEvaluationResult, bool, error) {
	now = now.UTC()
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "reconciler"
	}
	controls, err := s.ListUsageControls(ctx, true)
	if err != nil {
		return nil, false, err
	}
	if len(controls) == 0 {
		return nil, false, nil
	}

	ownerMap, err := s.keyOwnerLookup(ctx)
	if err != nil {
		return nil, false, err
	}
	windowCache := make(map[int64]*usageWindowStats)
	results := make([]UsageControlEvaluationResult, 0, len(controls))
	keysChanged := false
	var firstActionErr error

	for _, control := range controls {
		window := control.WindowSeconds
		if window <= 0 {
			continue
		}
		stats, ok := windowCache[window]
		if !ok {
			since := now.Add(-time.Duration(window) * time.Second)
			stats, err = s.buildUsageWindowStats(ctx, since, ownerMap)
			if err != nil {
				return nil, keysChanged, err
			}
			windowCache[window] = stats
		}

		usedReq := int64(0)
		usedTok := int64(0)
		switch control.ScopeType {
		case UsageControlScopeGlobal:
			usedReq = stats.Global.TotalRequests
			usedTok = stats.Global.TotalTokens
		case UsageControlScopeKey:
			item := stats.ByKey[control.ScopeValue]
			usedReq = item.TotalRequests
			usedTok = item.TotalTokens
		case UsageControlScopeUser:
			item := stats.ByUser[control.ScopeValue]
			usedReq = item.TotalRequests
			usedTok = item.TotalTokens
		default:
			continue
		}

		triggered := false
		if control.MaxRequests != nil && usedReq > *control.MaxRequests {
			triggered = true
		}
		if control.MaxTokens != nil && usedTok > *control.MaxTokens {
			triggered = true
		}

		resultText := "within_limit"
		errorText := ""
		if triggered {
			affected := int64(0)
			switch control.Action {
			case UsageControlActionAuditOnly:
				resultText = "audit_only"
			case UsageControlActionDisableKey:
				affected, err = s.disableKeyIfNeeded(ctx, control.ScopeValue)
			case UsageControlActionDisableUserKey:
				affected, err = s.disableUserKeysIfNeeded(ctx, control.ScopeValue)
			case UsageControlActionDisableAllKeys:
				affected, err = s.disableAllKeysIfNeeded(ctx)
			default:
				err = errors.New("unknown usage control action")
			}
			if err != nil {
				resultText = "action_failed"
				errorText = err.Error()
				if firstActionErr == nil {
					firstActionErr = err
				}
			} else if control.Action != UsageControlActionAuditOnly {
				if affected > 0 {
					keysChanged = true
					resultText = fmt.Sprintf("action_applied:%d", affected)
				} else {
					resultText = "no_change"
				}
			}

			detail := fmt.Sprintf(
				"control_id=%d scope=%s:%s used_requests=%d used_tokens=%d action=%s result=%s",
				control.ID,
				control.ScopeType,
				control.ScopeValue,
				usedReq,
				usedTok,
				control.Action,
				resultText,
			)
			_ = s.InsertAuditLog(ctx, actor, "usage_control_triggered", detail)
		}

		if err := s.insertUsageControlEvent(ctx, control, usedReq, usedTok, triggered, resultText, errorText); err != nil {
			return nil, keysChanged, err
		}
		results = append(results, UsageControlEvaluationResult{
			ControlID:     control.ID,
			ScopeType:     control.ScopeType,
			ScopeValue:    control.ScopeValue,
			WindowSeconds: control.WindowSeconds,
			UsedRequests:  usedReq,
			UsedTokens:    usedTok,
			Action:        control.Action,
			Triggered:     triggered,
			Result:        resultText,
			ErrorMessage:  errorText,
		})
	}

	return results, keysChanged, firstActionErr
}

func (s *Store) buildUsageWindowStats(ctx context.Context, since time.Time, ownerMap map[string]string) (*usageWindowStats, error) {
	summaries, err := s.UsageTopSince(ctx, since, 0)
	if err != nil {
		return nil, err
	}
	stats := &usageWindowStats{
		ByKey:  make(map[string]APIUsageSummary, len(summaries)),
		ByUser: make(map[string]UserUsageSummary),
	}
	for _, item := range summaries {
		stats.ByKey[item.APIKey] = item
		stats.Global.TotalRequests += item.TotalRequests
		stats.Global.FailedRequests += item.FailedRequests
		stats.Global.TotalTokens += item.TotalTokens

		email := normalizeEmail(ownerMap[item.APIKey])
		if email == "" {
			continue
		}
		current := stats.ByUser[email]
		current.Email = email
		current.TotalRequests += item.TotalRequests
		current.FailedRequests += item.FailedRequests
		current.TotalTokens += item.TotalTokens
		current.Keys = append(current.Keys, item.APIKey)
		stats.ByUser[email] = current
	}
	return stats, nil
}

func (s *Store) keyOwnerLookup(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT api_key, owner_email FROM api_keys`)
	if err != nil {
		return nil, fmt.Errorf("query key owners: %w", err)
	}
	defer rows.Close()

	owners := make(map[string]string)
	for rows.Next() {
		var key string
		var owner string
		if err := rows.Scan(&key, &owner); err != nil {
			return nil, fmt.Errorf("scan key owner: %w", err)
		}
		owners[strings.TrimSpace(key)] = normalizeEmail(owner)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate key owners: %w", err)
	}
	return owners, nil
}

func (s *Store) ownerEmailForKeys(ctx context.Context, keys []string) (map[string]string, error) {
	owners := make(map[string]string, len(keys))
	if len(keys) == 0 {
		return owners, nil
	}
	seen := make(map[string]struct{}, len(keys))
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return owners, nil
	}
	placeholders := strings.Repeat("?,", len(normalized))
	placeholders = strings.TrimSuffix(placeholders, ",")
	args := make([]any, 0, len(normalized))
	for _, key := range normalized {
		args = append(args, key)
	}
	query := fmt.Sprintf(`SELECT api_key, owner_email FROM api_keys WHERE api_key IN (%s)`, placeholders)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query owner emails for keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var owner string
		if err := rows.Scan(&key, &owner); err != nil {
			return nil, fmt.Errorf("scan owner email for key: %w", err)
		}
		owners[strings.TrimSpace(key)] = normalizeEmail(owner)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate owner email for keys: %w", err)
	}
	return owners, nil
}

func (s *Store) insertUsageControlEvent(ctx context.Context, control UsageControl, usedRequests, usedTokens int64, triggered bool, result, errorMessage string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO usage_control_events(
			control_id,
			scope_type,
			scope_value,
			window_seconds,
			used_requests,
			used_tokens,
			threshold_requests,
			threshold_tokens,
			action,
			triggered,
			result,
			error_message
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		control.ID,
		control.ScopeType,
		control.ScopeValue,
		control.WindowSeconds,
		usedRequests,
		usedTokens,
		toNullInt64(control.MaxRequests),
		toNullInt64(control.MaxTokens),
		control.Action,
		boolToInt(triggered),
		strings.TrimSpace(result),
		strings.TrimSpace(errorMessage),
	)
	if err != nil {
		return fmt.Errorf("insert usage control event: %w", err)
	}
	return nil
}

func (s *Store) disableKeyIfNeeded(ctx context.Context, key string) (int64, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, errors.New("key is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE api_keys
		SET status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE api_key = ? AND status != ?
	`, KeyStatusDisabled, key, KeyStatusDisabled)
	if err != nil {
		return 0, fmt.Errorf("disable key if needed: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

func (s *Store) disableUserKeysIfNeeded(ctx context.Context, email string) (int64, error) {
	email = normalizeEmail(email)
	if !isLikelyEmail(email) {
		return 0, errors.New("valid email is required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE api_keys
		SET status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE owner_email = ? AND status != ?
	`, KeyStatusDisabled, email, KeyStatusDisabled)
	if err != nil {
		return 0, fmt.Errorf("disable user keys if needed: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

func (s *Store) disableAllKeysIfNeeded(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE api_keys
		SET status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE status != ?
	`, KeyStatusDisabled, KeyStatusDisabled)
	if err != nil {
		return 0, fmt.Errorf("disable all keys if needed: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

func isValidPurchaseRequestTransition(current, target string) bool {
	current = strings.ToLower(strings.TrimSpace(current))
	target = strings.ToLower(strings.TrimSpace(target))
	if current == target {
		return true
	}
	switch current {
	case PurchaseRequestStatusPending:
		switch target {
		case PurchaseRequestStatusApproved, PurchaseRequestStatusRejected, PurchaseRequestStatusCancelled:
			return true
		}
	case PurchaseRequestStatusApproved:
		switch target {
		case PurchaseRequestStatusFulfilled, PurchaseRequestStatusRejected, PurchaseRequestStatusCancelled:
			return true
		}
	}
	return false
}

func normalizePurchaseRequestStatus(raw string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case PurchaseRequestStatusPending,
		PurchaseRequestStatusApproved,
		PurchaseRequestStatusRejected,
		PurchaseRequestStatusFulfilled,
		PurchaseRequestStatusCancelled:
		return status, nil
	default:
		return "", errors.New("invalid purchase request status")
	}
}

func normalizePurchaseRequestProvisioningStatus(raw string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case PurchaseRequestProvisioningPending,
		PurchaseRequestProvisioningReady,
		PurchaseRequestProvisioningFailed:
		return status, nil
	default:
		return "", errors.New("invalid purchase request provisioning status")
	}
}

func normalizePurchaseMonths(months int64) (int64, error) {
	if months < minPurchaseMonths || months > maxPurchaseMonths {
		return 0, fmt.Errorf("months must be between %d and %d", minPurchaseMonths, maxPurchaseMonths)
	}
	return months, nil
}

func normalizePlanPersona(raw string) (string, error) {
	persona := strings.ToLower(strings.TrimSpace(raw))
	switch persona {
	case PlanPersonaWebChat, PlanPersonaHybrid, PlanPersonaHeavy:
		return persona, nil
	default:
		return "", errors.New("invalid plan persona")
	}
}

func normalizePlanBillingCycle(raw string) (string, error) {
	cycle := strings.ToLower(strings.TrimSpace(raw))
	switch cycle {
	case PlanBillingMonthly:
		return cycle, nil
	default:
		return "", errors.New("invalid plan billing cycle")
	}
}

func normalizeUsageControlInput(scopeType, scopeValue string, windowSeconds int64, maxRequests, maxTokens *int64, action string) (string, string, int64, *int64, *int64, string, error) {
	normalizedScope, err := normalizeUsageControlScopeType(scopeType)
	if err != nil {
		return "", "", 0, nil, nil, "", err
	}
	normalizedValue := strings.TrimSpace(scopeValue)
	switch normalizedScope {
	case UsageControlScopeGlobal:
		normalizedValue = ""
	case UsageControlScopeUser:
		normalizedValue = normalizeEmail(normalizedValue)
		if !isLikelyEmail(normalizedValue) {
			return "", "", 0, nil, nil, "", errors.New("valid user email scope value is required")
		}
	case UsageControlScopeKey:
		if normalizedValue == "" {
			return "", "", 0, nil, nil, "", errors.New("key scope value is required")
		}
	}
	if windowSeconds <= 0 {
		return "", "", 0, nil, nil, "", errors.New("window_seconds must be > 0")
	}
	maxReq := cloneInt64Ptr(maxRequests)
	if maxReq != nil && *maxReq <= 0 {
		return "", "", 0, nil, nil, "", errors.New("max_requests must be > 0")
	}
	maxTok := cloneInt64Ptr(maxTokens)
	if maxTok != nil && *maxTok <= 0 {
		return "", "", 0, nil, nil, "", errors.New("max_tokens must be > 0")
	}
	if maxReq == nil && maxTok == nil {
		return "", "", 0, nil, nil, "", errors.New("at least one of max_requests or max_tokens is required")
	}
	normalizedAction, err := normalizeUsageControlAction(action)
	if err != nil {
		return "", "", 0, nil, nil, "", err
	}
	if normalizedAction == UsageControlActionDisableKey && normalizedScope != UsageControlScopeKey {
		return "", "", 0, nil, nil, "", errors.New("disable_key action requires key scope")
	}
	if normalizedAction == UsageControlActionDisableUserKey && normalizedScope != UsageControlScopeUser {
		return "", "", 0, nil, nil, "", errors.New("disable_user_keys action requires user scope")
	}
	return normalizedScope, normalizedValue, windowSeconds, maxReq, maxTok, normalizedAction, nil
}

func normalizeUsageControlScopeType(raw string) (string, error) {
	scopeType := strings.ToLower(strings.TrimSpace(raw))
	switch scopeType {
	case UsageControlScopeGlobal, UsageControlScopeUser, UsageControlScopeKey:
		return scopeType, nil
	default:
		return "", errors.New("invalid usage control scope type")
	}
}

func normalizeUsageControlAction(raw string) (string, error) {
	action := strings.ToLower(strings.TrimSpace(raw))
	switch action {
	case UsageControlActionAuditOnly,
		UsageControlActionDisableKey,
		UsageControlActionDisableUserKey,
		UsageControlActionDisableAllKeys:
		return action, nil
	default:
		return "", errors.New("invalid usage control action")
	}
}

func cloneInt64Ptr(input *int64) *int64 {
	if input == nil {
		return nil
	}
	value := *input
	return &value
}

func toNullInt64(input *int64) sql.NullInt64 {
	if input == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *input, Valid: true}
}

func int64Ptr(input int64) *int64 {
	return &input
}

func toInt64Ptr(input sql.NullInt64) *int64 {
	if !input.Valid {
		return nil
	}
	value := input.Int64
	return &value
}

func boolToInt(input bool) int {
	if input {
		return 1
	}
	return 0
}

func healthCheck(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("nil database")
	}
	if _, err := db.ExecContext(ctx, `PRAGMA quick_check;`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "no such pragma") {
			return fmt.Errorf("sqlite quick_check failed: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, `SELECT 1;`); err != nil {
		return fmt.Errorf("sqlite ping failed: %w", err)
	}
	return nil
}

func (s *Store) healthCheck(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("nil store")
	}
	if err := healthCheck(ctx, s.db); err != nil {
		return err
	}
	return nil
}

func isLikelyCorruptSQLiteError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	corruptMarkers := []string{
		"database disk image is malformed",
		"file is not a database",
		"malformed database schema",
		"database corruption",
		"sql logic error",
	}
	for _, marker := range corruptMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func backupCorruptDatabase(databasePath string) (string, error) {
	databasePath = strings.TrimSpace(databasePath)
	if databasePath == "" {
		return "", fmt.Errorf("database path is required")
	}
	if _, err := os.Stat(databasePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	dir := filepath.Dir(databasePath)
	base := filepath.Base(databasePath)
	backupPath := filepath.Join(dir, fmt.Sprintf("%s.corrupt.%d.bak", base, time.Now().UTC().Unix()))
	if err := os.Rename(databasePath, backupPath); err != nil {
		return "", err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		source := databasePath + suffix
		if _, err := os.Stat(source); err == nil {
			_ = os.Rename(source, backupPath+suffix)
		}
	}
	return backupPath, nil
}

func normalizeJSON(payload []byte) (string, error) {
	var anyValue any
	if err := json.Unmarshal(payload, &anyValue); err != nil {
		return "", err
	}
	normalized, err := json.Marshal(anyValue)
	if err != nil {
		return "", err
	}
	return string(normalized), nil
}

func normalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func isLikelyEmail(raw string) bool {
	email := normalizeEmail(raw)
	if email == "" {
		return false
	}
	at := strings.Index(email, "@")
	if at <= 0 || at >= len(email)-1 {
		return false
	}
	local := email[:at]
	domain := email[at+1:]
	if strings.TrimSpace(local) == "" || strings.TrimSpace(domain) == "" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	return true
}

func toNullTime(input *time.Time) sql.NullTime {
	if input == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: input.UTC(), Valid: true}
}
