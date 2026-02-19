package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
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
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_status_expires ON api_keys(status, expires_at);`,
		`ALTER TABLE api_keys ADD COLUMN owner_email TEXT NOT NULL DEFAULT '';`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_owner_email ON api_keys(owner_email);`,
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
	}
	for _, query := range queries {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			lowerErr := strings.ToLower(err.Error())
			lowerQuery := strings.ToLower(query)
			if strings.Contains(lowerErr, "duplicate column name") && (strings.Contains(lowerQuery, "alter table api_keys add column owner_email") || strings.Contains(lowerQuery, "alter table sync_state add column")) {
				continue
			}
			return fmt.Errorf("migrate query failed: %w", err)
		}
	}
	return nil
}

func (s *Store) UpsertAPIKey(ctx context.Context, key string, expiresAt *time.Time, ownerEmail, note, createdBy string) error {
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
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys(api_key, status, expires_at, owner_email, note, created_by)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(api_key) DO UPDATE SET
			status = excluded.status,
			expires_at = excluded.expires_at,
			owner_email = excluded.owner_email,
			note = excluded.note,
			updated_at = CURRENT_TIMESTAMP
	`, key, KeyStatusActive, toNullTime(expiresAt), ownerEmail, note, createdBy)
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
		SELECT id, api_key, status, expires_at, owner_email, note, created_by, created_at, updated_at
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
		if err := rows.Scan(
			&item.ID,
			&item.Key,
			&item.Status,
			&expires,
			&item.OwnerEmail,
			&item.Note,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		if expires.Valid {
			t := expires.Time.UTC()
			item.ExpiresAt = &t
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
