package reconcile

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/cliproxy"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
)

type Manager struct {
	store  *store.Store
	client *cliproxy.Client

	keySyncInterval       time.Duration
	usageSyncInterval     time.Duration
	recoveryCheckInterval time.Duration

	wg sync.WaitGroup
}

type Status struct {
	Healthy              bool       `json:"healthy"`
	LastKeySyncAt        *time.Time `json:"last_key_sync_at,omitempty"`
	LastUsageSnapshotAt  *time.Time `json:"last_usage_snapshot_at,omitempty"`
	LastRecoveryImportAt *time.Time `json:"last_recovery_import_at,omitempty"`
	LastKeysHash         string     `json:"last_keys_hash,omitempty"`
	LastSnapshotHash     string     `json:"last_snapshot_hash,omitempty"`
	LastRecoveryHash     string     `json:"last_recovery_hash,omitempty"`
	Message              string     `json:"message,omitempty"`
}

func NewManager(s *store.Store, c *cliproxy.Client, keySyncInterval, usageSyncInterval, recoveryCheckInterval time.Duration) *Manager {
	return &Manager{
		store:                 s,
		client:                c,
		keySyncInterval:       keySyncInterval,
		usageSyncInterval:     usageSyncInterval,
		recoveryCheckInterval: recoveryCheckInterval,
	}
}

func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	m.wg.Add(3)
	go func() {
		defer m.wg.Done()
		m.runLoop(ctx, m.keySyncInterval, "key-sync", m.SyncKeys)
	}()
	go func() {
		defer m.wg.Done()
		m.runLoop(ctx, m.usageSyncInterval, "usage-sync", m.SyncUsageSnapshot)
	}()
	go func() {
		defer m.wg.Done()
		m.runLoop(ctx, m.recoveryCheckInterval, "recovery", m.RecoverIfNeeded)
	}()
}

func (m *Manager) Wait() {
	if m == nil {
		return
	}
	m.wg.Wait()
}

func (m *Manager) runLoop(ctx context.Context, interval time.Duration, name string, fn func(context.Context) error) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if err := fn(ctx); err != nil {
		log.Printf("[WARN] %s initial run failed: %v", name, err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				log.Printf("[WARN] %s failed: %v", name, err)
			}
		}
	}
}

func (m *Manager) SyncKeys(ctx context.Context) error {
	if m == nil {
		return fmt.Errorf("nil manager")
	}
	activeKeys, err := m.store.ListActiveKeys(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	hash := store.KeysHash(activeKeys)
	currentKeys, err := m.client.GetAPIKeys(ctx)
	if err != nil {
		return err
	}
	if store.KeysHash(currentKeys) == hash {
		state, err := m.store.GetSyncState(ctx)
		if err != nil {
			return err
		}
		if state.LastAppliedKeysHash != hash {
			now := time.Now().UTC()
			if err := m.store.UpdateSyncStateKeys(ctx, hash, &now, &now); err != nil {
				return err
			}
			_ = m.store.InsertAuditLog(ctx, "reconciler", "sync_keys_state_fix", fmt.Sprintf("keys=%d hash=%s", len(activeKeys), hash))
		}
		return nil
	}
	if err := m.client.PutAPIKeys(ctx, activeKeys); err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := m.store.UpdateSyncStateKeys(ctx, hash, &now, &now); err != nil {
		return err
	}
	_ = m.store.InsertAuditLog(ctx, "reconciler", "sync_keys", fmt.Sprintf("keys=%d hash=%s", len(activeKeys), hash))
	log.Printf("[INFO] synced active api keys: %d", len(activeKeys))
	return nil
}

func (m *Manager) SyncUsageSnapshot(ctx context.Context) error {
	if m == nil {
		return fmt.Errorf("nil manager")
	}
	payload, exportedAt, err := m.client.ExportUsage(ctx)
	if err != nil {
		return err
	}
	hasData, err := store.UsageHasDataFromExportPayload(payload)
	if err != nil {
		return err
	}
	if !hasData {
		return nil
	}
	state, err := m.store.GetSyncState(ctx)
	if err != nil {
		return err
	}
	usageHash, err := store.UsageHashFromExportPayload(payload)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state.LastUsageSnapshotHash) == usageHash {
		return nil
	}
	inserted, hash, err := m.store.SaveUsageSnapshot(ctx, payload, exportedAt)
	if err != nil {
		return err
	}
	if inserted {
		_ = m.store.InsertAuditLog(ctx, "reconciler", "sync_usage_snapshot", fmt.Sprintf("hash=%s exported_at=%s", hash, exportedAt.Format(time.RFC3339)))
		log.Printf("[INFO] saved usage snapshot: %s", hash)
	}
	return nil
}

func (m *Manager) RecoverIfNeeded(ctx context.Context) error {
	if m == nil {
		return fmt.Errorf("nil manager")
	}
	latest, err := m.store.GetLatestUsageSnapshot(ctx)
	if err != nil {
		return err
	}
	if latest == nil {
		return nil
	}
	usageHash, err := store.UsageHashFromExportPayload([]byte(latest.PayloadJSON))
	if err != nil {
		return err
	}
	state, err := m.store.GetSyncState(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state.LastRecoverImportHash) == usageHash {
		return nil
	}
	livePayload, _, err := m.client.ExportUsage(ctx)
	if err != nil {
		return err
	}
	liveHasData, err := store.UsageHasDataFromExportPayload(livePayload)
	if err != nil {
		return err
	}
	if liveHasData {
		liveHash, hashErr := store.UsageHashFromExportPayload(livePayload)
		if hashErr != nil {
			return hashErr
		}
		if liveHash == usageHash {
			now := time.Now().UTC()
			if err := m.store.TouchSyncStateRecoveryHash(ctx, usageHash, &now); err != nil {
				return err
			}
		}
		return nil
	}
	if err := m.client.ImportUsage(ctx, []byte(latest.PayloadJSON)); err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := m.store.UpdateSyncStateRecovery(ctx, usageHash, &now, &now); err != nil {
		return err
	}
	_ = m.store.InsertAuditLog(ctx, "reconciler", "recover_usage_import", fmt.Sprintf("hash=%s", usageHash))
	if err := m.SyncKeys(ctx); err != nil {
		log.Printf("[WARN] key sync after recovery failed: %v", err)
	}
	log.Printf("[INFO] imported latest usage snapshot for recovery: %s", usageHash)
	return nil
}

func (m *Manager) ForceSync(ctx context.Context) error {
	if err := m.SyncKeys(ctx); err != nil {
		return err
	}
	if err := m.SyncUsageSnapshot(ctx); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	if m == nil {
		return Status{}, fmt.Errorf("nil manager")
	}
	state, err := m.store.GetSyncState(ctx)
	if err != nil {
		return Status{}, err
	}
	healthErr := m.client.Health(ctx)
	status := Status{
		Healthy:              healthErr == nil,
		LastKeySyncAt:        state.LastAppliedAt,
		LastUsageSnapshotAt:  state.LastUsageSnapshotAt,
		LastRecoveryImportAt: state.LastRecoverImportAt,
		LastKeysHash:         state.LastAppliedKeysHash,
		LastSnapshotHash:     state.LastUsageSnapshotHash,
		LastRecoveryHash:     state.LastRecoverImportHash,
	}
	if healthErr != nil {
		status.Message = healthErr.Error()
	}
	return status, nil
}
