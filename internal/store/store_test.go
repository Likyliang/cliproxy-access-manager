package store

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestListRecentUsageSnapshotsOrdersByExportedAt(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	p1 := []byte(`{"version":1,"exported_at":"2026-01-01T00:00:00Z","usage":{"apis":{"a":{}}}}`)
	p2 := []byte(`{"version":1,"exported_at":"2026-01-01T00:00:00Z","usage":{"apis":{"b":{}}}}`)
	if _, _, err := s.SaveUsageSnapshot(t.Context(), p1, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("save p1: %v", err)
	}
	if _, _, err := s.SaveUsageSnapshot(t.Context(), p2, now.Add(-time.Minute)); err != nil {
		t.Fatalf("save p2: %v", err)
	}

	items, err := s.ListRecentUsageSnapshots(t.Context(), 2)
	if err != nil {
		t.Fatalf("ListRecentUsageSnapshots error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items)=%d want=2", len(items))
	}
	if !items[0].ExportedAt.After(items[1].ExportedAt) {
		t.Fatalf("expected descending exported_at order")
	}
}

func TestIsLikelyCorruptSQLiteError(t *testing.T) {
	t.Parallel()
	if !isLikelyCorruptSQLiteError(errors.New("database disk image is malformed")) {
		t.Fatalf("expected corrupt marker to match")
	}
	if isLikelyCorruptSQLiteError(errors.New("permission denied")) {
		t.Fatalf("did not expect non-corrupt error to match")
	}
}

func TestBackupCorruptDatabaseCreatesBackup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dbPath := dir + "/apim.db"
	if err := os.WriteFile(dbPath, []byte("not-sqlite"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	backup, err := backupCorruptDatabase(dbPath)
	if err != nil {
		t.Fatalf("backupCorruptDatabase error: %v", err)
	}
	if strings.TrimSpace(backup) == "" {
		t.Fatalf("expected backup path")
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup not found: %v", err)
	}
}

func TestOpenWithRecoveryRejectsNonCorruptErrors(t *testing.T) {
	t.Parallel()
	_, err := OpenWithRecovery("/proc/forbidden/apim.db", true)
	if err == nil {
		t.Fatalf("expected error for invalid path")
	}
}

func TestIdentityRoundTripHTTPAndTelegram(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), IdentityProviderHTTP, "user-token-1", IdentityRoleUser, "user@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert http user identity: %v", err)
	}
	if err := s.UpsertIdentity(t.Context(), IdentityProviderTelegram, "12345", IdentityRoleAdmin, "", "", "tester"); err != nil {
		t.Fatalf("upsert telegram admin identity: %v", err)
	}

	httpPrincipal, err := s.ResolveHTTPPrincipal(t.Context(), "user-token-1")
	if err != nil {
		t.Fatalf("resolve http principal: %v", err)
	}
	if httpPrincipal == nil {
		t.Fatalf("expected http principal")
	}
	if httpPrincipal.Role != IdentityRoleUser || httpPrincipal.Email != "user@example.com" {
		t.Fatalf("unexpected http principal: %#v", httpPrincipal)
	}

	tgPrincipal, err := s.ResolveTelegramPrincipal(t.Context(), 12345)
	if err != nil {
		t.Fatalf("resolve telegram principal: %v", err)
	}
	if tgPrincipal == nil {
		t.Fatalf("expected telegram principal")
	}
	if tgPrincipal.Role != IdentityRoleAdmin {
		t.Fatalf("unexpected telegram role: %s", tgPrincipal.Role)
	}

	items, err := s.ListIdentities(t.Context(), "")
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items)=%d want=2", len(items))
	}

	deletedByRaw, err := s.DeleteIdentity(t.Context(), IdentityProviderHTTP, "user-token-1")
	if err != nil {
		t.Fatalf("delete http identity by raw token: %v", err)
	}
	if !deletedByRaw {
		t.Fatalf("expected delete by raw token")
	}

	if p, err := s.ResolveHTTPPrincipal(t.Context(), "user-token-1"); err != nil || p != nil {
		t.Fatalf("expected no principal after delete, got principal=%#v err=%v", p, err)
	}

	httpToken2 := "user-token-2"
	if err := s.UpsertIdentity(t.Context(), IdentityProviderHTTP, httpToken2, IdentityRoleUser, "user2@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert second http identity: %v", err)
	}
	deletedByHash, err := s.DeleteIdentity(t.Context(), IdentityProviderHTTP, hashHTTPToken(httpToken2))
	if err != nil {
		t.Fatalf("delete http identity by hash: %v", err)
	}
	if !deletedByHash {
		t.Fatalf("expected delete by hash")
	}
}

func TestIdentityValidation(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), "smtp", "x", IdentityRoleAdmin, "", "", "tester"); err == nil {
		t.Fatalf("expected invalid provider error")
	}
	if err := s.UpsertIdentity(t.Context(), IdentityProviderTelegram, "not-int", IdentityRoleAdmin, "", "", "tester"); err == nil {
		t.Fatalf("expected invalid telegram subject error")
	}
	if err := s.UpsertIdentity(t.Context(), IdentityProviderHTTP, "tok", "viewer", "", "", "tester"); err == nil {
		t.Fatalf("expected invalid role error")
	}
	if err := s.UpsertIdentity(t.Context(), IdentityProviderHTTP, "tok", IdentityRoleUser, "", "", "tester"); err == nil {
		t.Fatalf("expected missing user email error")
	}
	if err := s.UpsertIdentity(t.Context(), IdentityProviderHTTP, "tok", IdentityRoleAdmin, "not-email", "", "tester"); err == nil {
		t.Fatalf("expected invalid admin email error")
	}
}

func TestResolveTelegramPrincipalInvalidID(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	principal, err := s.ResolveTelegramPrincipal(t.Context(), 0)
	if err != nil {
		t.Fatalf("resolve telegram principal: %v", err)
	}
	if principal != nil {
		t.Fatalf("expected nil principal for invalid id")
	}

	if err := s.UpsertIdentity(t.Context(), IdentityProviderTelegram, strconv.FormatInt(999, 10), IdentityRoleUser, "u@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert telegram user: %v", err)
	}
	principal, err = s.ResolveTelegramPrincipal(t.Context(), 999)
	if err != nil {
		t.Fatalf("resolve telegram principal: %v", err)
	}
	if principal == nil || principal.Email != "u@example.com" {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}
