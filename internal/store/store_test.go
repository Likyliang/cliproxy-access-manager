package store

import (
	"crypto/subtle"
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

func TestPurchaseRequestLifecycle(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	item, err := s.CreatePurchaseRequest(t.Context(), "buyer@example.com", PlanIDWebChatMonthly, 3, "need for project", "tester")
	if err != nil {
		t.Fatalf("create purchase request: %v", err)
	}
	if item == nil || item.Status != PurchaseRequestStatusPending {
		t.Fatalf("unexpected created item: %#v", item)
	}
	if item.PlanID != PlanIDWebChatMonthly || item.Plan != PlanIDWebChatMonthly {
		t.Fatalf("expected plan id in request, got plan=%s plan_id=%s", item.Plan, item.PlanID)
	}
	if item.Months != 3 {
		t.Fatalf("months=%d want=3", item.Months)
	}
	if item.ProvisioningStatus != PurchaseRequestProvisioningReady {
		t.Fatalf("provisioning status=%s want=%s", item.ProvisioningStatus, PurchaseRequestProvisioningReady)
	}
	if item.ActivationAttemptedAt != nil {
		t.Fatalf("activation_attempted_at should be nil before approval")
	}

	keys, err := s.ListAPIKeysByOwner(t.Context(), "buyer@example.com")
	if err != nil {
		t.Fatalf("list keys by owner: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys)=%d want=1", len(keys))
	}
	if keys[0].Status != KeyStatusDisabled {
		t.Fatalf("provisioned key status=%s want=%s", keys[0].Status, KeyStatusDisabled)
	}
	if keys[0].PlanID != PlanIDWebChatMonthly {
		t.Fatalf("provisioned key plan_id=%s want=%s", keys[0].PlanID, PlanIDWebChatMonthly)
	}
	if keys[0].PurchaseRequestID == nil || *keys[0].PurchaseRequestID != item.ID {
		t.Fatalf("unexpected purchase request link on key: %#v", keys[0].PurchaseRequestID)
	}

	controls, err := s.ListUsageControls(t.Context(), true)
	if err != nil {
		t.Fatalf("list usage controls: %v", err)
	}
	matched := false
	for _, control := range controls {
		if control.ScopeType == UsageControlScopeKey && control.ScopeValue == keys[0].Key {
			matched = true
			if control.Action != UsageControlActionDisableKey {
				t.Fatalf("usage control action=%s want=%s", control.Action, UsageControlActionDisableKey)
			}
			if control.MaxTokens == nil || *control.MaxTokens <= 0 {
				t.Fatalf("expected key max_tokens from plan, got=%v", control.MaxTokens)
			}
		}
	}
	if !matched {
		t.Fatalf("expected auto usage control for provisioned key")
	}

	mine, err := s.ListPurchaseRequests(t.Context(), "buyer@example.com", "", 10)
	if err != nil {
		t.Fatalf("list mine: %v", err)
	}
	if len(mine) != 1 || mine[0].ID != item.ID {
		t.Fatalf("unexpected mine list: %#v", mine)
	}

	approved, err := s.UpdatePurchaseRequestStatus(t.Context(), item.ID, PurchaseRequestStatusApproved, "approved", "admin")
	if err != nil {
		t.Fatalf("approve request: %v", err)
	}
	if approved == nil || approved.Status != PurchaseRequestStatusApproved {
		t.Fatalf("unexpected approved item: %#v", approved)
	}
	if approved.ReviewedAt == nil {
		t.Fatalf("expected reviewed_at after approve")
	}
	if approved.ActivationAttemptedAt == nil {
		t.Fatalf("expected activation_attempted_at after approve")
	}

	keys, err = s.ListAPIKeysByOwner(t.Context(), "buyer@example.com")
	if err != nil {
		t.Fatalf("list keys by owner after approval: %v", err)
	}
	if len(keys) != 1 || keys[0].Status != KeyStatusActive {
		t.Fatalf("expected approved key active, got %#v", keys)
	}
	if keys[0].ExpiresAt == nil {
		t.Fatalf("expected approved key expires_at to be set")
	}
	if approved.ReviewedAt == nil {
		t.Fatalf("expected reviewed_at after approve")
	}
	expectedExpires := approved.ReviewedAt.AddDate(0, int(item.Months), 0)
	delta := keys[0].ExpiresAt.Sub(expectedExpires)
	if delta < -2*time.Second || delta > 2*time.Second {
		t.Fatalf("unexpected expires_at=%s expected=%s delta=%s", keys[0].ExpiresAt.UTC().Format(time.RFC3339Nano), expectedExpires.UTC().Format(time.RFC3339Nano), delta)
	}

	fulfilled, err := s.UpdatePurchaseRequestStatus(t.Context(), item.ID, PurchaseRequestStatusFulfilled, "delivered", "admin")
	if err != nil {
		t.Fatalf("fulfill request: %v", err)
	}
	if fulfilled == nil || fulfilled.Status != PurchaseRequestStatusFulfilled {
		t.Fatalf("unexpected fulfilled item: %#v", fulfilled)
	}

	_, err = s.UpdatePurchaseRequestStatus(t.Context(), item.ID, PurchaseRequestStatusPending, "rollback", "admin")
	if err == nil {
		t.Fatalf("expected invalid transition error")
	}
}

func TestPurchaseRequestMonthsValidation(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	_, err = s.CreatePurchaseRequest(t.Context(), "buyer@example.com", PlanIDWebChatMonthly, 0, "invalid months", "tester")
	if err == nil {
		t.Fatalf("expected error for months=0")
	}

	_, err = s.CreatePurchaseRequest(t.Context(), "buyer@example.com", PlanIDWebChatMonthly, -1, "invalid months", "tester")
	if err == nil {
		t.Fatalf("expected error for months<0")
	}

	_, err = s.CreatePurchaseRequest(t.Context(), "buyer@example.com", PlanIDWebChatMonthly, 37, "invalid months", "tester")
	if err == nil {
		t.Fatalf("expected error for months above max")
	}
}

func TestUsageControlEvaluateActions(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	if err := s.UpsertAPIKey(t.Context(), "key-a", nil, "usera@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert key-a: %v", err)
	}
	if err := s.UpsertAPIKey(t.Context(), "key-b", nil, "usera@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert key-b: %v", err)
	}
	if err := s.UpsertAPIKey(t.Context(), "key-c", nil, "userb@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert key-c: %v", err)
	}

	payload := []byte(`{"version":1,"exported_at":"2026-01-01T00:00:00Z","usage":{"apis":{"key-a":{"models":{"m1":{"details":[{"timestamp":"` + now.Format(time.RFC3339) + `","failed":false,"tokens":{"total_tokens":10}},{"timestamp":"` + now.Format(time.RFC3339) + `","failed":false,"tokens":{"total_tokens":20}},{"timestamp":"` + now.Format(time.RFC3339) + `","failed":false,"tokens":{"total_tokens":30}}]}}},"key-b":{"models":{"m1":{"details":[{"timestamp":"` + now.Format(time.RFC3339) + `","failed":false,"tokens":{"total_tokens":7}}]}}},"key-c":{"models":{"m1":{"details":[{"timestamp":"` + now.Format(time.RFC3339) + `","failed":false,"tokens":{"total_tokens":100}}]}}}}}}`)
	if _, _, err := s.SaveUsageSnapshot(t.Context(), payload, now); err != nil {
		t.Fatalf("save usage snapshot: %v", err)
	}

	maxReq2 := int64(2)
	if _, err := s.CreateUsageControl(
		t.Context(),
		UsageControlScopeKey,
		"key-a",
		3600,
		&maxReq2,
		nil,
		UsageControlActionDisableKey,
		true,
		"disable noisy key",
		"tester",
	); err != nil {
		t.Fatalf("create key control: %v", err)
	}

	maxReq1 := int64(1)
	if _, err := s.CreateUsageControl(
		t.Context(),
		UsageControlScopeUser,
		"usera@example.com",
		3600,
		&maxReq1,
		nil,
		UsageControlActionDisableUserKey,
		true,
		"disable user keys",
		"tester",
	); err != nil {
		t.Fatalf("create user control: %v", err)
	}

	maxTok50 := int64(50)
	if _, err := s.CreateUsageControl(
		t.Context(),
		UsageControlScopeGlobal,
		"",
		3600,
		nil,
		&maxTok50,
		UsageControlActionAuditOnly,
		true,
		"audit over token",
		"tester",
	); err != nil {
		t.Fatalf("create global control: %v", err)
	}

	results, keysChanged, err := s.EvaluateUsageControls(t.Context(), now, "reconciler")
	if err != nil {
		t.Fatalf("evaluate usage controls: %v", err)
	}
	if !keysChanged {
		t.Fatalf("expected keysChanged")
	}
	if len(results) != 3 {
		t.Fatalf("results len=%d want=3", len(results))
	}

	keys, err := s.ListAPIKeys(t.Context())
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	statusByKey := map[string]string{}
	for _, item := range keys {
		statusByKey[item.Key] = item.Status
	}
	if statusByKey["key-a"] != KeyStatusDisabled {
		t.Fatalf("key-a status=%s want=%s", statusByKey["key-a"], KeyStatusDisabled)
	}
	if statusByKey["key-b"] != KeyStatusDisabled {
		t.Fatalf("key-b status=%s want=%s", statusByKey["key-b"], KeyStatusDisabled)
	}

	users, err := s.UsageUsersSince(t.Context(), now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("usage users since: %v", err)
	}
	if len(users) == 0 {
		t.Fatalf("expected usage users")
	}

	userA, err := s.UsageForUserSince(t.Context(), "usera@example.com", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("usage for user since: %v", err)
	}
	if userA.TotalRequests == 0 {
		t.Fatalf("expected userA requests > 0")
	}
}

func TestPasswordHashAndVerify(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("P@ssw0rd-123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected hash")
	}

	ok, err := verifyPassword(hash, "P@ssw0rd-123")
	if err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if !ok {
		t.Fatalf("expected password verification success")
	}

	ok, err = verifyPassword(hash, "wrong-password")
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if ok {
		t.Fatalf("expected password verification failure")
	}
}

func TestVerifyPasswordMalformedHash(t *testing.T) {
	t.Parallel()

	if _, err := verifyPassword("bad-format", "abc"); err == nil {
		t.Fatalf("expected malformed hash error")
	}
}

func TestConstantTimeCompareUsage(t *testing.T) {
	t.Parallel()

	a := []byte{1, 2, 3}
	b := []byte{1, 2, 4}
	if subtle.ConstantTimeCompare(a, b) != 0 {
		t.Fatalf("expected non equal")
	}
}

func TestListPlanCatalogAndUsers(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	plans, err := s.ListPlanCatalog(t.Context(), true)
	if err != nil {
		t.Fatalf("list plan catalog: %v", err)
	}
	if len(plans) < 3 {
		t.Fatalf("expected default seeded plans, got=%d", len(plans))
	}

	if _, err := s.CreateUser(t.Context(), "admin@example.com", IdentityRoleAdmin, "Secret-123", "seed"); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if _, err := s.CreateUser(t.Context(), "user@example.com", IdentityRoleUser, "Secret-123", "seed"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	users, err := s.ListUsers(t.Context(), "", "", "", 20)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) < 2 {
		t.Fatalf("expected at least 2 users, got=%d", len(users))
	}
	for _, u := range users {
		if u.PasswordHash != "" {
			t.Fatalf("password hash should be redacted in ListUsers")
		}
	}

	filtered, err := s.ListUsers(t.Context(), IdentityRoleAdmin, UserStatusActive, "admin@", 10)
	if err != nil {
		t.Fatalf("list filtered users: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected one filtered admin user, got=%d", len(filtered))
	}
	if filtered[0].Role != IdentityRoleAdmin {
		t.Fatalf("expected admin role, got=%s", filtered[0].Role)
	}
}

func TestUserAndSessionLifecycle(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	user, err := s.CreateUser(t.Context(), "user@example.com", IdentityRoleUser, "Secret-123", "test")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user == nil || user.Role != IdentityRoleUser {
		t.Fatalf("unexpected user: %#v", user)
	}

	if _, err := s.CreateUser(t.Context(), "user@example.com", IdentityRoleUser, "Secret-123", "test"); err == nil {
		t.Fatalf("expected duplicate email error")
	}

	verified, err := s.VerifyUserPassword(t.Context(), "user@example.com", "Secret-123")
	if err != nil {
		t.Fatalf("verify user password: %v", err)
	}
	if verified == nil || verified.ID != user.ID {
		t.Fatalf("unexpected verified user: %#v", verified)
	}

	failed, err := s.VerifyUserPassword(t.Context(), "user@example.com", "bad")
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if failed != nil {
		t.Fatalf("expected nil for wrong password")
	}

	token, session, err := s.CreateSession(t.Context(), user.ID, time.Hour, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if token == "" || session == nil {
		t.Fatalf("unexpected session create result")
	}

	principal, err := s.ResolveSessionPrincipal(t.Context(), token)
	if err != nil {
		t.Fatalf("resolve session principal: %v", err)
	}
	if principal == nil || principal.Role != IdentityRoleUser || principal.Email != "user@example.com" {
		t.Fatalf("unexpected principal: %#v", principal)
	}

	if err := s.RevokeSession(t.Context(), token); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	principal, err = s.ResolveSessionPrincipal(t.Context(), token)
	if err != nil {
		t.Fatalf("resolve revoked session: %v", err)
	}
	if principal != nil {
		t.Fatalf("expected nil principal after revoke")
	}
}

func TestSessionExpired(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	user, err := s.CreateUser(t.Context(), "expired@example.com", IdentityRoleUser, "Secret-123", "test")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, session, err := s.CreateSession(t.Context(), user.ID, time.Minute, "", "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE auth_sessions SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute), session.ID); err != nil {
		t.Fatalf("force expire session: %v", err)
	}

	principal, err := s.ResolveSessionPrincipal(t.Context(), token)
	if err != nil {
		t.Fatalf("resolve expired session: %v", err)
	}
	if principal != nil {
		t.Fatalf("expected nil principal for expired session")
	}
}

func TestEnsureAdminUser(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	admin, err := s.EnsureAdminUser(t.Context(), "admin@example.com", "Secret-123", "bootstrap")
	if err != nil {
		t.Fatalf("ensure admin user: %v", err)
	}
	if admin == nil || admin.Role != IdentityRoleAdmin {
		t.Fatalf("unexpected admin user: %#v", admin)
	}

	again, err := s.EnsureAdminUser(t.Context(), "admin@example.com", "Secret-123", "bootstrap")
	if err != nil {
		t.Fatalf("ensure admin user second run: %v", err)
	}
	if again == nil || again.ID != admin.ID {
		t.Fatalf("expected same admin user")
	}

	none, err := s.EnsureAdminUser(t.Context(), "", "", "bootstrap")
	if err != nil {
		t.Fatalf("ensure admin empty config: %v", err)
	}
	if none != nil {
		t.Fatalf("expected nil when bootstrap credentials are empty")
	}
}
