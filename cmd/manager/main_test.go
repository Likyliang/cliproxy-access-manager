package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	cfgpkg "github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/reconcile"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
)

func TestUpdateEndpointsRequireAuthWhenTokenMissing(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	cfg := cfgpkg.Config{
		HTTPUpdateRequireAuth: true,
		HTTPAuthToken:         "",
		HTTPAddr:              "127.0.0.1:0",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieName:        "apim_session",
	}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	for _, path := range []string{"/update/check", "/update/apply"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d want=%d body=%s", path, rr.Code, http.StatusForbidden, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "require") {
			t.Fatalf("%s unexpected body: %s", path, rr.Body.String())
		}
	}
}

func TestUpdateEndpointAuthWithToken(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	cfg := cfgpkg.Config{
		HTTPUpdateRequireAuth: true,
		HTTPAuthToken:         "secret",
		HTTPAddr:              "127.0.0.1:0",
		AuthSessionTTL:        24 * time.Hour,
		AuthCookieName:        "apim_session",
	}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	req := httptest.NewRequest(http.MethodPost, "/update/check", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

func TestRBACStatusAndMe(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "user-http-token", store.IdentityRoleUser, "user@example.com", "", "test"); err != nil {
		t.Fatalf("upsert identity: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAuthToken: "bootstrap", HTTPAddr: "127.0.0.1:0", AuthSessionTTL: 24 * time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	statusReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	statusReq.Header.Set("Authorization", "Bearer user-http-token")
	statusRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(statusRR, statusReq)
	if statusRR.Code != http.StatusForbidden {
		t.Fatalf("status code=%d want=%d body=%s", statusRR.Code, http.StatusForbidden, statusRR.Body.String())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/me?since=24h", nil)
	meReq.Header.Set("Authorization", "Bearer user-http-token")
	meRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(meRR, meReq)
	if meRR.Code != http.StatusOK {
		t.Fatalf("me code=%d want=%d body=%s", meRR.Code, http.StatusOK, meRR.Body.String())
	}

	unknownReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	unknownReq.Header.Set("Authorization", "Bearer no-such-token")
	unknownRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(unknownRR, unknownReq)
	if unknownRR.Code != http.StatusUnauthorized {
		t.Fatalf("unknown code=%d want=%d body=%s", unknownRR.Code, http.StatusUnauthorized, unknownRR.Body.String())
	}
}

func TestWebUIRoutesAndV1RBAC(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "admin-http-token", store.IdentityRoleAdmin, "admin@example.com", "", "test"); err != nil {
		t.Fatalf("upsert admin identity: %v", err)
	}
	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "user-http-token", store.IdentityRoleUser, "user@example.com", "", "test"); err != nil {
		t.Fatalf("upsert user identity: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAuthToken: "bootstrap", HTTPAddr: "127.0.0.1:0", AuthSessionTTL: 24 * time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	webReq := httptest.NewRequest(http.MethodGet, "/web", nil)
	webRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(webRR, webReq)
	if webRR.Code != http.StatusOK {
		t.Fatalf("/web code=%d want=%d body=%s", webRR.Code, http.StatusOK, webRR.Body.String())
	}

	sessionReq := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	sessionReq.Header.Set("Authorization", "Bearer user-http-token")
	sessionRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(sessionRR, sessionReq)
	if sessionRR.Code != http.StatusOK {
		t.Fatalf("/api/v1/session code=%d want=%d body=%s", sessionRR.Code, http.StatusOK, sessionRR.Body.String())
	}

	adminDeniedReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/overview?since=24h", nil)
	adminDeniedReq.Header.Set("Authorization", "Bearer user-http-token")
	adminDeniedRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(adminDeniedRR, adminDeniedReq)
	if adminDeniedRR.Code != http.StatusForbidden {
		t.Fatalf("user /api/v1/admin/* code=%d want=%d body=%s", adminDeniedRR.Code, http.StatusForbidden, adminDeniedRR.Body.String())
	}

	userReq := httptest.NewRequest(http.MethodGet, "/api/v1/user/usage?since=24h", nil)
	userReq.Header.Set("Authorization", "Bearer user-http-token")
	userRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(userRR, userReq)
	if userRR.Code != http.StatusOK {
		t.Fatalf("user /api/v1/user/usage code=%d want=%d body=%s", userRR.Code, http.StatusOK, userRR.Body.String())
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/overview?since=24h", nil)
	adminReq.Header.Set("Authorization", "Bearer admin-http-token")
	adminRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusOK {
		t.Fatalf("admin /api/v1/admin/usage/overview code=%d want=%d body=%s", adminRR.Code, http.StatusOK, adminRR.Body.String())
	}

	plansReq := httptest.NewRequest(http.MethodGet, "/api/v1/plans", nil)
	plansReq.Header.Set("Authorization", "Bearer user-http-token")
	plansRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(plansRR, plansReq)
	if plansRR.Code != http.StatusOK {
		t.Fatalf("/api/v1/plans code=%d want=%d body=%s", plansRR.Code, http.StatusOK, plansRR.Body.String())
	}
	if !strings.Contains(plansRR.Body.String(), store.PlanIDWebChatMonthly) {
		t.Fatalf("/api/v1/plans missing default plan body=%s", plansRR.Body.String())
	}

	purchaseReq := httptest.NewRequest(http.MethodPost, "/api/v1/purchase-requests", strings.NewReader(`{"plan_id":"`+store.PlanIDWebChatMonthly+`","months":2,"note":"hi"}`))
	purchaseReq.Header.Set("Authorization", "Bearer user-http-token")
	purchaseReq.Header.Set("Content-Type", "application/json")
	purchaseRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(purchaseRR, purchaseReq)
	if purchaseRR.Code != http.StatusOK {
		t.Fatalf("/api/v1/purchase-requests code=%d want=%d body=%s", purchaseRR.Code, http.StatusOK, purchaseRR.Body.String())
	}

	usersReqDenied := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	usersReqDenied.Header.Set("Authorization", "Bearer user-http-token")
	usersRRDenied := httptest.NewRecorder()
	srv.Handler.ServeHTTP(usersRRDenied, usersReqDenied)
	if usersRRDenied.Code != http.StatusForbidden {
		t.Fatalf("user /api/v1/admin/users code=%d want=%d body=%s", usersRRDenied.Code, http.StatusForbidden, usersRRDenied.Body.String())
	}

	usersReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?limit=50", nil)
	usersReq.Header.Set("Authorization", "Bearer admin-http-token")
	usersRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(usersRR, usersReq)
	if usersRR.Code != http.StatusOK {
		t.Fatalf("admin /api/v1/admin/users code=%d want=%d body=%s", usersRR.Code, http.StatusOK, usersRR.Body.String())
	}
	if strings.Contains(usersRR.Body.String(), "password_hash") {
		t.Fatalf("/api/v1/admin/users leaked password_hash body=%s", usersRR.Body.String())
	}
}

func TestAdminPurchaseApprovalActivatesProvisionedKey(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "admin-http-token", store.IdentityRoleAdmin, "admin@example.com", "", "test"); err != nil {
		t.Fatalf("upsert admin identity: %v", err)
	}
	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "user-http-token", store.IdentityRoleUser, "user@example.com", "", "test"); err != nil {
		t.Fatalf("upsert user identity: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAuthToken: "bootstrap", HTTPAddr: "127.0.0.1:0", AuthSessionTTL: 24 * time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/purchase-requests", strings.NewReader(`{"plan_id":"`+store.PlanIDWebChatMonthly+`","months":3,"note":"approve me"}`))
	createReq.Header.Set("Authorization", "Bearer user-http-token")
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusOK {
		t.Fatalf("create purchase code=%d want=%d body=%s", createRR.Code, http.StatusOK, createRR.Body.String())
	}

	keysBefore, err := s.ListAPIKeysByOwner(t.Context(), "user@example.com")
	if err != nil {
		t.Fatalf("list keys before approval: %v", err)
	}
	if len(keysBefore) != 1 {
		t.Fatalf("expected one provisioned key before approval, got=%d", len(keysBefore))
	}
	if keysBefore[0].Status != store.KeyStatusDisabled {
		t.Fatalf("expected provisioned key disabled before approval, got=%s", keysBefore[0].Status)
	}

	pending, err := s.ListPurchaseRequests(t.Context(), "user@example.com", store.PurchaseRequestStatusPending, 1)
	if err != nil {
		t.Fatalf("list pending purchases: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected one pending request, got=%d", len(pending))
	}
	if pending[0].Months != 3 {
		t.Fatalf("pending months=%d want=3", pending[0].Months)
	}

	patchBody := `{"id":` + strconv.FormatInt(pending[0].ID, 10) + `,"status":"approved","review_note":"ok"}`
	approveReq := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/purchase-requests", strings.NewReader(patchBody))
	approveReq.Header.Set("Authorization", "Bearer admin-http-token")
	approveReq.Header.Set("Content-Type", "application/json")
	approveRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(approveRR, approveReq)
	if approveRR.Code != http.StatusOK && approveRR.Code != http.StatusBadGateway {
		t.Fatalf("approve code=%d want=%d or %d body=%s", approveRR.Code, http.StatusOK, http.StatusBadGateway, approveRR.Body.String())
	}

	keysAfter, err := s.ListAPIKeysByOwner(t.Context(), "user@example.com")
	if err != nil {
		t.Fatalf("list keys after approval: %v", err)
	}
	if len(keysAfter) != 1 {
		t.Fatalf("expected one key after approval, got=%d", len(keysAfter))
	}
	if keysAfter[0].Status != store.KeyStatusActive {
		t.Fatalf("expected key active after approval, got=%s", keysAfter[0].Status)
	}
	if keysAfter[0].ExpiresAt == nil {
		t.Fatalf("expected key expires_at after approval")
	}
	approvedItem, err := s.GetPurchaseRequestByID(t.Context(), pending[0].ID)
	if err != nil {
		t.Fatalf("load approved purchase request: %v", err)
	}
	if approvedItem == nil || approvedItem.ReviewedAt == nil {
		t.Fatalf("expected reviewed_at after approval, got=%#v", approvedItem)
	}
	expectedExpires := approvedItem.ReviewedAt.AddDate(0, int(approvedItem.Months), 0)
	delta := keysAfter[0].ExpiresAt.Sub(expectedExpires)
	if delta < -2*time.Second || delta > 2*time.Second {
		t.Fatalf("unexpected key expires_at=%s expected=%s delta=%s", keysAfter[0].ExpiresAt.UTC().Format(time.RFC3339Nano), expectedExpires.UTC().Format(time.RFC3339Nano), delta)
	}
}

func TestPurchaseRequestMonthsValidationAndDefault(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "admin-http-token", store.IdentityRoleAdmin, "admin@example.com", "", "test"); err != nil {
		t.Fatalf("upsert admin identity: %v", err)
	}
	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "user-http-token", store.IdentityRoleUser, "user@example.com", "", "test"); err != nil {
		t.Fatalf("upsert user identity: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAuthToken: "bootstrap", HTTPAddr: "127.0.0.1:0", AuthSessionTTL: 24 * time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	invalidReq := httptest.NewRequest(http.MethodPost, "/api/v1/purchase-requests", strings.NewReader(`{"plan_id":"`+store.PlanIDWebChatMonthly+`","months":0,"note":"bad"}`))
	invalidReq.Header.Set("Authorization", "Bearer user-http-token")
	invalidReq.Header.Set("Content-Type", "application/json")
	invalidRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(invalidRR, invalidReq)
	if invalidRR.Code != http.StatusBadRequest {
		t.Fatalf("invalid months code=%d want=%d body=%s", invalidRR.Code, http.StatusBadRequest, invalidRR.Body.String())
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/purchase-requests", strings.NewReader(`{"plan_id":"`+store.PlanIDWebChatMonthly+`","note":"default months"}`))
	createReq.Header.Set("Authorization", "Bearer user-http-token")
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusOK {
		t.Fatalf("create without months code=%d want=%d body=%s", createRR.Code, http.StatusOK, createRR.Body.String())
	}

	pending, err := s.ListPurchaseRequests(t.Context(), "user@example.com", store.PurchaseRequestStatusPending, 10)
	if err != nil {
		t.Fatalf("list pending purchases: %v", err)
	}
	if len(pending) == 0 {
		t.Fatalf("expected pending purchase request")
	}
	if pending[0].Months != 1 {
		t.Fatalf("default months=%d want=1", pending[0].Months)
	}
}

func TestAuthRegisterLoginLogoutFlow(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	cfg := cfgpkg.Config{HTTPAuthToken: "bootstrap", HTTPAddr: "127.0.0.1:0", AuthSessionTTL: time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"email":"user@example.com","password":"Secret-123"}`))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(registerRR, registerReq)
	if registerRR.Code != http.StatusOK {
		t.Fatalf("register code=%d want=%d body=%s", registerRR.Code, http.StatusOK, registerRR.Body.String())
	}

	duplicateReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"email":"user@example.com","password":"Secret-123"}`))
	duplicateReq.Header.Set("Content-Type", "application/json")
	duplicateRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(duplicateRR, duplicateReq)
	if duplicateRR.Code != http.StatusBadRequest {
		t.Fatalf("duplicate register code=%d want=%d body=%s", duplicateRR.Code, http.StatusBadRequest, duplicateRR.Body.String())
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"Secret-123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login code=%d want=%d body=%s", loginRR.Code, http.StatusOK, loginRR.Body.String())
	}
	cookies := loginRR.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected login session cookie")
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meReq.AddCookie(cookies[0])
	meRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(meRR, meReq)
	if meRR.Code != http.StatusOK {
		t.Fatalf("auth me code=%d want=%d body=%s", meRR.Code, http.StatusOK, meRR.Body.String())
	}
	var meResp struct {
		Principal struct {
			Role     any `json:"role"`
			Provider any `json:"provider"`
			Subject  any `json:"subject"`
			Email    any `json:"email"`
			UserID   any `json:"user_id"`
		} `json:"principal"`
	}
	if err := json.Unmarshal(meRR.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("decode auth me response: %v body=%s", err, meRR.Body.String())
	}
	if meResp.Principal.Role == nil || meResp.Principal.Provider == nil || meResp.Principal.Subject == nil || meResp.Principal.Email == nil || meResp.Principal.UserID == nil {
		t.Fatalf("auth me response missing lowercase principal fields body=%s", meRR.Body.String())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(cookies[0])
	logoutRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusOK {
		t.Fatalf("logout code=%d want=%d body=%s", logoutRR.Code, http.StatusOK, logoutRR.Body.String())
	}

	meAfterLogoutReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meAfterLogoutReq.AddCookie(cookies[0])
	meAfterLogoutRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(meAfterLogoutRR, meAfterLogoutReq)
	if meAfterLogoutRR.Code != http.StatusUnauthorized {
		t.Fatalf("auth me after logout code=%d want=%d body=%s", meAfterLogoutRR.Code, http.StatusUnauthorized, meAfterLogoutRR.Body.String())
	}
}

func TestAuthRegisterCannotCreateAdmin(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	cfg := cfgpkg.Config{HTTPAddr: "127.0.0.1:0", AuthSessionTTL: time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"email":"user@example.com","password":"Secret-123"}`))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(registerRR, registerReq)
	if registerRR.Code != http.StatusOK {
		t.Fatalf("register code=%d want=%d body=%s", registerRR.Code, http.StatusOK, registerRR.Body.String())
	}

	user, err := s.GetUserByEmail(t.Context(), "user@example.com")
	if err != nil {
		t.Fatalf("get user by email: %v", err)
	}
	if user == nil {
		t.Fatalf("expected user to exist")
	}
	if user.Role != store.IdentityRoleUser {
		t.Fatalf("user role=%s want=%s", user.Role, store.IdentityRoleUser)
	}
}

func TestSessionCookieAndRoleBoundary(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if _, err := s.CreateUser(t.Context(), "user@example.com", store.IdentityRoleUser, "Secret-123", "seed"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAddr: "127.0.0.1:0", AuthSessionTTL: time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"user@example.com","password":"Secret-123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login code=%d want=%d body=%s", loginRR.Code, http.StatusOK, loginRR.Body.String())
	}
	cookies := loginRR.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/overview?since=24h", nil)
	adminReq.AddCookie(cookies[0])
	adminRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusForbidden {
		t.Fatalf("user cookie on admin endpoint code=%d want=%d body=%s", adminRR.Code, http.StatusForbidden, adminRR.Body.String())
	}

	userReq := httptest.NewRequest(http.MethodGet, "/api/v1/user/usage?since=24h", nil)
	userReq.AddCookie(cookies[0])
	userRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(userRR, userReq)
	if userRR.Code != http.StatusOK {
		t.Fatalf("user cookie on user endpoint code=%d want=%d body=%s", userRR.Code, http.StatusOK, userRR.Body.String())
	}
}

func TestLegacyTokenPathStillWorks(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "admin-http-token", store.IdentityRoleAdmin, "admin@example.com", "", "test"); err != nil {
		t.Fatalf("upsert admin identity: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAddr: "127.0.0.1:0", HTTPAuthToken: "bootstrap", AuthSessionTTL: time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	unauthReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	unauthRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(unauthRR, unauthReq)
	if unauthRR.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized code=%d want=%d", unauthRR.Code, http.StatusUnauthorized)
	}

	userReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/overview?since=24h", nil)
	userReq.Header.Set("Authorization", "Bearer no-such-token")
	userRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(userRR, userReq)
	if userRR.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token code=%d want=%d", userRR.Code, http.StatusUnauthorized)
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/overview?since=24h", nil)
	adminReq.Header.Set("Authorization", "Bearer admin-http-token")
	adminRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusOK {
		t.Fatalf("legacy token admin code=%d want=%d body=%s", adminRR.Code, http.StatusOK, adminRR.Body.String())
	}
}

func TestAdminUsageControlAndOverviewSnakeCase(t *testing.T) {
	t.Parallel()

	dbPath := t.TempDir() + "/apim.db"
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	if err := s.UpsertIdentity(t.Context(), store.IdentityProviderHTTP, "admin-http-token", store.IdentityRoleAdmin, "admin@example.com", "", "test"); err != nil {
		t.Fatalf("upsert admin identity: %v", err)
	}
	if err := s.UpsertAPIKey(t.Context(), "snake-key-1", nil, "snake@example.com", "", "tester"); err != nil {
		t.Fatalf("upsert api key: %v", err)
	}

	now := time.Now().UTC()
	payload := []byte(`{"version":1,"exported_at":"2026-01-01T00:00:00Z","usage":{"apis":{"snake-key-1":{"models":{"m1":{"details":[{"timestamp":"` + now.Format(time.RFC3339) + `","failed":false,"tokens":{"total_tokens":42}}]}}}}}}`)
	if _, _, err := s.SaveUsageSnapshot(t.Context(), payload, now); err != nil {
		t.Fatalf("save usage snapshot: %v", err)
	}

	maxReq := int64(1)
	if _, err := s.CreateUsageControl(t.Context(), store.UsageControlScopeKey, "snake-key-1", 3600, &maxReq, nil, store.UsageControlActionAuditOnly, true, "snake-case", "tester"); err != nil {
		t.Fatalf("create usage control: %v", err)
	}

	cfg := cfgpkg.Config{HTTPAddr: "127.0.0.1:0", HTTPAuthToken: "bootstrap", AuthSessionTTL: time.Hour, AuthCookieName: "apim_session"}
	reconciler := reconcile.NewManager(s, nil, 0, 0, 0, true, "04:00", "/v0/management/latest-version", "", false, false, 10)
	srv := buildHTTPServer(cfg, s, reconciler)

	controlsReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage-controls", nil)
	controlsReq.Header.Set("Authorization", "Bearer admin-http-token")
	controlsRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(controlsRR, controlsReq)
	if controlsRR.Code != http.StatusOK {
		t.Fatalf("/api/v1/admin/usage-controls code=%d want=%d body=%s", controlsRR.Code, http.StatusOK, controlsRR.Body.String())
	}
	var controlsResp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(controlsRR.Body.Bytes(), &controlsResp); err != nil {
		t.Fatalf("decode usage controls: %v body=%s", err, controlsRR.Body.String())
	}
	if len(controlsResp.Items) == 0 {
		t.Fatalf("expected usage controls items")
	}
	first := controlsResp.Items[0]
	if _, ok := first["scope_type"]; !ok {
		t.Fatalf("missing snake_case scope_type in item=%v", first)
	}
	if _, ok := first["window_seconds"]; !ok {
		t.Fatalf("missing snake_case window_seconds in item=%v", first)
	}
	if _, ok := first["created_at"]; !ok {
		t.Fatalf("missing snake_case created_at in item=%v", first)
	}
	if _, ok := first["ScopeType"]; ok {
		t.Fatalf("unexpected PascalCase field ScopeType in item=%v", first)
	}

	evalReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/usage-controls/evaluate-now", nil)
	evalReq.Header.Set("Authorization", "Bearer admin-http-token")
	evalRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(evalRR, evalReq)
	if evalRR.Code != http.StatusOK && evalRR.Code != http.StatusBadGateway {
		t.Fatalf("/api/v1/admin/usage-controls/evaluate-now code=%d want=%d or %d body=%s", evalRR.Code, http.StatusOK, http.StatusBadGateway, evalRR.Body.String())
	}
	var evalResp struct {
		Results    []map[string]any `json:"results"`
		KeysSynced *bool            `json:"keys_synced"`
	}
	if err := json.Unmarshal(evalRR.Body.Bytes(), &evalResp); err != nil {
		t.Fatalf("decode evaluate-now: %v body=%s", err, evalRR.Body.String())
	}
	if evalResp.KeysSynced == nil {
		t.Fatalf("expected keys_synced in evaluate-now response: %s", evalRR.Body.String())
	}
	if len(evalResp.Results) == 0 {
		t.Fatalf("expected evaluate-now results")
	}
	if _, ok := evalResp.Results[0]["control_id"]; !ok {
		t.Fatalf("expected snake_case control_id in result=%v", evalResp.Results[0])
	}
	if _, ok := evalResp.Results[0]["used_requests"]; !ok {
		t.Fatalf("expected snake_case used_requests in result=%v", evalResp.Results[0])
	}

	overviewReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/overview?since=24h", nil)
	overviewReq.Header.Set("Authorization", "Bearer admin-http-token")
	overviewRR := httptest.NewRecorder()
	srv.Handler.ServeHTTP(overviewRR, overviewReq)
	if overviewRR.Code != http.StatusOK {
		t.Fatalf("/api/v1/admin/usage/overview code=%d want=%d body=%s", overviewRR.Code, http.StatusOK, overviewRR.Body.String())
	}
	var overviewResp struct {
		TopUsers []map[string]any `json:"top_users"`
		TopKeys  []map[string]any `json:"top_keys"`
	}
	if err := json.Unmarshal(overviewRR.Body.Bytes(), &overviewResp); err != nil {
		t.Fatalf("decode usage overview: %v body=%s", err, overviewRR.Body.String())
	}
	if len(overviewResp.TopUsers) == 0 {
		t.Fatalf("expected top_users entries")
	}
	if len(overviewResp.TopKeys) == 0 {
		t.Fatalf("expected top_keys entries")
	}
	if _, ok := overviewResp.TopUsers[0]["total_requests"]; !ok {
		t.Fatalf("expected snake_case total_requests in top_users[0]=%v", overviewResp.TopUsers[0])
	}
	if _, ok := overviewResp.TopUsers[0]["keys"]; !ok {
		t.Fatalf("expected snake_case keys in top_users[0]=%v", overviewResp.TopUsers[0])
	}
	if _, ok := overviewResp.TopKeys[0]["api_key"]; !ok {
		t.Fatalf("expected snake_case api_key in top_keys[0]=%v", overviewResp.TopKeys[0])
	}
}
