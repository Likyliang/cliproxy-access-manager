package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	cfg := cfgpkg.Config{HTTPAuthToken: "bootstrap", HTTPAddr: "127.0.0.1:0"}
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
