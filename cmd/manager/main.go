package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/cliproxy"
	cfgpkg "github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/reconcile"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/telegram"
)

func main() {
	cfg, err := cfgpkg.Load()
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	s, err := store.OpenWithRecovery(cfg.DatabasePath, cfg.DBRecoverOnCorrupt)
	if err != nil {
		log.Fatalf("open store failed: %v", err)
	}
	defer s.Close()

	client, err := cliproxy.NewClient(cfg.ManagementBaseURL, cfg.ManagementKey, 20*time.Second, cfg.AllowUnsafeDisableTLS)
	if err != nil {
		log.Fatalf("build cliproxy client failed: %v", err)
	}

	reconciler := reconcile.NewManager(
		s,
		client,
		cfg.ManagementPollInterval,
		cfg.UsageSyncInterval,
		cfg.RecoveryInterval,
		cfg.UpdateCheckEnabled,
		cfg.UpdateCheckTime,
		cfg.ManagementLatestVersionURL,
		cfg.UpdateApplyCommand,
		cfg.UpdateAutoApplyEnabled,
		cfg.UpdateAllowCustomCommand,
		cfg.RecoverySnapshotScanLimit,
	)
	if err := reconciler.RecoverIfNeeded(context.Background()); err != nil {
		log.Fatalf("initial recovery import failed: %v", err)
	}
	bot := telegram.New(
		cfg.TelegramBotToken,
		cfg.TelegramPollInterval,
		cfg.TelegramAllowedChatIDs,
		cfg.TelegramAllowedUserIDs,
		cfg.TelegramDenyHighRiskWhenAllowlistEmpty,
		s,
		reconciler,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := reconciler.ForceSync(ctx); err != nil {
		log.Printf("[WARN] initial sync failed: %v", err)
	}
	reconciler.Start(ctx)
	go bot.Run(ctx)

	server := buildHTTPServer(cfg, s, reconciler)
	errCh := make(chan error, 1)
	go func() {
		log.Printf("[INFO] cliproxy-access-manager listening on %s", cfg.HTTPAddr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[ERROR] http server: %v", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	reconciler.Wait()
	log.Printf("[INFO] cliproxy-access-manager stopped")
}

func buildHTTPServer(cfg cfgpkg.Config, s *store.Store, reconciler *reconcile.Manager) *http.Server {
	mux := http.NewServeMux()
	type principalHandler func(http.ResponseWriter, *http.Request, *store.Principal)

	principalActor := func(principal *store.Principal) string {
		if principal == nil {
			return "http"
		}
		email := strings.TrimSpace(principal.Email)
		if email != "" {
			return fmt.Sprintf("http:role=%s,subject=%s,email=%s", principal.Role, principal.Subject, email)
		}
		return fmt.Sprintf("http:role=%s,subject=%s", principal.Role, principal.Subject)
	}

	auditIdentitySubject := func(provider, subject string) string {
		provider = strings.ToLower(strings.TrimSpace(provider))
		subject = strings.TrimSpace(subject)
		if provider == store.IdentityProviderHTTP {
			return "[redacted-http-token]"
		}
		return subject
	}

	identitySubjectView := func(provider, subject string) string {
		provider = strings.ToLower(strings.TrimSpace(provider))
		subject = strings.TrimSpace(subject)
		if provider == store.IdentityProviderHTTP {
			return "[sha256]"
		}
		return subject
	}

	withPrincipal := func(next principalHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			provided := extractBearer(r.Header.Get("Authorization"))
			if provided == "" {
				provided = strings.TrimSpace(r.Header.Get("X-APIM-Token"))
			}
			if provided == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}

			bootstrapToken := strings.TrimSpace(cfg.HTTPAuthToken)
			if bootstrapToken != "" && provided == bootstrapToken {
				next(w, r, &store.Principal{
					Provider: store.IdentityProviderHTTP,
					Subject:  "bootstrap",
					Role:     store.IdentityRoleAdmin,
				})
				return
			}

			principal, err := s.ResolveHTTPPrincipal(r.Context(), provided)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			if principal == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			next(w, r, principal)
		}
	}

	requireAdmin := func(next principalHandler) http.HandlerFunc {
		return withPrincipal(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
			if principal == nil || principal.Role != store.IdentityRoleAdmin {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
				return
			}
			next(w, r, principal)
		})
	}

	requireUser := func(next principalHandler) http.HandlerFunc {
		return withPrincipal(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
			if principal == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			if principal.Role != store.IdentityRoleAdmin && principal.Role != store.IdentityRoleUser {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
				return
			}
			next(w, r, principal)
		})
	}

	withUpdateAdmin := func(next principalHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if cfg.HTTPUpdateRequireAuth && strings.TrimSpace(cfg.HTTPAuthToken) == "" {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "update endpoints require APIM_HTTP_AUTH_TOKEN when APIM_HTTP_UPDATE_REQUIRE_AUTH=true"})
				return
			}
			requireAdmin(next)(w, r)
		}
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/status", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		status, err := reconciler.Status(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, status)
	}))

	mux.HandleFunc("/update/check", withUpdateAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.CheckMainProjectUpdateNow(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "update_check_manual", "manual trigger")
		status, _ := reconciler.Status(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
	}))

	mux.HandleFunc("/update/apply", withUpdateAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.ApplyMainProjectUpdateNow(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		if err := reconciler.CheckMainProjectUpdateNow(r.Context()); err != nil {
			_ = s.InsertAuditLog(r.Context(), principalActor(principal), "update_check_after_apply_failed", err.Error())
		}
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "update_apply_manual", "manual trigger")
		status, _ := reconciler.Status(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
	}))

	mux.HandleFunc("/sync_now", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.ForceSync(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "sync_now", "manual")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/usage/sync_now", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.SyncUsageSnapshot(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "usage_sync_now", "manual")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/keys", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		switch r.Method {
		case http.MethodGet:
			items, err := s.ListAPIKeys(r.Context())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
			if filter == "" {
				filter = "all"
			}
			now := time.Now().UTC()
			out := make([]map[string]any, 0, len(items))
			for _, item := range items {
				state := item.Status
				if item.ExpiresAt != nil && !item.ExpiresAt.After(now) {
					state = "expired"
				}
				if filter == "active" && state != store.KeyStatusActive {
					continue
				}
				if filter == "expired" && state != "expired" {
					continue
				}
				out = append(out, map[string]any{
					"key":         item.Key,
					"status":      state,
					"expires_at":  item.ExpiresAt,
					"owner_email": item.OwnerEmail,
					"note":        item.Note,
					"updated_at":  item.UpdatedAt,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": out})
		case http.MethodPost:
			var req struct {
				Key        string  `json:"key"`
				OwnerEmail string  `json:"owner_email"`
				TTL        string  `json:"ttl"`
				ExpiresAt  *string `json:"expires_at"`
				Note       string  `json:"note"`
			}
			if err := decodeJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			expires, err := resolveExpires(req.TTL, req.ExpiresAt)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			if err := s.UpsertAPIKey(r.Context(), req.Key, expires, req.OwnerEmail, req.Note, actor); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			if err := reconciler.SyncKeys(r.Context()); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": "saved but sync failed: " + err.Error()})
				return
			}
			_ = s.InsertAuditLog(r.Context(), actor, "key_add", fmt.Sprintf("key=%s email=%s", strings.TrimSpace(req.Key), strings.ToLower(strings.TrimSpace(req.OwnerEmail))))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case http.MethodDelete:
			key := strings.TrimSpace(r.URL.Query().Get("key"))
			if key == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing key"})
				return
			}
			deleted, err := s.DeleteAPIKey(r.Context(), key)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			if !deleted {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "key not found"})
				return
			}
			if err := reconciler.SyncKeys(r.Context()); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": "deleted but sync failed: " + err.Error()})
				return
			}
			_ = s.InsertAuditLog(r.Context(), actor, "key_delete", key)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/keys/status", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPatch {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req struct {
			Key    string `json:"key"`
			Status string `json:"status"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		status := strings.ToLower(strings.TrimSpace(req.Status))
		updated, err := s.SetAPIKeyStatus(r.Context(), req.Key, status)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if !updated {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "key not found"})
			return
		}
		if err := reconciler.SyncKeys(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "updated but sync failed: " + err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "key_status", fmt.Sprintf("%s=%s", req.Key, status))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/keys/expiry", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPatch {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req struct {
			Key       string  `json:"key"`
			TTL       string  `json:"ttl"`
			ExpiresAt *string `json:"expires_at"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		expires, err := resolveExpires(req.TTL, req.ExpiresAt)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		updated, err := s.ExtendAPIKey(r.Context(), req.Key, expires)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if !updated {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "key not found"})
			return
		}
		if err := reconciler.SyncKeys(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "updated but sync failed: " + err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "key_expiry", req.Key)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/usage/top", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		items, err := s.UsageTopSince(r.Context(), since, 20)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "items": items})
	}))

	mux.HandleFunc("/usage/key", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		key := strings.TrimSpace(r.URL.Query().Get("key"))
		if key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing key"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		item, err := s.UsageForKeySince(r.Context(), key, since)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "item": item})
	}))

	mux.HandleFunc("/account/query", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		if email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing email"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		summary, err := s.AccountSummarySince(r.Context(), email, since, time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "item": summary})
	}))

	mux.HandleFunc("/me", requireUser(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		email := strings.TrimSpace(principal.Email)
		if email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "principal email is not set"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		summary, err := s.AccountSummarySince(r.Context(), email, since, time.Now().UTC())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "item": summary})
	}))

	mux.HandleFunc("/identities", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		switch r.Method {
		case http.MethodGet:
			provider := strings.TrimSpace(r.URL.Query().Get("provider"))
			items, err := s.ListIdentities(r.Context(), provider)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			out := make([]map[string]any, 0, len(items))
			for _, item := range items {
				out = append(out, map[string]any{
					"id":         item.ID,
					"provider":   item.Provider,
					"subject":    identitySubjectView(item.Provider, item.Subject),
					"role":       item.Role,
					"email":      item.Email,
					"status":     item.Status,
					"note":       item.Note,
					"created_by": item.CreatedBy,
					"created_at": item.CreatedAt,
					"updated_at": item.UpdatedAt,
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": out})
		case http.MethodPost:
			var req struct {
				Provider string `json:"provider"`
				Subject  string `json:"subject"`
				Role     string `json:"role"`
				Email    string `json:"email"`
				Note     string `json:"note"`
			}
			if err := decodeJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			if err := s.UpsertIdentity(r.Context(), req.Provider, req.Subject, req.Role, req.Email, req.Note, actor); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			detail := fmt.Sprintf("provider=%s subject=%s role=%s email=%s", strings.TrimSpace(req.Provider), auditIdentitySubject(req.Provider, req.Subject), strings.TrimSpace(req.Role), strings.ToLower(strings.TrimSpace(req.Email)))
			_ = s.InsertAuditLog(r.Context(), actor, "identity_upsert", detail)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case http.MethodDelete:
			provider := strings.TrimSpace(r.URL.Query().Get("provider"))
			subject := strings.TrimSpace(r.URL.Query().Get("subject"))
			if provider == "" || subject == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing provider or subject"})
				return
			}
			deleted, err := s.DeleteIdentity(r.Context(), provider, subject)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			if !deleted {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "identity not found"})
				return
			}
			detail := fmt.Sprintf("provider=%s subject=%s", provider, auditIdentitySubject(provider, subject))
			_ = s.InsertAuditLog(r.Context(), actor, "identity_delete", detail)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/recharge/request", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req struct {
			Email string `json:"email"`
			Plan  string `json:"plan"`
			Note  string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		req.Email = strings.TrimSpace(req.Email)
		if req.Email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing email"})
			return
		}
		req.Plan = strings.TrimSpace(req.Plan)
		req.Note = strings.TrimSpace(req.Note)
		detail := fmt.Sprintf("email=%s plan=%s note=%s", req.Email, req.Plan, req.Note)
		_ = s.InsertAuditLog(r.Context(), principalActor(principal), "recharge_request_placeholder", detail)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"status":  "pending",
			"message": "recharge interface placeholder, payment is not enabled yet",
		})
	}))

	return &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func parseSince(raw string) (time.Time, error) {
	now := time.Now().UTC()
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "24h" {
		return now.Add(-24 * time.Hour), nil
	}
	if raw == "7d" {
		return now.Add(-7 * 24 * time.Hour), nil
	}
	dur, err := time.ParseDuration(raw)
	if err != nil || dur <= 0 {
		return time.Time{}, fmt.Errorf("invalid since value")
	}
	return now.Add(-dur), nil
}

func resolveExpires(ttl string, expiresAt *string) (*time.Time, error) {
	ttl = strings.TrimSpace(ttl)
	if ttl != "" {
		lowerTTL := strings.ToLower(ttl)
		if lowerTTL == "never" || lowerTTL == "none" {
			return nil, nil
		}
		if strings.HasSuffix(lowerTTL, "d") && len(lowerTTL) > 1 {
			n, err := parsePositiveInt(strings.TrimSuffix(lowerTTL, "d"))
			if err != nil {
				return nil, err
			}
			t := time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour)
			return &t, nil
		}
		dur, err := time.ParseDuration(lowerTTL)
		if err != nil || dur <= 0 {
			return nil, fmt.Errorf("invalid ttl")
		}
		t := time.Now().UTC().Add(dur)
		return &t, nil
	}
	if expiresAt == nil {
		return nil, fmt.Errorf("ttl or expires_at is required")
	}
	raw := strings.TrimSpace(*expiresAt)
	if strings.EqualFold(raw, "none") || strings.EqualFold(raw, "never") {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("expires_at must be RFC3339")
	}
	t := parsed.UTC()
	return &t, nil
}

func parsePositiveInt(raw string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("invalid integer")
	}
	var out int
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid integer")
		}
		out = out*10 + int(r-'0')
	}
	if out <= 0 {
		return 0, fmt.Errorf("value must be > 0")
	}
	return out, nil
}

func extractBearer(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return header
}

func decodeJSON(r *http.Request, out any) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body failed")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("empty body")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid json")
	}
	if decoder.More() {
		return fmt.Errorf("invalid json")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid json")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
