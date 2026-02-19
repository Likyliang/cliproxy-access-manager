package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/cliproxy"
	cfgpkg "github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/reconcile"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/telegram"
	webui "github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/web"
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

	if _, err := s.EnsureAdminUser(context.Background(), cfg.AdminEmail, cfg.AdminPassword, "bootstrap"); err != nil {
		log.Fatalf("ensure admin user failed: %v", err)
	}

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
	authCookieName := strings.TrimSpace(cfg.AuthCookieName)
	if authCookieName == "" {
		authCookieName = "apim_session"
	}
	authCookiePath := "/"
	authCookieTTL := cfg.AuthSessionTTL
	if authCookieTTL <= 0 {
		authCookieTTL = 24 * time.Hour
	}
	cookieSecure := cfg.AuthCookieSecure

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

	setSessionCookie := func(w http.ResponseWriter, token string) {
		http.SetCookie(w, &http.Cookie{
			Name:     authCookieName,
			Value:    token,
			Path:     authCookiePath,
			MaxAge:   int(authCookieTTL / time.Second),
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	clearSessionCookie := func(w http.ResponseWriter) {
		http.SetCookie(w, &http.Cookie{
			Name:     authCookieName,
			Value:    "",
			Path:     authCookiePath,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0).UTC(),
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	clientIP := func(r *http.Request) string {
		if r == nil {
			return ""
		}
		forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
		realIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if realIP != "" {
			return realIP
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err == nil {
			return host
		}
		return strings.TrimSpace(r.RemoteAddr)
	}

	withPrincipal := func(next principalHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if cookie, err := r.Cookie(authCookieName); err == nil {
				raw := strings.TrimSpace(cookie.Value)
				if raw != "" {
					principal, resolveErr := s.ResolveSessionPrincipal(r.Context(), raw)
					if resolveErr != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]any{"error": resolveErr.Error()})
						return
					}
					if principal != nil {
						next(w, r, principal)
						return
					}
				}
			}

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

	webHandler := webui.NewHandler()
	mux.Handle("/web", webHandler)
	mux.Handle("/web/", webHandler)
	mux.Handle("/webapp", webHandler)
	mux.Handle("/webapp/", webHandler)

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
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.CheckMainProjectUpdateNow(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), actor, "update_check_manual", "manual trigger")
		status, _ := reconciler.Status(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
	}))

	mux.HandleFunc("/update/apply", withUpdateAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.ApplyMainProjectUpdateNow(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		if err := reconciler.CheckMainProjectUpdateNow(r.Context()); err != nil {
			_ = s.InsertAuditLog(r.Context(), actor, "update_check_after_apply_failed", err.Error())
		}
		_ = s.InsertAuditLog(r.Context(), actor, "update_apply_manual", "manual trigger")
		status, _ := reconciler.Status(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
	}))

	mux.HandleFunc("/sync_now", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.ForceSync(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), actor, "sync_now", "manual")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/usage/sync_now", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if err := reconciler.SyncUsageSnapshot(r.Context()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), actor, "usage_sync_now", "manual")
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
					"plan_id":     item.PlanID,
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
		actor := principalActor(principal)
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
		_ = s.InsertAuditLog(r.Context(), actor, "key_status", fmt.Sprintf("%s=%s", req.Key, status))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/keys/expiry", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
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
		_ = s.InsertAuditLog(r.Context(), actor, "key_expiry", req.Key)
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

	parseLimit := func(raw string, fallback int) int {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return fallback
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return fallback
		}
		return n
	}
	parseQueryBool := func(raw string, fallback bool) bool {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == "" {
			return fallback
		}
		switch raw {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		default:
			return fallback
		}
	}
	remainingFromLimit := func(limit *int64, used int64) *int64 {
		if limit == nil {
			return nil
		}
		remaining := *limit - used
		if remaining < 0 {
			remaining = 0
		}
		return &remaining
	}
	findUserControl := func(controls []store.UsageControl, email string) *store.UsageControl {
		email = strings.ToLower(strings.TrimSpace(email))
		for i := range controls {
			item := controls[i]
			if !item.Enabled {
				continue
			}
			if item.ScopeType == store.UsageControlScopeUser && strings.EqualFold(item.ScopeValue, email) {
				copyItem := item
				return &copyItem
			}
		}
		return nil
	}
	findKeyControl := func(controls []store.UsageControl, key, email string) *store.UsageControl {
		key = strings.TrimSpace(key)
		email = strings.ToLower(strings.TrimSpace(email))
		for i := range controls {
			item := controls[i]
			if !item.Enabled {
				continue
			}
			if item.ScopeType == store.UsageControlScopeKey && item.ScopeValue == key {
				copyItem := item
				return &copyItem
			}
		}
		for i := range controls {
			item := controls[i]
			if !item.Enabled {
				continue
			}
			if item.ScopeType == store.UsageControlScopeUser && strings.EqualFold(item.ScopeValue, email) {
				copyItem := item
				return &copyItem
			}
		}
		return nil
	}
	controlView := func(control *store.UsageControl, usedRequests, usedTokens int64) map[string]any {
		if control == nil {
			return map[string]any{
				"scope_type":         nil,
				"scope_value":        nil,
				"window_seconds":     nil,
				"action":             nil,
				"max_requests":       nil,
				"max_tokens":         nil,
				"remaining_requests": nil,
				"remaining_tokens":   nil,
			}
		}
		return map[string]any{
			"scope_type":         control.ScopeType,
			"scope_value":        control.ScopeValue,
			"window_seconds":     control.WindowSeconds,
			"action":             control.Action,
			"max_requests":       control.MaxRequests,
			"max_tokens":         control.MaxTokens,
			"remaining_requests": remainingFromLimit(control.MaxRequests, usedRequests),
			"remaining_tokens":   remainingFromLimit(control.MaxTokens, usedTokens),
		}
	}
	forwardToLegacy := func(targetPath string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cloned := r.Clone(r.Context())
			u := *r.URL
			u.Path = targetPath
			cloned.URL = &u
			cloned.RequestURI = targetPath
			mux.ServeHTTP(w, cloned)
		}
	}

	mux.HandleFunc("/recharge/request", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req struct {
			Email  string `json:"email"`
			PlanID string `json:"plan_id"`
			Plan   string `json:"plan"`
			Note   string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		planID := strings.TrimSpace(req.PlanID)
		if planID == "" {
			planID = strings.TrimSpace(req.Plan)
		}
		item, err := s.CreatePurchaseRequest(r.Context(), req.Email, planID, req.Note, actor)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), actor, "purchase_request_create", fmt.Sprintf("id=%d email=%s", item.ID, item.RequesterEmail))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": item})
	}))

	mux.HandleFunc("/api/v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if _, err := s.CreateUser(r.Context(), req.Email, store.IdentityRoleUser, req.Password, "self_register"); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		user, err := s.VerifyUserPassword(r.Context(), req.Email, req.Password)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
			return
		}
		token, _, err := s.CreateSession(r.Context(), user.ID, authCookieTTL, clientIP(r), r.UserAgent())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		setSessionCookie(w, token)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if cookie, err := r.Cookie(authCookieName); err == nil {
			_ = s.RevokeSession(r.Context(), cookie.Value)
		}
		clearSessionCookie(w)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/v1/auth/me", withPrincipal(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if principal == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"principal": principal})
	}))

	mux.HandleFunc("/api/v1/session", withPrincipal(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if principal == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"principal": principal})
	}))

	mux.HandleFunc("/api/v1/user/keys", requireUser(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
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
		keys, err := s.ListAPIKeysByOwner(r.Context(), email)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		usageItems, err := s.UsageTopSince(r.Context(), since, 0)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		usageByKey := make(map[string]store.APIUsageSummary, len(usageItems))
		for _, item := range usageItems {
			usageByKey[item.APIKey] = item
		}
		controls, err := s.ListUsageControls(r.Context(), true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		now := time.Now().UTC()
		items := make([]map[string]any, 0, len(keys))
		for _, key := range keys {
			state := key.Status
			if key.ExpiresAt != nil && !key.ExpiresAt.After(now) {
				state = "expired"
			}
			usage := usageByKey[key.Key]
			control := findKeyControl(controls, key.Key, email)
			items = append(items, map[string]any{
				"key":             key.Key,
				"status":          state,
				"expires_at":      key.ExpiresAt,
				"owner_email":     key.OwnerEmail,
				"note":            key.Note,
				"plan_id":         key.PlanID,
				"updated_at":      key.UpdatedAt,
				"total_requests":  usage.TotalRequests,
				"failed_requests": usage.FailedRequests,
				"total_tokens":    usage.TotalTokens,
				"control":         controlView(control, usage.TotalRequests, usage.TotalTokens),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "items": items})
	}))

	mux.HandleFunc("/api/v1/user/usage", requireUser(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
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
		keys, err := s.ListAPIKeysByOwner(r.Context(), email)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		usageItems, err := s.UsageTopSince(r.Context(), since, 0)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		usageByKey := make(map[string]store.APIUsageSummary, len(usageItems))
		for _, item := range usageItems {
			usageByKey[item.APIKey] = item
		}
		controls, err := s.ListUsageControls(r.Context(), true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		userControl := findUserControl(controls, email)
		userUsage, err := s.UsageForUserSince(r.Context(), email, since)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		keyItems := make([]map[string]any, 0, len(keys))
		for _, key := range keys {
			usage := usageByKey[key.Key]
			control := findKeyControl(controls, key.Key, email)
			keyItems = append(keyItems, map[string]any{
				"key":             key.Key,
				"total_requests":  usage.TotalRequests,
				"failed_requests": usage.FailedRequests,
				"total_tokens":    usage.TotalTokens,
				"control":         controlView(control, usage.TotalRequests, usage.TotalTokens),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"since":   since,
			"summary": summary,
			"usage": map[string]any{
				"total_requests":  userUsage.TotalRequests,
				"failed_requests": userUsage.FailedRequests,
				"total_tokens":    userUsage.TotalTokens,
				"control":         controlView(userControl, userUsage.TotalRequests, userUsage.TotalTokens),
			},
			"keys": keyItems,
		})
	}))

	mux.HandleFunc("/api/v1/purchase-requests", requireUser(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		email := strings.TrimSpace(principal.Email)
		if email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "principal email is not set"})
			return
		}
		var req struct {
			PlanID string `json:"plan_id"`
			Plan   string `json:"plan"`
			Note   string `json:"note"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		planID := strings.TrimSpace(req.PlanID)
		if planID == "" {
			planID = strings.TrimSpace(req.Plan)
		}
		item, err := s.CreatePurchaseRequest(r.Context(), email, planID, req.Note, actor)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		_ = s.InsertAuditLog(r.Context(), actor, "purchase_request_create", fmt.Sprintf("id=%d email=%s", item.ID, item.RequesterEmail))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": item})
	}))

	mux.HandleFunc("/api/v1/purchase-requests/mine", requireUser(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		email := strings.TrimSpace(principal.Email)
		if email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "principal email is not set"})
			return
		}
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.ListPurchaseRequests(r.Context(), email, "", limit)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))

	mux.HandleFunc("/api/v1/admin/usage/overview", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		allKeys, err := s.UsageTopSince(r.Context(), since, 0)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		totalRequests := int64(0)
		totalFailed := int64(0)
		totalTokens := int64(0)
		for _, item := range allKeys {
			totalRequests += item.TotalRequests
			totalFailed += item.FailedRequests
			totalTokens += item.TotalTokens
		}
		topKeys, err := s.UsageTopSince(r.Context(), since, 20)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		topUsers, err := s.UsageUsersSince(r.Context(), since, 20)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"since": since,
			"totals": map[string]any{
				"total_requests":  totalRequests,
				"failed_requests": totalFailed,
				"total_tokens":    totalTokens,
			},
			"top_keys":  topKeys,
			"top_users": topUsers,
		})
	}))

	mux.HandleFunc("/api/v1/admin/usage/users", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.UsageUsersSince(r.Context(), since, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "items": items})
	}))

	mux.HandleFunc("/api/v1/admin/usage/users/", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		rawEmail := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/usage/users/")
		rawEmail = strings.TrimSpace(rawEmail)
		if rawEmail == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing email"})
			return
		}
		email, err := url.PathUnescape(rawEmail)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid email path"})
			return
		}
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		usage, err := s.UsageForUserSince(r.Context(), email, since)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		keys, err := s.ListAPIKeysByOwner(r.Context(), email)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		allUsage, err := s.UsageTopSince(r.Context(), since, 0)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		usageByKey := make(map[string]store.APIUsageSummary, len(allUsage))
		for _, item := range allUsage {
			usageByKey[item.APIKey] = item
		}
		keyItems := make([]map[string]any, 0, len(keys))
		for _, key := range keys {
			item := usageByKey[key.Key]
			keyItems = append(keyItems, map[string]any{
				"key":             key.Key,
				"status":          key.Status,
				"expires_at":      key.ExpiresAt,
				"total_requests":  item.TotalRequests,
				"failed_requests": item.FailedRequests,
				"total_tokens":    item.TotalTokens,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"since": since, "item": usage, "keys": keyItems})
	}))

	mux.HandleFunc("/api/v1/admin/purchase-requests", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		switch r.Method {
		case http.MethodGet:
			status := strings.TrimSpace(r.URL.Query().Get("status"))
			email := strings.TrimSpace(r.URL.Query().Get("email"))
			limit := parseLimit(r.URL.Query().Get("limit"), 200)
			items, err := s.ListPurchaseRequests(r.Context(), email, status, limit)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": items})
		case http.MethodPatch:
			var req struct {
				ID         int64  `json:"id"`
				Status     string `json:"status"`
				ReviewNote string `json:"review_note"`
			}
			if err := decodeJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			item, err := s.UpdatePurchaseRequestStatus(r.Context(), req.ID, req.Status, req.ReviewNote, actor)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			if item == nil {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "purchase request not found"})
				return
			}
			if strings.EqualFold(item.Status, store.PurchaseRequestStatusApproved) {
				if syncErr := reconciler.SyncKeys(r.Context()); syncErr != nil {
					_ = s.InsertAuditLog(r.Context(), actor, "purchase_request_review", fmt.Sprintf("id=%d status=%s sync_error=%v", item.ID, item.Status, syncErr))
					writeJSON(w, http.StatusBadGateway, map[string]any{
						"ok":      true,
						"item":    item,
						"warning": "approved locally, sync pending retry",
						"error":   syncErr.Error(),
					})
					return
				}
			}
			_ = s.InsertAuditLog(r.Context(), actor, "purchase_request_review", fmt.Sprintf("id=%d status=%s", item.ID, item.Status))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": item})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/api/v1/admin/usage-controls", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		switch r.Method {
		case http.MethodGet:
			enabledOnly := parseQueryBool(r.URL.Query().Get("enabled_only"), false)
			items, err := s.ListUsageControls(r.Context(), enabledOnly)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": items})
		case http.MethodPost:
			var req struct {
				ScopeType     string `json:"scope_type"`
				ScopeValue    string `json:"scope_value"`
				WindowSeconds int64  `json:"window_seconds"`
				MaxRequests   *int64 `json:"max_requests"`
				MaxTokens     *int64 `json:"max_tokens"`
				Action        string `json:"action"`
				Enabled       *bool  `json:"enabled"`
				Note          string `json:"note"`
			}
			if err := decodeJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			item, err := s.CreateUsageControl(r.Context(), req.ScopeType, req.ScopeValue, req.WindowSeconds, req.MaxRequests, req.MaxTokens, req.Action, enabled, req.Note, actor)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			_ = s.InsertAuditLog(r.Context(), actor, "usage_control_create", fmt.Sprintf("id=%d scope=%s:%s", item.ID, item.ScopeType, item.ScopeValue))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": item})
		case http.MethodPatch:
			var req struct {
				ID            int64  `json:"id"`
				ScopeType     string `json:"scope_type"`
				ScopeValue    string `json:"scope_value"`
				WindowSeconds int64  `json:"window_seconds"`
				MaxRequests   *int64 `json:"max_requests"`
				MaxTokens     *int64 `json:"max_tokens"`
				Action        string `json:"action"`
				Enabled       bool   `json:"enabled"`
				Note          string `json:"note"`
			}
			if err := decodeJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			item, err := s.UpdateUsageControl(r.Context(), req.ID, req.ScopeType, req.ScopeValue, req.WindowSeconds, req.MaxRequests, req.MaxTokens, req.Action, req.Enabled, req.Note, actor)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			if item == nil {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "usage control not found"})
				return
			}
			_ = s.InsertAuditLog(r.Context(), actor, "usage_control_update", fmt.Sprintf("id=%d scope=%s:%s", item.ID, item.ScopeType, item.ScopeValue))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "item": item})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/api/v1/admin/usage-controls/evaluate-now", requireAdmin(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		actor := principalActor(principal)
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		results, keysSynced, err := reconciler.EvaluateUsageControlsNow(r.Context(), actor)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "results": results, "keys_synced": keysSynced})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "results": results, "keys_synced": keysSynced})
	}))

	mux.HandleFunc("/api/v1/plans", withPrincipal(func(w http.ResponseWriter, r *http.Request, principal *store.Principal) {
		if principal == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		items, err := s.ListPlanCatalog(r.Context(), true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))

	mux.HandleFunc("/api/v1/admin/users", requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *store.Principal) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		role := strings.TrimSpace(r.URL.Query().Get("role"))
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		limit := parseLimit(r.URL.Query().Get("limit"), 100)
		items, err := s.ListUsers(r.Context(), role, status, q, limit)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}))

	mux.HandleFunc("/api/v1/admin/keys", forwardToLegacy("/keys"))
	mux.HandleFunc("/api/v1/admin/keys/status", forwardToLegacy("/keys/status"))
	mux.HandleFunc("/api/v1/admin/keys/expiry", forwardToLegacy("/keys/expiry"))
	mux.HandleFunc("/api/v1/admin/identities", forwardToLegacy("/identities"))

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
