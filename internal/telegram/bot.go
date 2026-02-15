package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/reconcile"
	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
)

type Bot struct {
	token      string
	apiBaseURL string
	http       *http.Client
	store      *store.Store
	manager    *reconcile.Manager
	interval   time.Duration

	allowedChats map[int64]struct{}
	allowedUsers map[int64]struct{}
	offset       int64
}

func New(token string, pollInterval time.Duration, allowedChatIDs, allowedUserIDs []int64, s *store.Store, m *reconcile.Manager) *Bot {
	if pollInterval <= 0 {
		pollInterval = 3 * time.Second
	}
	b := &Bot{
		token:        strings.TrimSpace(token),
		http:         &http.Client{Timeout: 25 * time.Second},
		store:        s,
		manager:      m,
		interval:     pollInterval,
		allowedChats: make(map[int64]struct{}, len(allowedChatIDs)),
		allowedUsers: make(map[int64]struct{}, len(allowedUserIDs)),
	}
	for _, id := range allowedChatIDs {
		b.allowedChats[id] = struct{}{}
	}
	for _, id := range allowedUserIDs {
		b.allowedUsers[id] = struct{}{}
	}
	if b.token != "" {
		b.apiBaseURL = "https://api.telegram.org/bot" + b.token
	}
	return b
}

func (b *Bot) Enabled() bool { return b != nil && b.token != "" }

func (b *Bot) Run(ctx context.Context) {
	if !b.Enabled() {
		return
	}
	if err := b.bootstrapOffset(ctx); err != nil {
		log.Printf("[WARN] telegram bootstrap failed: %v", err)
	}
	if len(b.allowedChats) == 0 && len(b.allowedUsers) == 0 {
		log.Printf("[WARN] telegram allowlist is empty; all chats/users can execute commands")
	}
	log.Printf("[INFO] telegram bot started")
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := b.pollOnce(ctx); err != nil {
				log.Printf("[WARN] telegram poll failed: %v", err)
			}
		}
	}
}

type updatesResponse struct {
	OK     bool           `json:"ok"`
	Result []updateRecord `json:"result"`
}

type updateRecord struct {
	UpdateID int64        `json:"update_id"`
	Message  *messageBody `json:"message"`
}

type messageBody struct {
	MessageID int64 `json:"message_id"`
	From      struct {
		ID int64 `json:"id"`
	} `json:"from"`
	Chat struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	Text string `json:"text"`
}

func (b *Bot) pollOnce(ctx context.Context) error {
	if !b.Enabled() {
		return nil
	}
	updates, err := b.fetchUpdates(ctx, b.offset)
	if err != nil {
		return err
	}
	for _, upd := range updates {
		if upd.UpdateID >= b.offset {
			b.offset = upd.UpdateID + 1
		}
		if upd.Message == nil {
			continue
		}
		b.handleMessage(ctx, upd.Message)
	}
	return nil
}

func (b *Bot) bootstrapOffset(ctx context.Context) error {
	updates, err := b.fetchUpdates(ctx, -1)
	if err != nil {
		return err
	}
	for _, upd := range updates {
		if upd.UpdateID >= b.offset {
			b.offset = upd.UpdateID + 1
		}
	}
	return nil
}

func (b *Bot) fetchUpdates(ctx context.Context, offset int64) ([]updateRecord, error) {
	query := url.Values{}
	query.Set("timeout", "0")
	query.Set("limit", "20")
	if offset != 0 {
		query.Set("offset", strconv.FormatInt(offset, 10))
	}
	endpoint := b.apiBaseURL + "/getUpdates?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getUpdates status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var updates updatesResponse
	if err := json.Unmarshal(body, &updates); err != nil {
		return nil, fmt.Errorf("decode updates: %w", err)
	}
	return updates.Result, nil
}

func (b *Bot) handleMessage(ctx context.Context, msg *messageBody) {
	if msg == nil {
		return
	}
	chatID := msg.Chat.ID
	userID := msg.From.ID
	if !b.isAllowed(chatID, userID) {
		_ = b.sendMessage(ctx, chatID, "Access denied.")
		return
	}
	text := strings.TrimSpace(msg.Text)
	if text == "" || !strings.HasPrefix(text, "/") {
		return
	}
	response := b.executeCommand(ctx, text, chatID, userID)
	if strings.TrimSpace(response) != "" {
		_ = b.sendMessage(ctx, chatID, response)
	}
}

func (b *Bot) isAllowed(chatID, userID int64) bool {
	chatAllowed := len(b.allowedChats) == 0
	if !chatAllowed {
		_, chatAllowed = b.allowedChats[chatID]
	}
	userAllowed := len(b.allowedUsers) == 0
	if !userAllowed {
		_, userAllowed = b.allowedUsers[userID]
	}
	return chatAllowed && userAllowed
}

func (b *Bot) executeCommand(ctx context.Context, text string, chatID, userID int64) string {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return ""
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]
	actor := fmt.Sprintf("tg:user=%d,chat=%d", userID, chatID)

	switch cmd {
	case "/help", "/start":
		return strings.Join([]string{
			"Commands:",
			"/key_add <key> <email> <ttl|expires_at> [note]",
			"/key_extend <key> <ttl|expires_at>",
			"/key_disable <key>",
			"/key_enable <key>",
			"/key_delete <key>",
			"/key_list [active|expired|all]",
			"/usage_key <key> [24h|7d|duration]",
			"/usage_top [24h|7d|duration]",
			"/me <email> [24h|7d|duration]",
			"/recharge <email> [plan_or_note]",
			"/sync_now",
			"/status",
		}, "\n")
	case "/key_add":
		if len(args) < 3 {
			return "Usage: /key_add <key> <email> <ttl|expires_at> [note]"
		}
		key := args[0]
		email := strings.TrimSpace(args[1])
		if !isLikelyEmailToken(email) {
			return "Invalid email"
		}
		expires, err := parseExpiryToken(args[2])
		if err != nil {
			return "Invalid expiry: " + err.Error()
		}
		note := ""
		if len(args) > 3 {
			note = strings.Join(args[3:], " ")
		}
		if err := b.store.UpsertAPIKey(ctx, key, expires, email, note, actor); err != nil {
			return "Failed: " + err.Error()
		}
		_ = b.store.InsertAuditLog(ctx, actor, "key_add", fmt.Sprintf("key=%s email=%s", key, strings.ToLower(strings.TrimSpace(email))))
		if err := b.manager.SyncKeys(ctx); err != nil {
			return "Saved, but sync failed: " + err.Error()
		}
		return "OK: key added/updated and synced"
	case "/key_extend":
		if len(args) < 2 {
			return "Usage: /key_extend <key> <ttl|expires_at>"
		}
		expires, err := parseExpiryToken(args[1])
		if err != nil {
			return "Invalid expiry: " + err.Error()
		}
		updated, err := b.store.ExtendAPIKey(ctx, args[0], expires)
		if err != nil {
			return "Failed: " + err.Error()
		}
		if !updated {
			return "Key not found"
		}
		_ = b.store.InsertAuditLog(ctx, actor, "key_extend", args[0])
		if err := b.manager.SyncKeys(ctx); err != nil {
			return "Updated, but sync failed: " + err.Error()
		}
		return "OK: key expiry updated and synced"
	case "/key_disable":
		if len(args) < 1 {
			return "Usage: /key_disable <key>"
		}
		updated, err := b.store.SetAPIKeyStatus(ctx, args[0], store.KeyStatusDisabled)
		if err != nil {
			return "Failed: " + err.Error()
		}
		if !updated {
			return "Key not found"
		}
		_ = b.store.InsertAuditLog(ctx, actor, "key_disable", args[0])
		if err := b.manager.SyncKeys(ctx); err != nil {
			return "Disabled, but sync failed: " + err.Error()
		}
		return "OK: key disabled and synced"
	case "/key_enable":
		if len(args) < 1 {
			return "Usage: /key_enable <key>"
		}
		updated, err := b.store.SetAPIKeyStatus(ctx, args[0], store.KeyStatusActive)
		if err != nil {
			return "Failed: " + err.Error()
		}
		if !updated {
			return "Key not found"
		}
		_ = b.store.InsertAuditLog(ctx, actor, "key_enable", args[0])
		if err := b.manager.SyncKeys(ctx); err != nil {
			return "Enabled, but sync failed: " + err.Error()
		}
		return "OK: key enabled and synced"
	case "/key_delete":
		if len(args) < 1 {
			return "Usage: /key_delete <key>"
		}
		deleted, err := b.store.DeleteAPIKey(ctx, args[0])
		if err != nil {
			return "Failed: " + err.Error()
		}
		if !deleted {
			return "Key not found"
		}
		_ = b.store.InsertAuditLog(ctx, actor, "key_delete", args[0])
		if err := b.manager.SyncKeys(ctx); err != nil {
			return "Deleted, but sync failed: " + err.Error()
		}
		return "OK: key deleted and synced"
	case "/key_list":
		filter := "all"
		if len(args) > 0 {
			filter = strings.ToLower(strings.TrimSpace(args[0]))
		}
		items, err := b.store.ListAPIKeys(ctx)
		if err != nil {
			return "Failed: " + err.Error()
		}
		if len(items) == 0 {
			return "No keys."
		}
		now := time.Now().UTC()
		lines := []string{"API keys:"}
		for _, item := range items {
			expired := item.ExpiresAt != nil && !item.ExpiresAt.After(now)
			state := item.Status
			if expired {
				state = "expired"
			}
			switch filter {
			case "active":
				if state != store.KeyStatusActive {
					continue
				}
			case "expired":
				if state != "expired" {
					continue
				}
			case "all":
			default:
			}
			expiresStr := "never"
			if item.ExpiresAt != nil {
				expiresStr = item.ExpiresAt.UTC().Format(time.RFC3339)
			}
			owner := strings.TrimSpace(item.OwnerEmail)
			if owner == "" {
				owner = "-"
			}
			lines = append(lines, fmt.Sprintf("- %s | owner=%s | status=%s | expires=%s", maskKey(item.Key), owner, state, expiresStr))
		}
		if len(lines) == 1 {
			return "No keys for selected filter."
		}
		return strings.Join(lines, "\n")
	case "/usage_key":
		if len(args) < 1 {
			return "Usage: /usage_key <key> [24h|7d|duration]"
		}
		since := time.Now().UTC().Add(-24 * time.Hour)
		if len(args) > 1 {
			parsed, err := parseSinceToken(args[1])
			if err != nil {
				return "Invalid duration: " + err.Error()
			}
			since = parsed
		}
		summary, err := b.store.UsageForKeySince(ctx, args[0], since)
		if err != nil {
			return "Failed: " + err.Error()
		}
		return fmt.Sprintf("usage for %s since %s\nrequests=%d failed=%d tokens=%d", maskKey(summary.APIKey), since.Format(time.RFC3339), summary.TotalRequests, summary.FailedRequests, summary.TotalTokens)
	case "/usage_top":
		since := time.Now().UTC().Add(-24 * time.Hour)
		if len(args) > 0 {
			parsed, err := parseSinceToken(args[0])
			if err != nil {
				return "Invalid duration: " + err.Error()
			}
			since = parsed
		}
		items, err := b.store.UsageTopSince(ctx, since, 10)
		if err != nil {
			return "Failed: " + err.Error()
		}
		if len(items) == 0 {
			return "No usage data in range."
		}
		lines := []string{fmt.Sprintf("Top usage since %s:", since.Format(time.RFC3339))}
		for _, item := range items {
			lines = append(lines, fmt.Sprintf("- %s req=%d fail=%d tok=%d", maskKey(item.APIKey), item.TotalRequests, item.FailedRequests, item.TotalTokens))
		}
		return strings.Join(lines, "\n")
	case "/me":
		if len(args) < 1 {
			return "Usage: /me <email> [24h|7d|duration]"
		}
		email := strings.TrimSpace(args[0])
		if !isLikelyEmailToken(email) {
			return "Invalid email"
		}
		since := time.Now().UTC().Add(-24 * time.Hour)
		if len(args) > 1 {
			parsed, err := parseSinceToken(args[1])
			if err != nil {
				return "Invalid duration: " + err.Error()
			}
			since = parsed
		}
		summary, err := b.store.AccountSummarySince(ctx, email, since, time.Now().UTC())
		if err != nil {
			return "Failed: " + err.Error()
		}
		valid := "none"
		if summary.Unlimited {
			valid = "unlimited"
		} else if summary.ValidUntil != nil {
			valid = fmt.Sprintf("%d days (until %s)", summary.ValidDays, summary.ValidUntil.UTC().Format(time.RFC3339))
		}
		keys := "none"
		if len(summary.Keys) > 0 {
			masked := make([]string, 0, len(summary.Keys))
			for _, key := range summary.Keys {
				masked = append(masked, maskKey(key))
			}
			keys = strings.Join(masked, ",")
		}
		return fmt.Sprintf("account=%s\nkeys=%s\nvalid=%s\nusage since %s\nrequests=%d failed=%d tokens=%d", summary.Email, keys, valid, since.Format(time.RFC3339), summary.TotalRequests, summary.FailedRequests, summary.TotalTokens)
	case "/recharge":
		if len(args) < 1 {
			return "Usage: /recharge <email> [plan_or_note]"
		}
		email := strings.TrimSpace(args[0])
		if !isLikelyEmailToken(email) {
			return "Invalid email"
		}
		note := ""
		if len(args) > 1 {
			note = strings.Join(args[1:], " ")
		}
		detail := fmt.Sprintf("email=%s note=%s", strings.ToLower(email), strings.TrimSpace(note))
		_ = b.store.InsertAuditLog(ctx, actor, "recharge_request_placeholder", detail)
		return "Recharge request recorded (placeholder). Payment integration not enabled yet."
	case "/sync_now":
		if err := b.manager.ForceSync(ctx); err != nil {
			return "Sync failed: " + err.Error()
		}
		_ = b.store.InsertAuditLog(ctx, actor, "sync_now", "manual trigger")
		return "OK: sync completed"
	case "/status":
		status, err := b.manager.Status(ctx)
		if err != nil {
			return "Failed: " + err.Error()
		}
		lines := []string{fmt.Sprintf("healthy=%t", status.Healthy)}
		if status.LastKeySyncAt != nil {
			lines = append(lines, "last_key_sync="+status.LastKeySyncAt.UTC().Format(time.RFC3339))
		}
		if status.LastUsageSnapshotAt != nil {
			lines = append(lines, "last_usage_snapshot="+status.LastUsageSnapshotAt.UTC().Format(time.RFC3339))
		}
		if status.LastRecoveryImportAt != nil {
			lines = append(lines, "last_recovery_import="+status.LastRecoveryImportAt.UTC().Format(time.RFC3339))
		}
		if status.Message != "" {
			lines = append(lines, "message="+status.Message)
		}
		return strings.Join(lines, "\n")
	default:
		return "Unknown command. Use /help"
	}
}

func (b *Bot) sendMessage(ctx context.Context, chatID int64, text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	payload := map[string]any{
		"chat_id": chatID,
		"text":    text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.apiBaseURL+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sendMessage status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func maskKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func parseSinceToken(raw string) (time.Time, error) {
	now := time.Now().UTC()
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch raw {
	case "":
		return now.Add(-24 * time.Hour), nil
	case "24h":
		return now.Add(-24 * time.Hour), nil
	case "7d":
		return now.Add(-7 * 24 * time.Hour), nil
	}
	dur, err := time.ParseDuration(raw)
	if err != nil || dur <= 0 {
		return time.Time{}, fmt.Errorf("unsupported duration token %q", raw)
	}
	return now.Add(-dur), nil
}

func parseExpiryToken(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("expiry is required")
	}
	lower := strings.ToLower(raw)
	if lower == "none" || lower == "never" {
		return nil, nil
	}
	if strings.HasSuffix(lower, "d") && len(lower) > 1 {
		dayNum := strings.TrimSuffix(lower, "d")
		n, err := strconv.Atoi(dayNum)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid day ttl")
		}
		t := time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour)
		return &t, nil
	}
	if dur, err := time.ParseDuration(lower); err == nil {
		if dur <= 0 {
			return nil, fmt.Errorf("duration must be positive")
		}
		t := time.Now().UTC().Add(dur)
		return &t, nil
	}
	formats := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"}
	for _, format := range formats {
		if ts, err := time.Parse(format, raw); err == nil {
			t := ts.UTC()
			return &t, nil
		}
	}
	return nil, fmt.Errorf("cannot parse expiry token")
}

func isLikelyEmailToken(raw string) bool {
	email := strings.ToLower(strings.TrimSpace(raw))
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
