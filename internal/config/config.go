package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime settings for cliproxy-access-manager.
type Config struct {
	HTTPAddr                               string
	DataDir                                string
	DatabasePath                           string
	LogLevel                               string
	ManagementBaseURL                      string
	ManagementKey                          string
	ManagementPollInterval                 time.Duration
	UsageSyncInterval                      time.Duration
	RecoveryInterval                       time.Duration
	UpdateCheckEnabled                     bool
	UpdateCheckTime                        string
	ManagementLatestVersionURL             string
	UpdateApplyCommand                     string
	UpdateAutoApplyEnabled                 bool
	UpdateAllowCustomCommand               bool
	TelegramBotToken                       string
	TelegramAllowedChatIDs                 []int64
	TelegramAllowedUserIDs                 []int64
	TelegramPollInterval                   time.Duration
	TelegramDenyHighRiskWhenAllowlistEmpty bool
	AllowUnsafeDisableTLS                  bool
	HTTPAuthToken                          string
	HTTPUpdateRequireAuth                  bool
	DBRecoverOnCorrupt                     bool
	RecoverySnapshotScanLimit              int
	AuthSessionTTL                         time.Duration
	AuthCookieName                         string
	AuthCookieSecure                       bool
	AdminEmail                             string
	AdminPassword                          string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:                               envOrDefault("APIM_HTTP_ADDR", "127.0.0.1:8390"),
		DataDir:                                envOrDefault("APIM_DATA_DIR", "./data"),
		LogLevel:                               strings.ToLower(envOrDefault("APIM_LOG_LEVEL", "info")),
		ManagementBaseURL:                      strings.TrimSpace(envOrDefault("CLIPROXY_MGMT_BASE_URL", "http://127.0.0.1:8317")),
		ManagementKey:                          strings.TrimSpace(os.Getenv("CLIPROXY_MGMT_KEY")),
		ManagementPollInterval:                 envDurationOrDefault("APIM_KEY_SYNC_INTERVAL", 30*time.Second),
		UsageSyncInterval:                      envDurationOrDefault("APIM_USAGE_SYNC_INTERVAL", 2*time.Minute),
		RecoveryInterval:                       envDurationOrDefault("APIM_RECOVERY_CHECK_INTERVAL", 60*time.Second),
		UpdateCheckEnabled:                     envBoolOrDefault("APIM_UPDATE_CHECK_ENABLED", true),
		UpdateCheckTime:                        strings.TrimSpace(envOrDefault("APIM_UPDATE_CHECK_TIME", "04:00")),
		ManagementLatestVersionURL:             strings.TrimSpace(envOrDefault("APIM_MANAGEMENT_LATEST_VERSION_URL", "/v0/management/latest-version")),
		UpdateApplyCommand:                     strings.TrimSpace(os.Getenv("APIM_UPDATE_APPLY_COMMAND")),
		UpdateAutoApplyEnabled:                 envBoolOrDefault("APIM_UPDATE_AUTO_APPLY_ENABLED", false),
		UpdateAllowCustomCommand:               envBoolOrDefault("APIM_UPDATE_ALLOW_CUSTOM_COMMAND", false),
		TelegramBotToken:                       strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")),
		TelegramPollInterval:                   envDurationOrDefault("TELEGRAM_POLL_INTERVAL", 3*time.Second),
		TelegramDenyHighRiskWhenAllowlistEmpty: envBoolOrDefault("APIM_TELEGRAM_DENY_HIGH_RISK_WHEN_ALLOWLIST_EMPTY", true),
		AllowUnsafeDisableTLS:                  envBoolOrDefault("APIM_INSECURE_SKIP_TLS_VERIFY", false),
		HTTPAuthToken:                          strings.TrimSpace(os.Getenv("APIM_HTTP_AUTH_TOKEN")),
		HTTPUpdateRequireAuth:                  envBoolOrDefault("APIM_HTTP_UPDATE_REQUIRE_AUTH", true),
		DBRecoverOnCorrupt:                     envBoolOrDefault("APIM_DB_RECOVER_ON_CORRUPT", true),
		RecoverySnapshotScanLimit:              envIntOrDefault("APIM_RECOVERY_SNAPSHOT_SCAN_LIMIT", 10),
		AuthSessionTTL:                         envDurationOrDefault("APIM_AUTH_SESSION_TTL", 24*time.Hour),
		AuthCookieName:                         strings.TrimSpace(envOrDefault("APIM_AUTH_COOKIE_NAME", "apim_session")),
		AuthCookieSecure:                       envBoolOrDefault("APIM_AUTH_COOKIE_SECURE", false),
		AdminEmail:                             normalizeOptionalEmail(os.Getenv("APIM_ADMIN_EMAIL")),
		AdminPassword:                          strings.TrimSpace(os.Getenv("APIM_ADMIN_PASSWORD")),
	}

	if cfg.ManagementBaseURL == "" {
		return Config{}, fmt.Errorf("CLIPROXY_MGMT_BASE_URL is required")
	}
	if cfg.ManagementKey == "" {
		return Config{}, fmt.Errorf("CLIPROXY_MGMT_KEY is required")
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return Config{}, fmt.Errorf("create data dir: %w", err)
	}
	cfg.DatabasePath = envOrDefault("APIM_DB_PATH", cfg.DataDir+"/apim.db")
	dbDir := filepath.Dir(cfg.DatabasePath)
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return Config{}, fmt.Errorf("create db dir: %w", err)
	}

	allowedChats, err := parseInt64CSV(os.Getenv("TELEGRAM_ALLOWED_CHAT_IDS"))
	if err != nil {
		return Config{}, fmt.Errorf("parse TELEGRAM_ALLOWED_CHAT_IDS: %w", err)
	}
	cfg.TelegramAllowedChatIDs = allowedChats

	allowedUsers, err := parseInt64CSV(os.Getenv("TELEGRAM_ALLOWED_USER_IDS"))
	if err != nil {
		return Config{}, fmt.Errorf("parse TELEGRAM_ALLOWED_USER_IDS: %w", err)
	}
	cfg.TelegramAllowedUserIDs = allowedUsers

	if !isHHMM(cfg.UpdateCheckTime) {
		return Config{}, fmt.Errorf("invalid APIM_UPDATE_CHECK_TIME, expected HH:MM")
	}
	if cfg.RecoverySnapshotScanLimit <= 0 {
		cfg.RecoverySnapshotScanLimit = 10
	}
	if cfg.AuthSessionTTL <= 0 {
		cfg.AuthSessionTTL = 24 * time.Hour
	}
	if strings.TrimSpace(cfg.AuthCookieName) == "" {
		cfg.AuthCookieName = "apim_session"
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	dur, err := time.ParseDuration(value)
	if err != nil || dur <= 0 {
		return fallback
	}
	return dur
}

func envBoolOrDefault(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	if value == "1" || value == "true" || value == "yes" {
		return true
	}
	if value == "0" || value == "false" || value == "no" {
		return false
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseInt64CSV(raw string) ([]int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]int64, 0, len(parts))
	seen := make(map[int64]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid int64 %q", part)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func isHHMM(raw string) bool {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 2 {
		return false
	}
	hh, err := strconv.Atoi(parts[0])
	if err != nil || hh < 0 || hh > 23 {
		return false
	}
	mm, err := strconv.Atoi(parts[1])
	if err != nil || mm < 0 || mm > 59 {
		return false
	}
	return true
}

func normalizeOptionalEmail(raw string) string {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" {
		return ""
	}
	if strings.Count(email, "@") != 1 {
		return ""
	}
	parts := strings.SplitN(email, "@", 2)
	if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}
	if !strings.Contains(parts[1], ".") {
		return ""
	}
	return email
}
