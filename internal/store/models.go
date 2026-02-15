package store

import "time"

const (
	KeyStatusActive   = "active"
	KeyStatusDisabled = "disabled"
)

// APIKey represents a managed inbound API key metadata row.
type APIKey struct {
	ID         int64
	Key        string
	Status     string
	ExpiresAt  *time.Time
	OwnerEmail string
	Note       string
	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// SyncState stores durable idempotency/recovery markers.
type SyncState struct {
	ID                    int64
	LastAppliedKeysHash   string
	LastAppliedAt         *time.Time
	LastUsageSnapshotHash string
	LastUsageSnapshotAt   *time.Time
	LastRecoverImportHash string
	LastRecoverImportAt   *time.Time
	UpdatedAt             time.Time
}

// UsageSnapshot is a persisted exported payload from cliproxy management endpoint.
type UsageSnapshot struct {
	ID           int64
	SnapshotHash string
	ExportedAt   time.Time
	PayloadJSON  string
	CreatedAt    time.Time
}

// APIUsageSummary is an aggregated view for operator queries.
type APIUsageSummary struct {
	APIKey         string
	TotalRequests  int64
	FailedRequests int64
	TotalTokens    int64
}

// AccountSummary is a user-facing account view keyed by email.
type AccountSummary struct {
	Email          string
	Keys           []string
	TotalRequests  int64
	FailedRequests int64
	TotalTokens    int64
	ValidDays      int64
	Unlimited      bool
	ValidUntil     *time.Time
}

// AuditLog records operator and background actions.
type AuditLog struct {
	ID        int64
	Actor     string
	Action    string
	Detail    string
	CreatedAt time.Time
}
