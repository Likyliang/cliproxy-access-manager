package store

import "time"

const (
	KeyStatusActive   = "active"
	KeyStatusDisabled = "disabled"

	IdentityProviderHTTP     = "http"
	IdentityProviderTelegram = "telegram"
	IdentityProviderSession  = "session"

	IdentityRoleAdmin = "admin"
	IdentityRoleUser  = "user"

	IdentityStatusActive   = "active"
	IdentityStatusDisabled = "disabled"

	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"

	PurchaseRequestStatusPending   = "pending"
	PurchaseRequestStatusApproved  = "approved"
	PurchaseRequestStatusRejected  = "rejected"
	PurchaseRequestStatusFulfilled = "fulfilled"
	PurchaseRequestStatusCancelled = "cancelled"

	PurchaseRequestProvisioningPending = "pending"
	PurchaseRequestProvisioningReady   = "ready"
	PurchaseRequestProvisioningFailed  = "failed"

	PlanIDWebChatMonthly    = "web-chat-monthly"
	PlanIDHybridMonthly     = "hybrid-monthly"
	PlanIDHeavyAgentMonthly = "heavy-agent-monthly"

	PlanPersonaWebChat = "web_chat"
	PlanPersonaHybrid  = "hybrid"
	PlanPersonaHeavy   = "heavy_agent"
	PlanBillingMonthly = "monthly"

	UsageControlScopeGlobal = "global"
	UsageControlScopeUser   = "user"
	UsageControlScopeKey    = "key"

	UsageControlActionAuditOnly      = "audit_only"
	UsageControlActionDisableKey     = "disable_key"
	UsageControlActionDisableUserKey = "disable_user_keys"
	UsageControlActionDisableAllKeys = "disable_all_keys"
)

// APIKey represents a managed inbound API key metadata row.
type APIKey struct {
	ID                int64      `json:"id"`
	Key               string     `json:"key"`
	Status            string     `json:"status"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	OwnerEmail        string     `json:"owner_email"`
	Note              string     `json:"note"`
	CreatedBy         string     `json:"created_by"`
	PlanID            string     `json:"plan_id"`
	PlanSnapshotJSON  string     `json:"plan_snapshot_json"`
	PurchaseRequestID *int64     `json:"purchase_request_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
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
	LastUpdateCheckAt     *time.Time
	LastKnownLatest       string
	LastKnownCurrent      string
	LastUpdateStatus      string
	LastUpdateMessage     string
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

// UserUsageSummary is an aggregated usage view by owner email.
type UserUsageSummary struct {
	Email          string
	Keys           []string
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

// Identity maps external auth principals to role/email.
type Identity struct {
	ID        int64
	Provider  string
	Subject   string
	Role      string
	Email     string
	Status    string
	Note      string
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Principal is a resolved request identity.
type Principal struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	UserID   int64  `json:"user_id"`
}

// AuthUser represents a login-capable user account.
type AuthUser struct {
	ID           int64      `json:"id"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	PasswordHash string     `json:"password_hash,omitempty"`
	Status       string     `json:"status"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// AuthSession represents a persisted browser/API session.
type AuthSession struct {
	ID          int64
	SessionHash string
	UserID      int64
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
	LastSeenAt  *time.Time
	ClientIP    string
	UserAgent   string
}

// AuditLog records operator and background actions.
type AuditLog struct {
	ID        int64
	Actor     string
	Action    string
	Detail    string
	CreatedAt time.Time
}

// PurchaseRequest stores user recharge/purchase workflow state.
type PurchaseRequest struct {
	ID                    int64      `json:"id"`
	RequesterEmail        string     `json:"requester_email"`
	Plan                  string     `json:"plan"`
	PlanID                string     `json:"plan_id"`
	PlanSnapshotJSON      string     `json:"plan_snapshot_json"`
	ProvisionedAPIKey     string     `json:"-"`
	ProvisioningStatus    string     `json:"provisioning_status"`
	ActivationAttemptedAt *time.Time `json:"activation_attempted_at,omitempty"`
	Note                  string     `json:"note"`
	Status                string     `json:"status"`
	ReviewNote            string     `json:"review_note"`
	CreatedBy             string     `json:"created_by"`
	ReviewedBy            string     `json:"reviewed_by"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	ReviewedAt            *time.Time `json:"reviewed_at,omitempty"`
}

// PlanCatalogItem defines a structured purchase plan.
type PlanCatalogItem struct {
	ID                     string    `json:"id"`
	Name                   string    `json:"name"`
	Persona                string    `json:"persona"`
	BillingCycle           string    `json:"billing_cycle"`
	MonthlyPriceSuggestion string    `json:"monthly_price_suggestion"`
	IncludedTokensTotal    int64     `json:"included_tokens_total"`
	IncludedRequestsTotal  *int64    `json:"included_requests_total,omitempty"`
	OveragePriceSuggestion string    `json:"overage_price_suggestion"`
	UsageControlAction     string    `json:"usage_control_action"`
	Recommended            bool      `json:"recommended"`
	Enabled                bool      `json:"enabled"`
	DisplayOrder           int64     `json:"display_order"`
	Description            string    `json:"description"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// UsageControl defines usage-limit actions for global/user/key scope.
type UsageControl struct {
	ID            int64
	ScopeType     string
	ScopeValue    string
	WindowSeconds int64
	MaxRequests   *int64
	MaxTokens     *int64
	Action        string
	Enabled       bool
	Note          string
	CreatedBy     string
	UpdatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// UsageControlEvent records each evaluation result and action execution.
type UsageControlEvent struct {
	ID            int64
	ControlID     int64
	ScopeType     string
	ScopeValue    string
	WindowSeconds int64
	UsedRequests  int64
	UsedTokens    int64
	ThresholdReq  *int64
	ThresholdTok  *int64
	Action        string
	Triggered     bool
	Result        string
	ErrorMessage  string
	CreatedAt     time.Time
}

// UsageControlEvaluationResult is returned after evaluating controls.
type UsageControlEvaluationResult struct {
	ControlID     int64
	ScopeType     string
	ScopeValue    string
	WindowSeconds int64
	UsedRequests  int64
	UsedTokens    int64
	Action        string
	Triggered     bool
	Result        string
	ErrorMessage  string
}
