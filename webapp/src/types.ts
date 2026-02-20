export type Principal = {
  role: 'admin' | 'user' | string
  email?: string
  provider?: string
  subject?: string
  user_id?: number
}

export type PlanCatalogItem = {
  id: string
  name: string
  persona: 'web_chat' | 'hybrid' | 'heavy_agent' | string
  billing_cycle: string
  monthly_price_suggestion: string
  included_tokens_total: number
  included_requests_total?: number
  overage_price_suggestion: string
  usage_control_action: string
  recommended: boolean
  enabled: boolean
  display_order: number
  description: string
}

export type PurchaseRequest = {
  id: number
  requester_email: string
  plan: string
  plan_id: string
  months: number
  note: string
  status: string
  review_note: string
  created_at: string
  reviewed_at?: string
  provisioned_api_key?: string
  provisioning_status?: string
}

export type APIKeyItem = {
  key: string
  status: string
  expires_at?: string
  total_requests?: number
  failed_requests?: number
  total_tokens?: number
  control?: {
    max_requests?: number
    max_tokens?: number
    remaining_requests?: number
    remaining_tokens?: number
  }
  plan_id?: string
  owner_email?: string
  note?: string
  updated_at?: string
}

export type UsageOverview = {
  totals?: {
    total_requests: number
    failed_requests: number
    total_tokens: number
  }
  top_users?: Array<{ email: string; total_requests: number; failed_requests: number; total_tokens: number; keys: string[] }>
  top_keys?: Array<{ api_key: string; total_requests: number; failed_requests: number; total_tokens: number }>
}

export type AccountSummary = {
  email: string
  keys: string[]
  total_requests: number
  failed_requests: number
  total_tokens: number
  valid_days: number
  unlimited: boolean
  valid_until?: string
}

export type UsageControlView = {
  scope_type?: string
  scope_value?: string
  window_seconds?: number
  action?: string
  max_requests?: number
  max_tokens?: number
  remaining_requests?: number
  remaining_tokens?: number
}

export type UserUsageResponse = {
  since: string
  summary: AccountSummary
  usage: {
    total_requests: number
    failed_requests: number
    total_tokens: number
    control?: UsageControlView
  }
  keys: Array<{
    key: string
    total_requests: number
    failed_requests: number
    total_tokens: number
    control?: UsageControlView
  }>
}

export type ReconcilerStatus = {
  healthy: boolean
  last_key_sync_at?: string
  last_usage_snapshot_at?: string
  last_recovery_import_at?: string
  last_update_check_at?: string
  last_keys_hash?: string
  last_snapshot_hash?: string
  last_recovery_hash?: string
  current_version?: string
  latest_version?: string
  update_status?: string
  update_message?: string
  update_check_time?: string
  update_apply_mode?: string
  update_command_set?: boolean
  message?: string
}

export type AuthUser = {
  id: number
  email: string
  role: string
  status: string
  created_at: string
  updated_at: string
  last_login_at?: string
}

export type UsageControl = {
  id: number
  scope_type: string
  scope_value: string
  window_seconds: number
  max_requests?: number
  max_tokens?: number
  action: string
  enabled: boolean
  note: string
}
