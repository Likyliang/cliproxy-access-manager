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
