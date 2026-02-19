import type {
  APIKeyItem,
  AuthUser,
  PlanCatalogItem,
  Principal,
  PurchaseRequest,
  UsageControl,
  UsageOverview,
} from './types'

const TOKEN_KEY = 'apim.web.token'

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken(token: string): void {
  if (!token) {
    localStorage.removeItem(TOKEN_KEY)
    return
  }
  localStorage.setItem(TOKEN_KEY, token.trim())
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {})
  if (init.body && !headers.get('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const token = getToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const res = await fetch(path, {
    ...init,
    headers,
    credentials: 'include',
  })

  const text = await res.text()
  const data = text ? JSON.parse(text) : {}
  if (!res.ok) {
    const message = data?.error || `HTTP ${res.status}`
    throw new Error(message)
  }
  return data as T
}

function normalizePrincipal(input: any): Principal | null {
  if (!input || typeof input !== 'object') return null

  const role = String(input.role ?? input.Role ?? '').trim().toLowerCase()
  if (!role) return null

  const provider = String(input.provider ?? input.Provider ?? '').trim()
  const subject = String(input.subject ?? input.Subject ?? '').trim()
  const email = String(input.email ?? input.Email ?? '').trim()
  const rawUserID = input.user_id ?? input.userId ?? input.UserID

  let user_id: number | undefined
  if (rawUserID !== null && rawUserID !== undefined && rawUserID !== '') {
    const n = Number(rawUserID)
    if (Number.isFinite(n)) {
      user_id = n
    }
  }

  return { role, provider, subject, email, user_id }
}

export async function fetchPrincipal(): Promise<Principal | null> {
  try {
    const data = await api<{ principal?: any }>('/api/v1/auth/me')
    return normalizePrincipal(data.principal)
  } catch (err: any) {
    if (String(err?.message || '').includes('401')) return null
    if (String(err?.message || '').toLowerCase().includes('unauthorized')) return null
    return null
  }
}

export async function login(email: string, password: string) {
  return api('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export async function register(email: string, password: string) {
  return api('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export async function logout() {
  try {
    await api('/api/v1/auth/logout', { method: 'POST' })
  } finally {
    setToken('')
  }
}

export async function listPlans() {
  return api<{ items: PlanCatalogItem[] }>('/api/v1/plans')
}

export async function createPurchaseRequest(planId: string, note: string) {
  return api<{ item: PurchaseRequest }>('/api/v1/purchase-requests', {
    method: 'POST',
    body: JSON.stringify({ plan_id: planId, note }),
  })
}

export async function listMyPurchases() {
  return api<{ items: PurchaseRequest[] }>('/api/v1/purchase-requests/mine?limit=100')
}

export async function listMyKeys(since = '24h') {
  return api<{ items: APIKeyItem[] }>(`/api/v1/user/keys?since=${encodeURIComponent(since)}`)
}

export async function getMyUsage(since = '24h') {
  return api<any>(`/api/v1/user/usage?since=${encodeURIComponent(since)}`)
}

export async function getUsageOverview(since = '24h') {
  return api<UsageOverview>(`/api/v1/admin/usage/overview?since=${encodeURIComponent(since)}`)
}

export async function listAdminPurchases(status = '') {
  const q = status ? `?status=${encodeURIComponent(status)}` : ''
  return api<{ items: PurchaseRequest[] }>(`/api/v1/admin/purchase-requests${q}`)
}

export async function updatePurchaseStatus(id: number, status: string, reviewNote: string) {
  return api('/api/v1/admin/purchase-requests', {
    method: 'PATCH',
    body: JSON.stringify({ id, status, review_note: reviewNote }),
  })
}

export async function listAdminUsers(params: { role?: string; status?: string; q?: string; limit?: number } = {}) {
  const usp = new URLSearchParams()
  if (params.role) usp.set('role', params.role)
  if (params.status) usp.set('status', params.status)
  if (params.q) usp.set('q', params.q)
  if (params.limit) usp.set('limit', String(params.limit))
  const query = usp.toString()
  return api<{ items: AuthUser[] }>(`/api/v1/admin/users${query ? `?${query}` : ''}`)
}

export async function listUsageControls() {
  return api<{ items: UsageControl[] }>('/api/v1/admin/usage-controls')
}

export async function createUsageControl(payload: any) {
  return api('/api/v1/admin/usage-controls', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function evaluateUsageControlsNow() {
  return api<{ results: any[]; keys_synced: boolean }>('/api/v1/admin/usage-controls/evaluate-now', {
    method: 'POST',
  })
}
