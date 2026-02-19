import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { fetchPrincipal } from '../api'
import type { Principal } from '../types'

type Props = {
  role: 'admin' | 'user'
  children: React.ReactNode
}

export function RequireAuth({ role, children }: Props) {
  const [loading, setLoading] = useState(true)
  const [principal, setPrincipal] = useState<Principal | null>(null)

  useEffect(() => {
    fetchPrincipal()
      .then((p) => setPrincipal(p))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="panel">Loading...</div>
  if (!principal) return <Navigate to="/login" replace />
  if (principal.role !== role) {
    return <Navigate to={principal.role === 'admin' ? '/admin/overview' : '/user/plans'} replace />
  }
  return <>{children}</>
}
