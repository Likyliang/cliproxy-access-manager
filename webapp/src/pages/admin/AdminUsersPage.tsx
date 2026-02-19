import { useEffect, useState } from 'react'
import { listAdminUsers } from '../../api'
import type { AuthUser } from '../../types'

export function AdminUsersPage() {
  const [q, setQ] = useState('')
  const [role, setRole] = useState('')
  const [status, setStatus] = useState('')
  const [items, setItems] = useState<AuthUser[]>([])

  const load = () =>
    listAdminUsers({ q, role, status, limit: 200 }).then((d) => {
      setItems(d.items || [])
    })

  useEffect(() => {
    load()
  }, [])

  return (
    <div>
      <h1>注册用户列表</h1>
      <div className="row">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="q" />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="">all roles</option>
          <option value="admin">admin</option>
          <option value="user">user</option>
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">all status</option>
          <option value="active">active</option>
          <option value="disabled">disabled</option>
        </select>
        <button onClick={load}>筛选</button>
      </div>
      <table>
        <thead>
          <tr><th>ID</th><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th>Updated</th><th>Last Login</th></tr>
        </thead>
        <tbody>
          {items.map((u) => (
            <tr key={u.id}>
              <td>{u.id}</td>
              <td>{u.email}</td>
              <td>{u.role}</td>
              <td>{u.status}</td>
              <td>{u.created_at}</td>
              <td>{u.updated_at}</td>
              <td>{u.last_login_at || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
