import { useEffect, useMemo, useState } from 'react'
import { deleteAdminKey, listAdminKeys, updateAdminKeyExpiry, updateAdminKeyStatus } from '../../api'
import type { AdminKeyItem } from '../../types'

function toLocalInputValue(iso?: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function toISOFromLocalInput(localValue: string): string {
  return new Date(localValue).toISOString()
}

export function AdminKeysPage() {
  const [items, setItems] = useState<AdminKeyItem[]>([])
  const [filter, setFilter] = useState('all')
  const [msg, setMsg] = useState('')
  const [busyKey, setBusyKey] = useState('')
  const [expiryDraft, setExpiryDraft] = useState<Record<string, string>>({})

  const load = async () => {
    const data = await listAdminKeys(filter)
    const next = data.items || []
    setItems(next)
    setExpiryDraft((prev) => {
      const draft = { ...prev }
      for (const item of next) {
        if (!draft[item.key]) {
          draft[item.key] = toLocalInputValue(item.expires_at)
        }
      }
      return draft
    })
  }

  useEffect(() => {
    load()
  }, [filter])

  const counts = useMemo(() => {
    let active = 0
    let disabled = 0
    let expired = 0
    for (const item of items) {
      if (item.status === 'active') active++
      else if (item.status === 'disabled') disabled++
      else if (item.status === 'expired') expired++
    }
    return { active, disabled, expired }
  }, [items])

  const run = async (key: string, fn: () => Promise<unknown>, success: string) => {
    setBusyKey(key)
    setMsg('')
    try {
      await fn()
      setMsg(success)
      await load()
    } catch (e: any) {
      setMsg(`操作失败: ${String(e?.message || e)}`)
    } finally {
      setBusyKey('')
    }
  }

  return (
    <div>
      <h1>Keys 管理</h1>
      <div className="row">
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">all</option>
          <option value="active">active</option>
          <option value="expired">expired</option>
        </select>
        <button onClick={load}>刷新</button>
      </div>
      <p className="msg">{msg}</p>
      <p>
        总数={items.length} / active={counts.active} / disabled={counts.disabled} / expired={counts.expired}
      </p>

      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Status</th>
            <th>Owner</th>
            <th>Plan</th>
            <th>Expires</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const isBusy = busyKey === item.key
            const nextStatus = item.status === 'active' ? 'disabled' : 'active'
            return (
              <tr key={item.key}>
                <td><code>{item.key}</code></td>
                <td>{item.status}</td>
                <td>{item.owner_email || '-'}</td>
                <td>{item.plan_id || '-'}</td>
                <td>
                  <input
                    type="datetime-local"
                    value={expiryDraft[item.key] || ''}
                    onChange={(e) => setExpiryDraft((prev) => ({ ...prev, [item.key]: e.target.value }))}
                  />
                </td>
                <td>
                  <div className="row">
                    <button
                      disabled={isBusy}
                      onClick={() =>
                        run(item.key, () => updateAdminKeyStatus(item.key, nextStatus), `已更新状态: ${item.key} -> ${nextStatus}`)
                      }
                    >
                      {nextStatus === 'active' ? '启用' : '禁用'}
                    </button>
                    <button
                      className="secondary"
                      disabled={isBusy || !expiryDraft[item.key]}
                      onClick={() =>
                        run(
                          item.key,
                          () => updateAdminKeyExpiry(item.key, toISOFromLocalInput(expiryDraft[item.key])),
                          `已更新过期时间: ${item.key}`,
                        )
                      }
                    >
                      改过期
                    </button>
                    <button
                      className="secondary"
                      disabled={isBusy}
                      onClick={() => {
                        if (!window.confirm(`确认删除 key: ${item.key} ?`)) return
                        run(item.key, () => deleteAdminKey(item.key), `已删除 key: ${item.key}`)
                      }}
                    >
                      删除
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
