import { useEffect, useState } from 'react'
import { createUsageControl, evaluateUsageControlsNow, listUsageControls } from '../../api'
import type { UsageControl } from '../../types'

export function AdminUsageControlsPage() {
  const [items, setItems] = useState<UsageControl[]>([])
  const [msg, setMsg] = useState('')

  const [scopeType, setScopeType] = useState('global')
  const [scopeValue, setScopeValue] = useState('')
  const [windowSeconds, setWindowSeconds] = useState(86400)
  const [maxRequests, setMaxRequests] = useState('')
  const [maxTokens, setMaxTokens] = useState('')
  const [action, setAction] = useState('disable_key')
  const [enabled, setEnabled] = useState(true)
  const [note, setNote] = useState('')

  const load = () => listUsageControls().then((d) => setItems(d.items || []))

  useEffect(() => {
    load()
  }, [])

  return (
    <div>
      <h1>配额控制</h1>
      <div className="row">
        <button onClick={load}>刷新</button>
        <button
          className="secondary"
          onClick={async () => {
            const r = await evaluateUsageControlsNow()
            setMsg(`评估完成 results=${r.results?.length || 0} keys_synced=${String(r.keys_synced)}`)
          }}
        >
          立即评估
        </button>
      </div>
      <p className="msg">{msg}</p>

      <div className="panel">
        <h3>创建规则</h3>
        <div className="row">
          <select value={scopeType} onChange={(e) => setScopeType(e.target.value)}>
            <option value="global">global</option>
            <option value="user">user</option>
            <option value="key">key</option>
          </select>
          <input value={scopeValue} onChange={(e) => setScopeValue(e.target.value)} placeholder="scope value" />
          <input value={windowSeconds} onChange={(e) => setWindowSeconds(Number(e.target.value || 0))} />
          <input value={maxRequests} onChange={(e) => setMaxRequests(e.target.value)} placeholder="max req" />
          <input value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)} placeholder="max tok" />
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="audit_only">audit_only</option>
            <option value="disable_key">disable_key</option>
            <option value="disable_user_keys">disable_user_keys</option>
            <option value="disable_all_keys">disable_all_keys</option>
          </select>
          <label>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> enabled
          </label>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note" />
          <button
            onClick={async () => {
              await createUsageControl({
                scope_type: scopeType,
                scope_value: scopeValue,
                window_seconds: windowSeconds,
                max_requests: maxRequests ? Number(maxRequests) : null,
                max_tokens: maxTokens ? Number(maxTokens) : null,
                action,
                enabled,
                note,
              })
              await load()
              setMsg('创建成功')
            }}
          >
            创建
          </button>
        </div>
      </div>

      <table>
        <thead>
          <tr><th>ID</th><th>Scope</th><th>Window</th><th>Req</th><th>Tok</th><th>Action</th><th>Enabled</th><th>Note</th></tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.id}>
              <td>{c.id}</td>
              <td>{c.scope_type}:{c.scope_value || ''}</td>
              <td>{c.window_seconds}</td>
              <td>{c.max_requests ?? '∞'}</td>
              <td>{c.max_tokens ?? '∞'}</td>
              <td>{c.action}</td>
              <td>{String(c.enabled)}</td>
              <td>{c.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
