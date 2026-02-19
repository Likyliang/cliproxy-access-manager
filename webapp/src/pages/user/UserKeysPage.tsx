import { useEffect, useState } from 'react'
import { listMyKeys } from '../../api'
import type { APIKeyItem } from '../../types'

export function UserKeysPage() {
  const [since, setSince] = useState('24h')
  const [items, setItems] = useState<APIKeyItem[]>([])

  const load = () => listMyKeys(since).then((d) => setItems(d.items || []))

  useEffect(() => {
    load()
  }, [])

  return (
    <div>
      <h1>我的 Keys</h1>
      <div className="row">
        <input value={since} onChange={(e) => setSince(e.target.value)} />
        <button onClick={load}>刷新</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>状态</th>
            <th>Plan ID</th>
            <th>请求数</th>
            <th>Token</th>
            <th>剩余额度</th>
          </tr>
        </thead>
        <tbody>
          {items.map((k) => (
            <tr key={k.key}>
              <td><code>{k.key}</code></td>
              <td>{k.status}</td>
              <td>{k.plan_id || '-'}</td>
              <td>{k.total_requests || 0}</td>
              <td>{k.total_tokens || 0}</td>
              <td>
                req={k.control?.remaining_requests ?? '∞'} / tok={k.control?.remaining_tokens ?? '∞'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
