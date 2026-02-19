import { useEffect, useState } from 'react'
import { getUsageOverview } from '../../api'
import type { UsageOverview } from '../../types'

export function AdminOverviewPage() {
  const [since, setSince] = useState('24h')
  const [data, setData] = useState<UsageOverview>({})

  const load = () => getUsageOverview(since).then(setData)

  useEffect(() => {
    load()
  }, [])

  return (
    <div>
      <h1>总览</h1>
      <div className="row">
        <input value={since} onChange={(e) => setSince(e.target.value)} />
        <button onClick={load}>刷新</button>
      </div>
      <div className="cards">
        <div className="panel">Requests: {data.totals?.total_requests || 0}</div>
        <div className="panel">Failed: {data.totals?.failed_requests || 0}</div>
        <div className="panel">Tokens: {data.totals?.total_tokens || 0}</div>
      </div>

      <h2>Top Users</h2>
      <table>
        <thead>
          <tr><th>Email</th><th>Req</th><th>Fail</th><th>Token</th><th>Keys</th></tr>
        </thead>
        <tbody>
          {(data.top_users || []).map((u) => (
            <tr key={u.email}>
              <td>{u.email}</td>
              <td>{u.total_requests}</td>
              <td>{u.failed_requests}</td>
              <td>{u.total_tokens}</td>
              <td>{u.keys?.length || 0}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Top Keys</h2>
      <table>
        <thead>
          <tr><th>Key</th><th>Req</th><th>Fail</th><th>Token</th></tr>
        </thead>
        <tbody>
          {(data.top_keys || []).map((k) => (
            <tr key={k.api_key}>
              <td><code>{k.api_key}</code></td>
              <td>{k.total_requests}</td>
              <td>{k.failed_requests}</td>
              <td>{k.total_tokens}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
