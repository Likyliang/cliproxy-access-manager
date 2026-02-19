import { useEffect, useState } from 'react'
import { getMyUsage } from '../../api'

export function UserUsagePage() {
  const [since, setSince] = useState('24h')
  const [data, setData] = useState<any>(null)

  const load = () => getMyUsage(since).then(setData)

  useEffect(() => {
    load()
  }, [])

  const usage = data?.usage || {}
  const summary = data?.summary || {}

  return (
    <div>
      <h1>用量视图</h1>
      <div className="row">
        <input value={since} onChange={(e) => setSince(e.target.value)} />
        <button onClick={load}>刷新</button>
      </div>
      <div className="cards">
        <div className="panel">
          <h3>账户</h3>
          <p>Email: {summary.email || '-'}</p>
          <p>Key 数: {(summary.keys || []).length}</p>
          <p>有效期: {summary.unlimited ? 'unlimited' : summary.valid_until || '-'}</p>
        </div>
        <div className="panel">
          <h3>窗口统计</h3>
          <p>请求数: {usage.total_requests || 0}</p>
          <p>失败数: {usage.failed_requests || 0}</p>
          <p>Token: {usage.total_tokens || 0}</p>
        </div>
      </div>
    </div>
  )
}
