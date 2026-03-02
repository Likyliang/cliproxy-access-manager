import { useEffect, useMemo, useState } from 'react'
import { getMyUsage, listMyKeys } from '../../api'
import type { APIKeyItem, UserUsageResponse } from '../../types'

function fmtNum(v: number | undefined) {
  const n = Number(v || 0)
  return Number.isFinite(n) ? n.toLocaleString() : '0'
}

function fmtTime(v?: string) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return v
  return d.toLocaleString()
}

function remainingText(item?: { remaining_requests?: number; remaining_tokens?: number }) {
  if (!item) return 'unconfigured'
  const hasReq = item.remaining_requests !== undefined
  const hasTok = item.remaining_tokens !== undefined
  if (!hasReq && !hasTok) return 'unconfigured'
  return `req=${item.remaining_requests == null ? '∞' : fmtNum(item.remaining_requests)} / tok=${item.remaining_tokens == null ? '∞' : fmtNum(item.remaining_tokens)}`
}

function limitText(item?: { max_requests?: number; max_tokens?: number }) {
  if (!item) return 'unconfigured'
  const hasReq = item.max_requests !== undefined
  const hasTok = item.max_tokens !== undefined
  if (!hasReq && !hasTok) return 'unconfigured'
  return `req=${item.max_requests == null ? '∞' : fmtNum(item.max_requests)} / tok=${item.max_tokens == null ? '∞' : fmtNum(item.max_tokens)}`
}

export function UserUsagePage() {
  const [since, setSince] = useState('24h')
  const [data, setData] = useState<UserUsageResponse | null>(null)
  const [keys, setKeys] = useState<APIKeyItem[]>([])
  const [error, setError] = useState('')

  const load = async () => {
    setError('')
    try {
      const [usageRes, keysRes] = await Promise.all([getMyUsage(since), listMyKeys(since)])
      setData(usageRes)
      setKeys(keysRes.items || [])
    } catch (e: any) {
      setError(e?.message || '加载失败')
    }
  }

  useEffect(() => {
    load()
  }, [])

  const summary = data?.summary
  const usage = data?.usage

  const activeKeyCount = useMemo(() => keys.filter((k) => k.status === 'active').length, [keys])

  return (
    <div>
      <h1>用量视图</h1>
      <div className="row">
        <input value={since} onChange={(e) => setSince(e.target.value)} placeholder="24h / 7d / 30m" />
        <button onClick={load}>刷新</button>
      </div>
      {error ? <p className="error">{error}</p> : null}

      <div className="cards">
        <div className="panel">
          <h3>账户信息</h3>
          <p>Email: {summary?.email || '-'}</p>
          <p>我的 Key: {summary?.keys?.length || 0}（active: {activeKeyCount}）</p>
          <p>有效期: {summary?.unlimited ? 'unlimited' : fmtTime(summary?.valid_until)}</p>
          <p>有效天数: {summary?.unlimited ? '∞' : fmtNum(summary?.valid_days)}</p>
        </div>
        <div className="panel">
          <h3>当前窗口汇总</h3>
          <p>请求数: {fmtNum(usage?.total_requests)}</p>
          <p>失败数: {fmtNum(usage?.failed_requests)}</p>
          <p>Token: {fmtNum(usage?.total_tokens)}</p>
          <p>用户限额: {limitText(usage?.control)}</p>
          <p>用户剩余: {remainingText(usage?.control)}</p>
        </div>
      </div>

      <h2>Key 用量明细（当前用户）</h2>
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>状态</th>
            <th>Plan</th>
            <th>Req</th>
            <th>Fail</th>
            <th>Token</th>
            <th>配额上限</th>
            <th>剩余额度</th>
            <th>过期时间</th>
            <th>更新时间</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.key}>
              <td><code>{k.key}</code></td>
              <td>{k.status || '-'}</td>
              <td>{k.plan_id || '-'}</td>
              <td>{fmtNum(k.total_requests)}</td>
              <td>{fmtNum(k.failed_requests)}</td>
              <td>{fmtNum(k.total_tokens)}</td>
              <td>{limitText(k.control)}</td>
              <td>{remainingText(k.control)}</td>
              <td>{fmtTime(k.expires_at)}</td>
              <td>{fmtTime(k.updated_at)}</td>
            </tr>
          ))}
          {keys.length === 0 ? (
            <tr>
              <td colSpan={10}>No keys</td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  )
}
