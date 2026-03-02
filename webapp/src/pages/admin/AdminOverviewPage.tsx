import { useEffect, useState } from 'react'
import { applyMainProjectUpdate, checkMainProjectUpdate, getReconcilerStatus, getUsageOverview } from '../../api'
import type { ReconcilerStatus, UsageOverview } from '../../types'

export function AdminOverviewPage() {
  const [since, setSince] = useState('24h')
  const [data, setData] = useState<UsageOverview>({})
  const [status, setStatus] = useState<ReconcilerStatus | null>(null)
  const [updateMsg, setUpdateMsg] = useState('')
  const [updateError, setUpdateError] = useState('')
  const [checkingUpdate, setCheckingUpdate] = useState(false)
  const [applyingUpdate, setApplyingUpdate] = useState(false)

  const loadOverview = () => getUsageOverview(since).then(setData)
  const loadStatus = () => getReconcilerStatus().then(setStatus)

  const load = async () => {
    await Promise.all([loadOverview(), loadStatus()])
  }

  useEffect(() => {
    load().catch((e: any) => {
      setUpdateError(e?.message || '加载失败')
    })
  }, [])

  const canApplyUpdate = status?.update_status === 'update_available'

  const doCheckUpdate = async () => {
    setCheckingUpdate(true)
    setUpdateError('')
    setUpdateMsg('')
    try {
      const res = await checkMainProjectUpdate()
      const nextStatus = res.status || (await getReconcilerStatus())
      setStatus(nextStatus)
      setUpdateMsg(nextStatus.update_message || '已完成检查更新')
    } catch (e: any) {
      setUpdateError(`检查更新失败: ${e?.message || 'unknown error'}`)
    } finally {
      setCheckingUpdate(false)
    }
  }

  const doApplyUpdate = async () => {
    if (!canApplyUpdate) return
    if (!window.confirm('确认执行更新吗？更新过程会触发后端自动更新流程。')) return

    setApplyingUpdate(true)
    setUpdateError('')
    setUpdateMsg('')
    try {
      const res = await applyMainProjectUpdate()
      const nextStatus = res.status || (await getReconcilerStatus())
      setStatus(nextStatus)
      setUpdateMsg(nextStatus.update_message || '更新命令已执行')
    } catch (e: any) {
      setUpdateError(`执行更新失败: ${e?.message || 'unknown error'}`)
    } finally {
      setApplyingUpdate(false)
    }
  }

  return (
    <div>
      <h1>总览</h1>

      <div className="panel">
        <h2>主项目更新</h2>
        <div className="row">
          <button onClick={doCheckUpdate} disabled={checkingUpdate || applyingUpdate}>
            {checkingUpdate ? '检查中...' : '手动检查更新'}
          </button>
          <button
            className="secondary"
            onClick={doApplyUpdate}
            disabled={!canApplyUpdate || checkingUpdate || applyingUpdate}
          >
            {applyingUpdate ? '更新中...' : '确认并更新'}
          </button>
          <button className="secondary" onClick={() => loadStatus()} disabled={checkingUpdate || applyingUpdate}>
            刷新状态
          </button>
        </div>

        <div className="grid">
          <div>Update status: <code>{status?.update_status || '-'}</code></div>
          <div>Current version: <code>{status?.current_version || '-'}</code></div>
          <div>Latest version: <code>{status?.latest_version || '-'}</code></div>
          <div>Last check: <code>{status?.last_update_check_at || '-'}</code></div>
        </div>

        {updateMsg ? <p className="msg">{updateMsg}</p> : null}
        {updateError ? <p className="error">{updateError}</p> : null}
      </div>

      <div className="row">
        <input value={since} onChange={(e) => setSince(e.target.value)} />
        <button onClick={loadOverview}>刷新用量</button>
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
