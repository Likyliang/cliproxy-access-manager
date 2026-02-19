import { useEffect, useState } from 'react'
import { listAdminPurchases, updatePurchaseStatus } from '../../api'
import type { PurchaseRequest } from '../../types'

export function AdminPurchasesPage() {
  const [status, setStatus] = useState('')
  const [items, setItems] = useState<PurchaseRequest[]>([])
  const [msg, setMsg] = useState('')

  const load = () => listAdminPurchases(status).then((d) => setItems(d.items || []))

  useEffect(() => {
    load()
  }, [])

  const mutate = async (id: number, next: string) => {
    const review = window.prompt('Review note', '') || ''
    await updatePurchaseStatus(id, next, review)
    setMsg(`已更新 #${id} -> ${next}`)
    await load()
  }

  return (
    <div>
      <h1>审批队列</h1>
      <div className="row">
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">all</option>
          <option value="pending">pending</option>
          <option value="approved">approved</option>
          <option value="rejected">rejected</option>
          <option value="fulfilled">fulfilled</option>
          <option value="cancelled">cancelled</option>
        </select>
        <button onClick={load}>刷新</button>
      </div>
      <p className="msg">{msg}</p>
      <table>
        <thead>
          <tr><th>ID</th><th>Email</th><th>Status</th><th>Plan ID</th><th>Provisioning</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id}>
              <td>{i.id}</td>
              <td>{i.requester_email}</td>
              <td>{i.status}</td>
              <td>{i.plan_id || i.plan}</td>
              <td>{i.provisioning_status || '-'}</td>
              <td>
                <button onClick={() => mutate(i.id, 'approved')}>Approve</button>
                <button className="secondary" onClick={() => mutate(i.id, 'rejected')}>Reject</button>
                <button className="secondary" onClick={() => mutate(i.id, 'fulfilled')}>Fulfill</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
