import { useEffect, useState } from 'react'
import { listMyPurchases } from '../../api'
import type { PurchaseRequest } from '../../types'

export function UserPurchaseHistoryPage() {
  const [items, setItems] = useState<PurchaseRequest[]>([])
  const [error, setError] = useState('')

  const load = () =>
    listMyPurchases()
      .then((d) => setItems(d.items || []))
      .catch((e) => setError(e.message))

  useEffect(() => {
    load()
  }, [])

  return (
    <div>
      <h1>申请历史</h1>
      <button onClick={load}>刷新</button>
      {error ? <p className="error">{error}</p> : null}
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>状态</th>
            <th>Plan ID</th>
            <th>备注</th>
            <th>评审备注</th>
            <th>创建时间</th>
            <th>评审时间</th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id}>
              <td>{i.id}</td>
              <td>{i.status}</td>
              <td>{i.plan_id || i.plan}</td>
              <td>{i.note}</td>
              <td>{i.review_note}</td>
              <td>{i.created_at}</td>
              <td>{i.reviewed_at || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
