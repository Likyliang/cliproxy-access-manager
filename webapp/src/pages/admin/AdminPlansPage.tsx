import { useEffect, useState } from 'react'
import { listPlans } from '../../api'
import type { PlanCatalogItem } from '../../types'

export function AdminPlansPage() {
  const [items, setItems] = useState<PlanCatalogItem[]>([])

  useEffect(() => {
    listPlans().then((d) => setItems(d.items || []))
  }, [])

  return (
    <div>
      <h1>套餐管理（只读）</h1>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Persona</th>
            <th>Billing</th>
            <th>Monthly Suggestion</th>
            <th>Token Limit</th>
            <th>Req Limit</th>
            <th>Recommended</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {items.map((p) => (
            <tr key={p.id}>
              <td><code>{p.id}</code></td>
              <td>{p.name}</td>
              <td>{p.persona}</td>
              <td>{p.billing_cycle}</td>
              <td>{p.monthly_price_suggestion}</td>
              <td>{p.included_tokens_total}</td>
              <td>{p.included_requests_total ?? '∞'}</td>
              <td>{String(p.recommended)}</td>
              <td>{String(p.enabled)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
