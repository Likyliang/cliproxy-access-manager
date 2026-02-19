import { useEffect, useState } from 'react'
import { listPlans } from '../../api'
import type { PlanCatalogItem } from '../../types'

export function UserPlansPage() {
  const [items, setItems] = useState<PlanCatalogItem[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    listPlans()
      .then((d) => setItems(d.items || []))
      .catch((e) => setError(e.message))
  }, [])

  return (
    <div>
      <h1>套餐目录</h1>
      {error ? <p className="error">{error}</p> : null}
      <div className="cards">
        {items.map((p) => (
          <div className="panel" key={p.id}>
            <h3>
              {p.name} {p.recommended ? <span className="tag">推荐</span> : null}
            </h3>
            <p>{p.description}</p>
            <p>Persona: {p.persona}</p>
            <p>建议价: {p.monthly_price_suggestion}</p>
            <p>月度总 Token: {p.included_tokens_total.toLocaleString()}</p>
            <p>月度请求数: {p.included_requests_total?.toLocaleString() || '不限'}</p>
            <p>超额建议价: {p.overage_price_suggestion}</p>
            <p>计划 ID: <code>{p.id}</code></p>
          </div>
        ))}
      </div>
    </div>
  )
}
