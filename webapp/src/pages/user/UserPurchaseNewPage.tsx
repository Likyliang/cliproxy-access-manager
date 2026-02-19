import { useEffect, useState } from 'react'
import { createPurchaseRequest, listPlans } from '../../api'
import type { PlanCatalogItem } from '../../types'

export function UserPurchaseNewPage() {
  const [plans, setPlans] = useState<PlanCatalogItem[]>([])
  const [planId, setPlanId] = useState('')
  const [note, setNote] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    listPlans().then((d) => {
      setPlans(d.items || [])
      if (d.items?.length) setPlanId(d.items[0].id)
    })
  }, [])

  return (
    <div>
      <h1>新建购买申请</h1>
      <div className="panel">
        <label>
          套餐
          <select value={planId} onChange={(e) => setPlanId(e.target.value)}>
            {plans.map((p) => (
              <option value={p.id} key={p.id}>
                {p.name} ({p.id})
              </option>
            ))}
          </select>
        </label>
        <label>
          备注
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={4} />
        </label>
        <button
          onClick={async () => {
            try {
              const r = await createPurchaseRequest(planId, note)
              setMsg(`提交成功，申请 ID=${r.item.id}`)
            } catch (e: any) {
              setMsg(`提交失败: ${e.message}`)
            }
          }}
        >
          提交申请
        </button>
        <p className="msg">{msg}</p>
      </div>
    </div>
  )
}
