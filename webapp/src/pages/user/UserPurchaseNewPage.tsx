import { useEffect, useState } from 'react'
import { createPurchaseRequest, listPlans } from '../../api'
import type { PlanCatalogItem } from '../../types'

export function UserPurchaseNewPage() {
  const [plans, setPlans] = useState<PlanCatalogItem[]>([])
  const [planId, setPlanId] = useState('')
  const [months, setMonths] = useState(1)
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
          订阅月数
          <input
            type="number"
            min={1}
            max={36}
            step={1}
            value={months}
            onChange={(e) => setMonths(Number(e.target.value || 1))}
          />
        </label>
        <label>
          备注
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={4} />
        </label>
        <button
          onClick={async () => {
            try {
              if (!Number.isFinite(months) || months < 1 || months > 36) {
                setMsg('提交失败: 订阅月数必须在 1-36 之间')
                return
              }
              const r = await createPurchaseRequest(planId, months, note)
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
