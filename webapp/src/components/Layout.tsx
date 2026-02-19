import { Link, useNavigate } from 'react-router-dom'
import { logout } from '../api'

type Props = {
  title: string
  role: 'user' | 'admin'
  children: React.ReactNode
}

export function AppLayout({ title, role, children }: Props) {
  const navigate = useNavigate()

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h2>{title}</h2>
        {role === 'user' ? (
          <nav>
            <Link to="/user/plans">套餐目录</Link>
            <Link to="/user/purchase/new">新建申请</Link>
            <Link to="/user/purchase/history">申请历史</Link>
            <Link to="/user/keys">我的 Keys</Link>
            <Link to="/user/usage">用量视图</Link>
          </nav>
        ) : (
          <nav>
            <Link to="/admin/overview">总览</Link>
            <Link to="/admin/purchases">审批队列</Link>
            <Link to="/admin/users">用户列表</Link>
            <Link to="/admin/usage-controls">配额控制</Link>
            <Link to="/admin/plans">套餐目录</Link>
          </nav>
        )}
        <button
          className="secondary"
          onClick={async () => {
            await logout()
            navigate('/login')
          }}
        >
          退出登录
        </button>
      </aside>
      <main className="content">{children}</main>
    </div>
  )
}
