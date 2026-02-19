import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchPrincipal, login, register, setToken } from '../api'

export function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [token, setTokenInput] = useState('')
  const [message, setMessage] = useState('')
  const navigate = useNavigate()

  const goByRole = async () => {
    const principal = await fetchPrincipal()
    if (!principal) throw new Error('认证失败')
    navigate(principal.role === 'admin' ? '/admin/overview' : '/user/plans')
  }

  return (
    <div className="login-wrap">
      <div className="panel">
        <h2>cliproxy-access-manager</h2>
        <p>邮箱密码登录，或使用 Legacy Token。</p>
        <div className="row">
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" placeholder="Password" />
        </div>
        <div className="row">
          <button
            onClick={async () => {
              try {
                setMessage('登录中...')
                await login(email, password)
                await goByRole()
              } catch (e: any) {
                setMessage(`登录失败: ${e.message}`)
              }
            }}
          >
            登录
          </button>
          <button
            className="secondary"
            onClick={async () => {
              try {
                setMessage('注册中...')
                await register(email, password)
                await login(email, password)
                await goByRole()
              } catch (e: any) {
                setMessage(`注册失败: ${e.message}`)
              }
            }}
          >
            注册
          </button>
        </div>
      </div>

      <div className="panel">
        <h3>Legacy Token</h3>
        <div className="row">
          <input value={token} onChange={(e) => setTokenInput(e.target.value)} placeholder="Bearer token" />
          <button
            onClick={async () => {
              setToken(token)
              try {
                await goByRole()
              } catch (e: any) {
                setMessage(`Token 登录失败: ${e.message}`)
              }
            }}
          >
            使用 Token
          </button>
        </div>
      </div>

      <div className="msg">{message}</div>
    </div>
  )
}
