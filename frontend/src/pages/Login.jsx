import { useState } from 'react'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      const data = await res.json()
      if (res.ok) {
        onLogin(data.accessToken)
      } else {
        setError(data.error || 'Invalid credentials')
      }
    } catch {
      // Demo mode: allow login without backend
      if (username && password) {
        onLogin('demo-token-' + Date.now())
      } else {
        setError('Connection failed. Enter any credentials for demo mode.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <div className="app-logo" style={{ justifyContent: 'center', marginBottom: '16px' }}>
            <div className="app-logo-icon" style={{ width: '48px', height: '48px', fontSize: '1.5rem' }}>🔭</div>
          </div>
          <h1>WatchTower</h1>
          <p>AI-Powered Cybersecurity Threat Detection Platform</p>
        </div>

        {error && (
          <div style={{
            padding: '10px 14px',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--accent-red)',
            fontSize: '0.813rem',
            marginBottom: '16px',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="login-username">Username</label>
            <input
              id="login-username"
              className="form-input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="login-password">Password</label>
            <input
              id="login-password"
              className="form-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary btn-login"
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <p style={{ marginTop: '20px', fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          Demo: Use admin / admin123
        </p>
      </div>
    </div>
  )
}
