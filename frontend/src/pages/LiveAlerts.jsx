import { useState, useEffect, useRef } from 'react'

const DEMO_ALERTS = [
  { alertType: 'BRUTE_FORCE', severity: 'CRITICAL', sourceIp: '203.0.113.42', description: 'Brute force: 12 failed logins in 300s', detectionMethod: 'RULE', confidenceScore: 1.0 },
  { alertType: 'SUSPICIOUS_USER_AGENT', severity: 'HIGH', sourceIp: '198.51.100.17', description: 'sqlmap detected in user agent', detectionMethod: 'RULE', confidenceScore: 1.0 },
  { alertType: 'ANOMALOUS_LOGIN_FREQUENCY', severity: 'HIGH', sourceIp: '45.33.32.156', description: '25 login attempts in the last hour', detectionMethod: 'STATISTICAL', confidenceScore: 0.87 },
  { alertType: 'PRIVILEGE_ESCALATION', severity: 'CRITICAL', sourceIp: '10.0.1.50', description: 'sudo: deploy executed /bin/bash as root', detectionMethod: 'RULE', confidenceScore: 1.0 },
  { alertType: 'ANOMALOUS_LOGIN_TIME', severity: 'MEDIUM', sourceIp: '172.16.0.100', description: 'User alice logged in at 03:00 UTC', detectionMethod: 'STATISTICAL', confidenceScore: 0.6 },
  { alertType: 'PORT_SCAN', severity: 'HIGH', sourceIp: '185.220.101.1', description: '30 connection attempts in 60 seconds', detectionMethod: 'RULE', confidenceScore: 1.0 },
]

export default function LiveAlerts() {
  const [alerts, setAlerts] = useState([])
  const [filter, setFilter] = useState('ALL')

  useEffect(() => {
    const interval = setInterval(() => {
      const t = DEMO_ALERTS[Math.floor(Math.random() * DEMO_ALERTS.length)]
      setAlerts(prev => [{ ...t, alertId: crypto.randomUUID(), timestamp: new Date().toISOString() }, ...prev].slice(0, 200))
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  const filtered = filter === 'ALL' ? alerts : alerts.filter(a => a.severity === filter)
  const badge = (s) => `alert-severity-badge badge-${s.toLowerCase()}`

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Live Alert Feed</h1>
        <p className="page-subtitle">
          <span className="status-dot" style={{ display: 'inline-block', width: 8, height: 8, marginRight: 6, verticalAlign: 'middle' }} />
          Connected — {alerts.length} alerts
        </p>
      </div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
          <button key={s} className={`btn ${filter === s ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setFilter(s)} style={{ fontSize: '0.813rem', padding: '6px 14px' }}>
            {s} {s !== 'ALL' && `(${alerts.filter(a => a.severity === s).length})`}
          </button>
        ))}
      </div>
      <div className="card" style={{ padding: 0 }}>
        <div className="alert-feed" style={{ maxHeight: '70vh' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Waiting for alerts...</div>
          ) : filtered.map(a => (
            <div className="alert-item" key={a.alertId}>
              <span className={badge(a.severity)}>{a.severity}</span>
              <div className="alert-content">
                <div className="alert-type">{a.alertType.replace(/_/g, ' ')}</div>
                <div className="alert-description">{a.description}</div>
                <div className="alert-meta">
                  <span>🌐 {a.sourceIp}</span>
                  <span>📊 {(a.confidenceScore * 100).toFixed(0)}%</span>
                  <span>⏱ {new Date(a.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
