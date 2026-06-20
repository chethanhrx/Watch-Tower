import { useState } from 'react'

const initialRules = [
  { id: 1, name: 'Brute Force Login', type: 'THRESHOLD', severity: 'HIGH', enabled: true, config: '5 failed logins / 300s per IP' },
  { id: 2, name: 'Port Scan Detection', type: 'THRESHOLD', severity: 'MEDIUM', enabled: true, config: '20 conn attempts / 60s per IP' },
  { id: 3, name: 'Privilege Escalation', type: 'PATTERN', severity: 'CRITICAL', enabled: true, config: 'Pattern: sudo|su|COMMAND=' },
  { id: 4, name: 'Suspicious User Agent', type: 'PATTERN', severity: 'MEDIUM', enabled: true, config: 'Pattern: sqlmap|nikto|nmap' },
  { id: 5, name: 'Impossible Travel', type: 'GEO_ANOMALY', severity: 'HIGH', enabled: false, config: 'Max 900 km/h, min 500 km distance' },
]

export default function Rules() {
  const [rules, setRules] = useState(initialRules)

  const toggle = (id) => {
    setRules(rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }

  const badge = (s) => `alert-severity-badge badge-${s.toLowerCase()}`
  const typeBadge = { padding: '3px 8px', borderRadius: 'var(--radius-sm)', fontSize: '0.688rem', fontWeight: 600,
    background: 'rgba(139,92,246,0.15)', color: 'var(--accent-purple)', border: '1px solid rgba(139,92,246,0.3)' }

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Detection Rules</h1>
        <p className="page-subtitle">Configure threat detection rules — stored in PostgreSQL</p>
      </div>
      <div className="card">
        <div className="card-header">
          <div className="card-title">Active Rules ({rules.filter(r => r.enabled).length} / {rules.length})</div>
          <button className="btn btn-primary" style={{ fontSize: '0.813rem' }}>+ Add Rule</button>
        </div>
        <table className="data-table">
          <thead>
            <tr><th>Rule</th><th>Type</th><th>Severity</th><th>Config</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.5 }}>
                <td style={{ fontWeight: 600 }}>{r.name}</td>
                <td><span style={typeBadge}>{r.type}</span></td>
                <td><span className={badge(r.severity)}>{r.severity}</span></td>
                <td style={{ fontSize: '0.813rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{r.config}</td>
                <td>
                  <span style={{
                    color: r.enabled ? 'var(--accent-green)' : 'var(--text-muted)',
                    fontWeight: 600, fontSize: '0.813rem',
                  }}>
                    {r.enabled ? '● Active' : '○ Disabled'}
                  </span>
                </td>
                <td>
                  <button className="btn btn-ghost" onClick={() => toggle(r.id)}
                    style={{ fontSize: '0.75rem', padding: '4px 10px' }}>
                    {r.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
