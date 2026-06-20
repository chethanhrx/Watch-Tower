import { useState } from 'react'

export default function Scanner() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)

  const handleScan = async (e) => {
    e.preventDefault()
    if (!url) return
    
    setScanning(true)
    setReport(null)
    setError(null)

    try {
      const res = await fetch('/api/v1/scanner/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('watchtower_token')}`
        },
        body: JSON.stringify({ url })
      })

      if (!res.ok) {
        const errText = await res.text()
        throw new Error(`Server returned ${res.status}: ${errText}`)
      }

      const data = await res.json()
      setReport(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const getSeverityColor = (sev) => {
    switch(sev) {
      case 'CRITICAL': return 'var(--accent-red)'
      case 'HIGH': return 'var(--accent-orange)'
      case 'MEDIUM': return 'var(--accent-yellow)'
      case 'LOW': return 'var(--accent-blue)'
      default: return 'var(--text-muted)'
    }
  }

  const getScoreColor = (score) => {
    if (score >= 90) return 'var(--accent-green)'
    if (score >= 70) return 'var(--accent-yellow)'
    if (score >= 50) return 'var(--accent-orange)'
    return 'var(--accent-red)'
  }

  return (
    <div className="page-container fade-in">
      <div className="page-header">
        <div>
          <h2>Active Vulnerability Scanner</h2>
          <p className="subtitle">Actively probe external targets for exposed sensitive files and missing security headers.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '24px' }}>
        <form onSubmit={handleScan} style={{ display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
          <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
            <label className="form-label">Target URL</label>
            <input 
              type="text" 
              className="form-input" 
              placeholder="https://example.com" 
              value={url}
              onChange={e => setUrl(e.target.value)}
              disabled={scanning}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={scanning || !url}>
            {scanning ? 'Scanning...' : 'Launch Scan'}
          </button>
        </form>
      </div>

      {error && (
        <div className="card" style={{ borderLeft: '4px solid var(--accent-red)' }}>
          <h3 style={{ color: 'var(--accent-red)' }}>Error</h3>
          <p>{error}</p>
        </div>
      )}

      {scanning && (
        <div className="card pulse" style={{ textAlign: 'center', padding: '48px' }}>
          <div style={{ fontSize: '2rem', marginBottom: '16px' }}>🛡️</div>
          <h3>Probing Target...</h3>
          <p className="subtitle">Sending requests to identify misconfigurations.</p>
        </div>
      )}

      {report && (
        <div className="fade-in">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 3fr', gap: '24px', marginBottom: '24px' }}>
            <div className="card" style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <h3 style={{ marginBottom: '8px' }}>Security Score</h3>
              <div style={{ 
                fontSize: '4rem', 
                fontWeight: 'bold', 
                color: getScoreColor(report.security_score),
                lineHeight: 1
              }}>
                {report.security_score}
              </div>
              <p className="subtitle" style={{ marginTop: '8px' }}>out of 100</p>
            </div>
            
            <div className="card">
              <h3>Scan Details</h3>
              <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '16px' }}>
                <tbody>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '12px 0', color: 'var(--text-muted)' }}>Target</td>
                    <td style={{ padding: '12px 0', fontWeight: '500' }}>{report.target_url}</td>
                  </tr>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '12px 0', color: 'var(--text-muted)' }}>Duration</td>
                    <td style={{ padding: '12px 0' }}>{report.scan_duration_ms} ms</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '12px 0', color: 'var(--text-muted)' }}>Checks Performed</td>
                    <td style={{ padding: '12px 0' }}>{report.findings.length}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <h3 style={{ marginBottom: '16px' }}>Detailed Findings</h3>
          <div style={{ display: 'grid', gap: '16px' }}>
            {report.findings.map((f, i) => (
              <div key={i} className="card" style={{ 
                borderLeft: `4px solid ${f.passed ? 'var(--accent-green)' : getSeverityColor(f.severity)}`,
                display: 'flex',
                alignItems: 'flex-start',
                gap: '16px'
              }}>
                <div style={{ 
                  fontSize: '1.5rem', 
                  color: f.passed ? 'var(--accent-green)' : getSeverityColor(f.severity) 
                }}>
                  {f.passed ? '✓' : '⚠'}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                    <h4 style={{ margin: 0 }}>{f.title}</h4>
                    {!f.passed && (
                      <span className="badge" style={{ backgroundColor: `${getSeverityColor(f.severity)}20`, color: getSeverityColor(f.severity) }}>
                        {f.severity}
                      </span>
                    )}
                  </div>
                  <p style={{ margin: 0, color: 'var(--text-muted)' }}>{f.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
