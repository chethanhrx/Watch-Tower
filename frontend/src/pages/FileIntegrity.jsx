const files = [
  { path: '/etc/shadow', hash: 'a3f2...8b1c', status: 'OK', lastCheck: '2 min ago', size: '1.2 KB', perms: 'rw-------' },
  { path: '/etc/passwd', hash: '7d1e...f4a2', status: 'OK', lastCheck: '2 min ago', size: '2.1 KB', perms: 'rw-r--r--' },
  { path: '/etc/ssh/sshd_config', hash: 'b4c9...2e3f', status: 'MODIFIED', lastCheck: '5 min ago', size: '3.4 KB', perms: 'rw-r--r--' },
  { path: '/usr/bin/sudo', hash: 'e8a1...7d5b', status: 'OK', lastCheck: '2 min ago', size: '164 KB', perms: 'rwsr-xr-x' },
  { path: '/var/log/auth.log', hash: 'c2f3...9a4e', status: 'MODIFIED', lastCheck: '1 min ago', size: '45 KB', perms: 'rw-r-----' },
  { path: '/etc/crontab', hash: '1a2b...3c4d', status: 'OK', lastCheck: '2 min ago', size: '722 B', perms: 'rw-r--r--' },
]

export default function FileIntegrity() {
  const statusStyle = (s) => ({
    padding: '3px 8px', borderRadius: 'var(--radius-sm)', fontSize: '0.688rem', fontWeight: 700,
    background: s === 'OK' ? 'rgba(16,185,129,0.15)' : 'rgba(249,115,22,0.15)',
    color: s === 'OK' ? 'var(--accent-green)' : 'var(--severity-high)',
    border: `1px solid ${s === 'OK' ? 'rgba(16,185,129,0.3)' : 'rgba(249,115,22,0.3)'}`,
  })

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">File Integrity Monitoring</h1>
        <p className="page-subtitle">SHA-256 baseline tracking for critical system files</p>
      </div>
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <div className="stat-card total">
          <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{files.length}</div>
          <div className="stat-label">Monitored Files</div>
        </div>
        <div className="stat-card" style={{ borderTop: '3px solid var(--accent-green)' }}>
          <div className="stat-value" style={{ color: 'var(--accent-green)' }}>
            {files.filter(f => f.status === 'OK').length}
          </div>
          <div className="stat-label">Baseline Match</div>
        </div>
        <div className="stat-card high">
          <div className="stat-value" style={{ color: 'var(--severity-high)' }}>
            {files.filter(f => f.status === 'MODIFIED').length}
          </div>
          <div className="stat-label">Modified</div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Monitored Files</div></div>
        <table className="data-table">
          <thead>
            <tr>
              <th>File Path</th><th>Status</th><th>SHA-256</th><th>Permissions</th><th>Size</th><th>Last Check</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f, i) => (
              <tr key={i}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.813rem' }}>{f.path}</td>
                <td><span style={statusStyle(f.status)}>{f.status}</span></td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{f.hash}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.813rem' }}>{f.perms}</td>
                <td>{f.size}</td>
                <td style={{ color: 'var(--text-muted)' }}>{f.lastCheck}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
