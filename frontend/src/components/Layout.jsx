import { useLocation, Link } from 'react-router-dom'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊', section: 'Monitoring' },
  { path: '/alerts', label: 'Live Alerts', icon: '🔔', section: 'Monitoring' },
  { path: '/file-integrity', label: 'File Integrity', icon: '🛡️', section: 'Security' },
  { path: '/rules', label: 'Detection Rules', icon: '⚙️', section: 'Security' },
]

export default function Layout({ children, onLogout }) {
  const location = useLocation()

  const sections = navItems.reduce((acc, item) => {
    if (!acc[item.section]) acc[item.section] = []
    acc[item.section].push(item)
    return acc
  }, {})

  return (
    <div className="app-layout">
      {/* Header */}
      <header className="app-header">
        <div className="app-logo">
          <div className="app-logo-icon">🔭</div>
          <span>WatchTower</span>
        </div>
        <div className="header-status">
          <div className="status-indicator">
            <div className="status-dot"></div>
            System Active
          </div>
          <button className="btn btn-ghost" onClick={onLogout}>Logout</button>
        </div>
      </header>

      {/* Sidebar */}
      <aside className="app-sidebar">
        {Object.entries(sections).map(([section, items]) => (
          <nav className="nav-section" key={section}>
            <div className="nav-section-title">{section}</div>
            {items.map(item => (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
              >
                <span className="nav-item-icon">{item.icon}</span>
                {item.label}
                {item.path === '/alerts' && (
                  <span className="nav-item-badge">Live</span>
                )}
              </Link>
            ))}
          </nav>
        ))}
      </aside>

      {/* Main */}
      <main className="app-main">
        {children}
      </main>
    </div>
  )
}
