import { useState, useEffect } from 'react'
import {
  LineChart, Line, AreaChart, Area, PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts'

// Mock data generator for demo mode
const generateTimeSeriesData = () => {
  const data = []
  const now = new Date()
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now - i * 3600000)
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      critical: Math.floor(Math.random() * 5),
      high: Math.floor(Math.random() * 12) + 2,
      medium: Math.floor(Math.random() * 20) + 5,
      low: Math.floor(Math.random() * 15) + 3,
    })
  }
  return data
}

const severityData = [
  { name: 'Critical', value: 8, color: '#ef4444' },
  { name: 'High', value: 24, color: '#f97316' },
  { name: 'Medium', value: 47, color: '#f59e0b' },
  { name: 'Low', value: 31, color: '#3b82f6' },
]

const topIPs = [
  { ip: '203.0.113.42', count: 156 },
  { ip: '198.51.100.17', count: 98 },
  { ip: '45.33.32.156', count: 67 },
  { ip: '185.220.101.1', count: 45 },
  { ip: '91.121.87.18', count: 34 },
  { ip: '192.0.2.99', count: 28 },
]

const recentAlerts = [
  { id: 1, type: 'BRUTE_FORCE', severity: 'CRITICAL', ip: '203.0.113.42', desc: 'Brute force: 15 failed logins in 5 min', time: '2 min ago' },
  { id: 2, type: 'SUSPICIOUS_USER_AGENT', severity: 'HIGH', ip: '198.51.100.17', desc: 'sqlmap detected in user agent', time: '5 min ago' },
  { id: 3, type: 'PRIVILEGE_ESCALATION', severity: 'CRITICAL', ip: '10.0.1.50', desc: 'sudo: deploy executed /bin/bash as root', time: '8 min ago' },
  { id: 4, type: 'ANOMALOUS_LOGIN_TIME', severity: 'MEDIUM', ip: '172.16.0.100', desc: 'User alice logged in at 03:00 UTC', time: '15 min ago' },
  { id: 5, type: 'PORT_SCAN', severity: 'HIGH', ip: '45.33.32.156', desc: '45 connection attempts in 60 seconds', time: '22 min ago' },
  { id: 6, type: 'FILE_INTEGRITY_VIOLATION', severity: 'HIGH', ip: 'N/A', desc: '/etc/shadow modified — hash mismatch', time: '30 min ago' },
]

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload) return null
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-color)',
      borderRadius: 'var(--radius-md)',
      padding: '10px 14px',
      fontSize: '0.813rem',
    }}>
      <p style={{ fontWeight: 600, marginBottom: 4 }}>{label}</p>
      {payload.map((entry, i) => (
        <p key={i} style={{ color: entry.color }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const [timeData, setTimeData] = useState(generateTimeSeriesData)

  useEffect(() => {
    const interval = setInterval(() => {
      setTimeData(prev => {
        const updated = [...prev.slice(1)]
        const now = new Date()
        updated.push({
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          critical: Math.floor(Math.random() * 5),
          high: Math.floor(Math.random() * 12) + 2,
          medium: Math.floor(Math.random() * 20) + 5,
          low: Math.floor(Math.random() * 15) + 3,
        })
        return updated
      })
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const badgeClass = (severity) => `alert-severity-badge badge-${severity.toLowerCase()}`

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Security Dashboard</h1>
        <p className="page-subtitle">Real-time threat monitoring and analytics</p>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card total">
          <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>110</div>
          <div className="stat-label">Total Alerts (24h)</div>
          <div className="stat-trend up">↑ 12% from yesterday</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-value" style={{ color: 'var(--severity-critical)' }}>8</div>
          <div className="stat-label">Critical Alerts</div>
          <div className="stat-trend up">↑ 3 new</div>
        </div>
        <div className="stat-card high">
          <div className="stat-value" style={{ color: 'var(--severity-high)' }}>24</div>
          <div className="stat-label">High Severity</div>
          <div className="stat-trend down">↓ 5% from yesterday</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-value" style={{ color: 'var(--severity-medium)' }}>78</div>
          <div className="stat-label">Med + Low</div>
          <div className="stat-trend up">↑ 8%</div>
        </div>
      </div>

      {/* Charts */}
      <div className="charts-grid">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Alerts Over Time (24h)</div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={timeData}>
              <defs>
                <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity={0.3}/>
                  <stop offset="100%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f97316" stopOpacity={0.3}/>
                  <stop offset="100%" stopColor="#f97316" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="critical" name="Critical" stroke="#ef4444"
                    fill="url(#colorCritical)" strokeWidth={2} />
              <Area type="monotone" dataKey="high" name="High" stroke="#f97316"
                    fill="url(#colorHigh)" strokeWidth={2} />
              <Line type="monotone" dataKey="medium" name="Medium" stroke="#f59e0b"
                    strokeWidth={1.5} dot={false} />
              <Legend />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Severity Breakdown</div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%" cy="50%"
                innerRadius={65} outerRadius={100}
                paddingAngle={4}
                dataKey="value"
              >
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bottom section: Top IPs + Recent Alerts */}
      <div className="charts-grid">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Recent Alerts</div>
          </div>
          <div className="alert-feed">
            {recentAlerts.map(alert => (
              <div className="alert-item" key={alert.id}>
                <span className={badgeClass(alert.severity)}>
                  {alert.severity}
                </span>
                <div className="alert-content">
                  <div className="alert-type">{alert.type.replace(/_/g, ' ')}</div>
                  <div className="alert-description">{alert.desc}</div>
                  <div className="alert-meta">
                    <span>🌐 {alert.ip}</span>
                    <span>⏱ {alert.time}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Top Source IPs</div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={topIPs} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis type="category" dataKey="ip" tick={{ fill: '#94a3b8', fontSize: 11 }} width={110} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Alerts" fill="var(--accent-cyan)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </>
  )
}
