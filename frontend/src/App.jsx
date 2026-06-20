import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import LiveAlerts from './pages/LiveAlerts'
import FileIntegrity from './pages/FileIntegrity'
import Rules from './pages/Rules'
import Login from './pages/Login'

function App() {
  const [token, setToken] = useState(localStorage.getItem('watchtower_token'))

  const handleLogin = (accessToken) => {
    localStorage.setItem('watchtower_token', accessToken)
    setToken(accessToken)
  }

  const handleLogout = () => {
    localStorage.removeItem('watchtower_token')
    setToken(null)
  }

  if (!token) {
    return (
      <BrowserRouter>
        <Login onLogin={handleLogin} />
      </BrowserRouter>
    )
  }

  return (
    <BrowserRouter>
      <Layout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<LiveAlerts />} />
          <Route path="/file-integrity" element={<FileIntegrity />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}

export default App
