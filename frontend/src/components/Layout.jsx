import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { auth, auth_state } from '../services/api.js'
 
const NAV = [
  { to: '/overview',    label: 'Overview',     icon: '◈' },
  { to: '/devices',     label: 'Devices',      icon: '◉' },
  { to: '/ports',       label: 'Port Scan',    icon: '◎' },
  { to: '/password',    label: 'Pwned Check',  icon: '◆' },
  { to: '/ai',          label: 'AI Advisor',   icon: '◇' },
  { to: '/agent-setup', label: 'Run Scan',     icon: '▶' },
]
 
export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const [time, setTime] = useState(new Date())
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [theme, setTheme] = useState(
    () => localStorage.getItem('ng_theme') || 'dark'
  )
 
  // Apply theme to document root
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('ng_theme', theme)
  }, [theme])
 
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
 
  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])
 
  async function handleLogout() {
    await auth.logout()
    navigate('/login')
  }
 
  function toggleTheme() {
    setTheme(t => t === 'dark' ? 'light' : 'dark')
  }
 
  const username = auth_state.getUsername() || 'user'
  const currentNav = NAV.find(n => n.to === location.pathname)
  const isDark = theme === 'dark'
 
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
 
      {/* Mobile overlay */}
      <div
        className={`mobile-overlay ${sidebarOpen ? 'open' : ''}`}
        onClick={() => setSidebarOpen(false)}
      />
 
      {/* Sidebar */}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`} style={{
        width: 220,
        background: 'var(--surface)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 20px 16px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32,
              border: '2px solid var(--green)',
              borderRadius: 6,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--green)', fontSize: 14,
            }}>⬡</div>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)', fontSize: 16, letterSpacing: 3 }}>NETGUARD</div>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 9, letterSpacing: 2 }}>SECURITY MONITOR</div>
            </div>
          </div>
        </div>
 
        {/* Nav */}
        <nav style={{ flex: 1, padding: '12px 10px' }}>
          {NAV.map(({ to, label, icon }) => {
            const isRunScan = to === '/agent-setup'
            return (
              <NavLink key={to} to={to} style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 12px', borderRadius: 'var(--radius)',
                fontFamily: 'var(--font-mono)', fontSize: 11,
                letterSpacing: 1.5, textTransform: 'uppercase',
                textDecoration: 'none',
                marginBottom: isRunScan ? 0 : 2,
                marginTop: isRunScan ? 8 : 0,
                borderTop: isRunScan ? '1px solid var(--border)' : 'none',
                paddingTop: isRunScan ? 12 : 9,
                color: isActive ? 'var(--green)' : isRunScan ? 'var(--green)' : 'var(--muted)',
                background: isActive ? 'var(--green-dim)' : 'transparent',
                border: `1px solid ${isActive ? 'rgba(0,229,160,0.3)' : 'transparent'}`,
                borderTopColor: isRunScan && !isActive ? 'var(--border)' : undefined,
                transition: 'all 0.15s',
              })}>
                <span style={{ fontSize: 14 }}>{icon}</span>
                {label}
              </NavLink>
            )
          })}
        </nav>
 
        {/* Footer */}
        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginBottom: 8 }}>
            {time.toLocaleTimeString()}
          </div>
 
          {/* Theme toggle */}
          <button
            className="theme-toggle"
            onClick={toggleTheme}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            style={{ width: '100%', marginBottom: 8, justifyContent: 'center' }}
          >
            {isDark ? '☀ LIGHT MODE' : '☾ DARK MODE'}
          </button>
 
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>
              {username}
            </span>
            <button className="btn-ghost" style={{ padding: '4px 10px', fontSize: 9 }} onClick={handleLogout}>
              LOGOUT
            </button>
          </div>
        </div>
      </aside>
 
      {/* Right side wrapper */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
 
        {/* Mobile top bar */}
        <div className="mobile-topbar" style={{
          display: 'none',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          background: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          <button
            className="hamburger"
            onClick={() => setSidebarOpen(o => !o)}
            style={{
              background: 'none',
              border: '1px solid var(--border2)',
              borderRadius: 'var(--radius)',
              color: 'var(--green)',
              fontSize: 18,
              padding: '4px 10px',
              lineHeight: 1,
              letterSpacing: 0,
            }}
          >
            ☰
          </button>
 
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)', letterSpacing: 2 }}>
            {currentNav ? `${currentNav.icon} ${currentNav.label.toUpperCase()}` : 'NETGUARD'}
          </div>
 
          <div style={{ display: 'flex', gap: 6 }}>
            {/* Theme toggle on mobile */}
            <button
              className="theme-toggle"
              onClick={toggleTheme}
              style={{ padding: '4px 8px', fontSize: 12 }}
              title={isDark ? 'Light mode' : 'Dark mode'}
            >
              {isDark ? '☀' : '☾'}
            </button>
            <button
              className="btn-ghost"
              style={{ fontSize: 9, padding: '4px 10px' }}
              onClick={handleLogout}
            >
              EXIT
            </button>
          </div>
        </div>
 
        {/* Main content */}
        <main className="main-content" style={{ flex: 1, overflow: 'auto', padding: 24 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}