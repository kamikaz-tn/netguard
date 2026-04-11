import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { auth } from '../services/api.js'
 
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
  const [time, setTime] = useState(new Date())
 
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
 
  function handleLogout() {
    auth.logout()
    navigate('/login')
  }
 
  const username = (() => {
    try {
      const token = localStorage.getItem('ng_token')
      if (!token) return 'user'
      const payload = JSON.parse(atob(token.split('.')[1]))
      return payload.username || 'user'
    } catch { return 'user' }
  })()
 
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
 
      {/* Sidebar */}
      <aside style={{
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
 
      {/* Main content */}
      <main style={{ flex: 1, overflow: 'auto', padding: 24 }}>
        <Outlet />
      </main>
    </div>
  )
}