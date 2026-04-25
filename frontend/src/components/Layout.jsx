import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useState, useEffect, useRef } from 'react'
import { auth, auth_state } from '../services/api.js'
 
const NAV = [
  { to: '/overview',    label: 'Overview',    icon: '◈', code: 'OVR' },
  { to: '/devices',     label: 'Devices',     icon: '◉', code: 'DEV' },
  { to: '/ports',       label: 'Port Scan',   icon: '◎', code: 'PSC' },
  { to: '/password',    label: 'Pwned Check', icon: '◆', code: 'PWD' },
  { to: '/ai',          label: 'AI Advisor',  icon: '◇', code: 'AIA' },
  { to: '/agent-setup', label: 'Run Scan',    icon: '▶', code: 'SCN' },
]
 
// Only shown in dark mode — invisible / ugly in light
function DataStream({ visible }) {
  const canvasRef = useRef(null)
 
  useEffect(() => {
    if (!visible) return
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    canvas.width  = canvas.offsetWidth
    canvas.height = canvas.offsetHeight
 
    const cols  = Math.floor(canvas.width / 14)
    const drops = Array(cols).fill(1).map(() => Math.random() * -50)
    const chars = '01アイウエオカキ█▓░┼┤├╔╗╚╝╠╣ AB_#$%'
 
    function draw() {
      ctx.fillStyle = 'rgba(4,5,6,0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = 'rgba(232,53,74,0.08)'
      ctx.font = '11px Share Tech Mono, monospace'
      drops.forEach((y, i) => {
        const char = chars[Math.floor(Math.random() * chars.length)]
        ctx.fillText(char, i * 14, y * 14)
        if (y * 14 > canvas.height && Math.random() > 0.975) drops[i] = 0
        drops[i] += 0.3
      })
    }
 
    const id = setInterval(draw, 60)
    return () => clearInterval(id)
  }, [visible])
 
  if (!visible) return null
 
  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute', inset: 0, width: '100%', height: '100%',
        pointerEvents: 'none', opacity: 0.6, zIndex: 0,
      }}
    />
  )
}
 
export default function Layout() {
  const navigate  = useNavigate()
  const location  = useLocation()
  const [time, setTime]               = useState(new Date())
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [threatLevel, setThreatLevel] = useState('NOMINAL')
  const [theme, setTheme]             = useState(() => localStorage.getItem('ng_theme') || 'dark')
  const [bootSeq, setBootSeq]         = useState(true)
 
  const isDark = theme === 'dark'
 
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('ng_theme', theme)
  }, [theme])
 
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
 
  useEffect(() => { setSidebarOpen(false) }, [location.pathname])
 
  useEffect(() => {
    const t = setTimeout(() => setBootSeq(false), 800)
    return () => clearTimeout(t)
  }, [])
 
  async function handleLogout() {
    await auth.logout()
    navigate('/login')
  }
 
  const username   = auth_state.getUsername() || 'operator'
  const currentNav = NAV.find(n => n.to === location.pathname)
 
  const threatColor = threatLevel === 'CRITICAL' ? 'var(--red-bright)'
    : threatLevel === 'HIGH'     ? 'var(--amber)'
    : threatLevel === 'ELEVATED' ? 'var(--amber)'
    : isDark ? 'var(--blue)' : 'var(--blue)'
 
  // Nav link colors — light mode needs darker text for readability
  function navStyle({ isActive }, isRunScan) {
    return {
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '8px 10px', borderRadius: 'var(--radius)',
      fontFamily: 'var(--font-mono)', fontSize: 10,
      letterSpacing: 2, textTransform: 'uppercase',
      textDecoration: 'none',
      marginBottom: isRunScan ? 0 : 2,
      marginTop: isRunScan ? 8 : 0,
      borderTop: isRunScan ? '1px solid var(--border)' : 'none',
      paddingTop: isRunScan ? 12 : 8,
      // FIX: light mode nav text is readable, dark mode stays subtle
      color: isActive
        ? 'var(--red-bright)'
        : isRunScan
          ? 'var(--red)'
          : isDark ? 'var(--muted)' : '#3a5060',   // ← was too light in light mode
      background: isActive
        ? 'var(--red-dim)'
        : 'transparent',
      border: `1px solid ${isActive ? 'rgba(191,17,48,0.3)' : 'transparent'}`,
      borderTopColor: isRunScan && !isActive ? 'var(--border)' : undefined,
      transition: 'all 0.15s',
      position: 'relative',
      boxShadow: isActive ? 'inset 0 0 15px rgba(191,17,48,0.05)' : 'none',
    }
  }
 
  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
 
      {/* Mobile overlay */}
      <div
        className={`mobile-overlay ${sidebarOpen ? 'open' : ''}`}
        onClick={() => setSidebarOpen(false)}
      />
 
      {/* ── SIDEBAR ─────────────────────────────────────────────────────── */}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`} style={{
        width: 220, display: 'flex', flexDirection: 'column', flexShrink: 0,
        position: 'relative', overflow: 'hidden',
        // Light mode: clean white sidebar, no matrix effect
        background: isDark ? undefined : '#ffffff',
      }}>
        {/* Data stream — dark mode only */}
        <DataStream visible={isDark} />
 
        <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', height: '100%' }}>
 
          {/* Logo */}
          <div style={{
            padding: '20px 20px 16px',
            borderBottom: `1px solid var(--border)`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="logo-hex" style={{
                width: 34, height: 34,
                border: '2px solid var(--red)',
                borderRadius: 6,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--red)', fontSize: 16,
                boxShadow: isDark ? '0 0 10px var(--red-glow)' : 'none',
                background: 'var(--red-dim)',
              }}>⬡</div>
              <div>
                <div style={{
                  fontFamily: 'var(--font-display)',
                  color: 'var(--text-bright)',
                  fontSize: 17, letterSpacing: 4, fontWeight: 700,
                }}>NETGUARD</div>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--muted)',
                  fontSize: 8, letterSpacing: 2,
                }}>SECURITY MONITOR v2</div>
              </div>
            </div>
 
            {/* Threat level badge */}
            <div style={{
              marginTop: 12, padding: '6px 10px',
              background: isDark ? 'var(--surface2)' : 'var(--surface3)',
              borderRadius: 'var(--radius)',
              border: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 1 }}>
                THREAT LEVEL
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: threatColor, letterSpacing: 2, fontWeight: 700 }}>
                {threatLevel}
              </span>
            </div>
          </div>
 
          {/* Navigation */}
          <nav style={{ flex: 1, padding: '10px 8px', overflowY: 'auto' }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 8,
              // FIX: light mode section label — much more visible
              color: isDark ? 'var(--muted2)' : '#8fa4ae',
              letterSpacing: 3, padding: '6px 6px 8px', textTransform: 'uppercase',
            }}>
              Navigation
            </div>
 
            {NAV.map(({ to, label, icon, code }) => {
              const isRunScan = to === '/agent-setup'
              return (
                <NavLink key={to} to={to} style={(p) => navStyle(p, isRunScan)}>
                  {({ isActive }) => (
                    <>
                      {/* Left active bar */}
                      <div style={{
                        position: 'absolute', left: 0, top: '50%',
                        transform: 'translateY(-50%)',
                        width: 2, height: isActive ? '60%' : 0,
                        background: 'var(--red)',
                        boxShadow: isDark ? '0 0 6px var(--red-glow)' : 'none',
                        borderRadius: '0 1px 1px 0',
                        transition: 'height 0.2s ease',
                      }} />
                      {/* Code tag */}
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 7,
                        color: isActive ? 'var(--red)' : isDark ? 'var(--muted2)' : '#9ab0ba',
                        letterSpacing: 1, minWidth: 24, opacity: 0.8,
                      }}>{code}</span>
                      <span style={{ fontSize: 13 }}>{icon}</span>
                      <span style={{ flex: 1 }}>{label}</span>
                      {isActive && (
                        <div style={{
                          width: 4, height: 4, background: 'var(--red)',
                          borderRadius: '50%',
                          boxShadow: isDark ? '0 0 4px var(--red-glow)' : 'none',
                        }} />
                      )}
                    </>
                  )}
                </NavLink>
              )
            })}
          </nav>
 
          {/* Footer */}
          <div style={{ padding: '12px 14px', borderTop: '1px solid var(--border)' }}>
            {/* Clock */}
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 10,
              color: 'var(--muted)', marginBottom: 8,
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <span>{time.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}</span>
              <span className="terminal-cursor" style={{ color: 'var(--red)', fontSize: 11 }}>
                {time.toLocaleTimeString()}
              </span>
            </div>
 
            {/* Theme toggle */}
            <button
              className="theme-toggle"
              onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
              style={{ width: '100%', marginBottom: 8, justifyContent: 'center', fontSize: 10 }}
            >
              {isDark ? '☀ LIGHT' : '☾ DARK'}
            </button>
 
            {/* User + logout */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{
                  width: 22, height: 22, borderRadius: '50%',
                  background: 'var(--red-dim)', border: '1px solid var(--red)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--red)',
                }}>
                  {username.slice(0, 2).toUpperCase()}
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>
                  {username}
                </span>
              </div>
              <button
                className="btn-ghost"
                style={{ padding: '3px 8px', fontSize: 8, letterSpacing: 1 }}
                onClick={handleLogout}
              >
                EXIT
              </button>
            </div>
          </div>
        </div>
      </aside>
 
      {/* ── RIGHT SIDE ──────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
 
        {/* Mobile topbar */}
        <div className="mobile-topbar" style={{
          display: 'none', alignItems: 'center', justifyContent: 'space-between',
          padding: '10px 16px',
          background: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          <button
            className="hamburger"
            onClick={() => setSidebarOpen(o => !o)}
            style={{
              background: 'none', border: '1px solid var(--border2)',
              borderRadius: 'var(--radius)', color: 'var(--red)',
              fontSize: 18, padding: '4px 10px', lineHeight: 1, letterSpacing: 0,
            }}
          >☰</button>
 
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 13, color: 'var(--red)', letterSpacing: 3, fontWeight: 700 }}>
            {currentNav ? `${currentNav.icon} ${currentNav.label.toUpperCase()}` : 'NETGUARD'}
          </div>
 
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              className="theme-toggle"
              onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
              style={{ padding: '4px 8px', fontSize: 12 }}
            >
              {isDark ? '☀' : '☾'}
            </button>
            <button className="btn-ghost" style={{ fontSize: 9, padding: '4px 10px' }} onClick={handleLogout}>
              EXIT
            </button>
          </div>
        </div>
 
        {/* Top HUD bar */}
        <div style={{
          padding: '0 24px',
          background: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          <div style={{ height: 2 }}>
            <div className="scan-bar" style={{ width: '100%' }} />
          </div>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 0',
            fontFamily: 'var(--font-mono)', fontSize: 9,
            color: 'var(--muted)', letterSpacing: 1.5,
          }}>
            <span style={{ color: 'var(--red)', opacity: 0.7 }}>NETGUARD</span>
            <span>/</span>
            <span style={{ color: 'var(--text-bright)' }}>
              {currentNav?.label?.toUpperCase() || 'SYSTEM'}
            </span>
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