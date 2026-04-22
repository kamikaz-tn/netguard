import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth } from '../services/api.js'
 
const TURNSTILE_SITE_KEY = '0x4AAAAAADBVh15Y0oJUYMbv'
 
// Animated hex grid background
function HexGrid() {
  return (
    <div style={{
      position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0,
      overflow: 'hidden',
    }}>
      {/* Radial glow from center */}
      <div style={{
        position: 'absolute', left: '50%', top: '50%',
        transform: 'translate(-50%, -50%)',
        width: 600, height: 600,
        background: 'radial-gradient(ellipse, rgba(232,53,74,0.07) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />
      {/* Corner accent lines */}
      {[
        { top: 0,    left: 0,    borderWidth: '2px 0 0 2px' },
        { top: 0,    right: 0,   borderWidth: '2px 2px 0 0' },
        { bottom: 0, left: 0,    borderWidth: '0 0 2px 2px' },
        { bottom: 0, right: 0,   borderWidth: '0 2px 2px 0' },
      ].map((pos, i) => (
        <div key={i} style={{
          position: 'absolute', width: 60, height: 60,
          borderStyle: 'solid', borderColor: 'rgba(232,53,74,0.25)',
          ...pos,
        }} />
      ))}
    </div>
  )
}
 
// Boot-sequence text
const BOOT_LINES = [
  '> NETGUARD SECURITY MONITOR v2.0',
  '> Initializing cryptographic modules...',
  '> Loading threat database...',
  '> Establishing secure channel...',
  '> System ready.',
]
 
export default function Login() {
  const navigate = useNavigate()
  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({ username: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState('')
  const turnstileRef = useRef(null)
  const widgetIdRef  = useRef(null)
 
  // Boot sequence state
  const [bootLines, setBootLines] = useState([])
  const [bootDone, setBootDone] = useState(false)
 
  useEffect(() => {
    let i = 0
    const id = setInterval(() => {
      if (i < BOOT_LINES.length) {
        setBootLines(l => [...l, BOOT_LINES[i]])
        i++
      } else {
        clearInterval(id)
        setTimeout(() => setBootDone(true), 300)
      }
    }, 180)
    return () => clearInterval(id)
  }, [])
 
  function renderWidget() {
    if (!window.turnstile || !turnstileRef.current) return
    if (widgetIdRef.current !== null) {
      try { window.turnstile.remove(widgetIdRef.current) } catch {}
      widgetIdRef.current = null
    }
    setTurnstileToken('')
    widgetIdRef.current = window.turnstile.render(turnstileRef.current, {
      sitekey: TURNSTILE_SITE_KEY,
      theme: 'dark',
      callback: (token) => setTurnstileToken(token),
      'expired-callback':  () => setTurnstileToken(''),
      'error-callback':    () => setTurnstileToken(''),
    })
  }
 
  useEffect(() => {
    let attempts = 0
    const interval = setInterval(() => {
      attempts++
      if (window.turnstile) { clearInterval(interval); renderWidget() }
      else if (attempts > 50) clearInterval(interval)
    }, 100)
    return () => clearInterval(interval)
  }, [mode])
 
  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!turnstileToken) { setError('Please complete the security check.'); return }
    setLoading(true)
    try {
      if (mode === 'login') {
        await auth.login(form.username, form.password, turnstileToken)
      } else {
        await auth.register(form.username, form.email, form.password, turnstileToken)
      }
      navigate('/overview')
    } catch (err) {
      setError(err.message)
      if (widgetIdRef.current !== null) { try { window.turnstile.reset(widgetIdRef.current) } catch {} }
      setTurnstileToken('')
    } finally { setLoading(false) }
  }
 
  function switchMode(newMode) {
    setMode(newMode); setShowPassword(false); setError('')
    setForm({ username: '', email: '', password: '' })
  }
 
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20, position: 'relative' }}>
      <HexGrid />
 
      {/* Boot sequence overlay */}
      {!bootDone && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 50,
          background: 'var(--bg-deep)',
          display: 'flex', flexDirection: 'column', justifyContent: 'center',
          padding: '0 40px',
          animation: bootLines.length === BOOT_LINES.length ? 'fadeOutBoot 0.4s 0.5s forwards' : 'none',
        }}>
          <style>{`@keyframes fadeOutBoot { to { opacity: 0; pointer-events: none; } }`}</style>
          {bootLines.map((line, i) => (
            <div key={i} style={{
              fontFamily: 'var(--font-mono)', fontSize: 12,
              color: i === bootLines.length - 1 ? 'var(--red-bright)' : 'var(--muted)',
              letterSpacing: 1, marginBottom: 6,
              animation: 'hudBootUp 0.2s ease both',
            }}>
              {line}
              {i === bootLines.length - 1 && <span className="terminal-cursor" />}
            </div>
          ))}
        </div>
      )}
 
      {/* Login card */}
      <div style={{ width: '100%', maxWidth: 420, zIndex: 1, animation: 'hudBootUp 0.5s 0.8s both cubic-bezier(0.22,1,0.36,1)' }}>
 
        {/* Hex logo */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{
            display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 8,
          }}>
            <div style={{
              width: 64, height: 64,
              border: '2px solid var(--red)',
              borderRadius: 14,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 26, color: 'var(--red)',
              background: 'var(--red-dim)',
              boxShadow: '0 0 24px var(--red-glow), inset 0 0 16px rgba(232,53,74,0.05)',
              position: 'relative',
            }}>
              ⬡
              {/* Corner accents on logo */}
              {[
                { top: -2, left: -2,   borderWidth: '2px 0 0 2px' },
                { top: -2, right: -2,  borderWidth: '2px 2px 0 0' },
                { bottom: -2, left: -2,  borderWidth: '0 0 2px 2px' },
                { bottom: -2, right: -2, borderWidth: '0 2px 2px 0' },
              ].map((pos, i) => (
                <div key={i} style={{
                  position: 'absolute', width: 10, height: 10,
                  borderStyle: 'solid', borderColor: 'var(--red)',
                  opacity: 0.6, ...pos,
                }} />
              ))}
            </div>
            <div style={{ fontFamily: 'var(--font-display)', color: 'var(--text-bright)', fontSize: 24, letterSpacing: 5, fontWeight: 700 }}>
              NETGUARD
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 9, letterSpacing: 3 }}>
              NETWORK SECURITY MONITOR
            </div>
          </div>
        </div>
 
        {/* Card */}
        <div className="card" style={{ padding: '28px 28px' }}>
          {/* Mode tabs */}
          <div style={{
            display: 'flex', marginBottom: 24,
            borderBottom: '1px solid var(--border)',
          }}>
            {[['login', 'Access Terminal'], ['register', 'Register']].map(([m, label]) => (
              <button
                key={m}
                onClick={() => switchMode(m)}
                style={{
                  flex: 1, background: 'none', border: 'none',
                  borderBottom: mode === m ? '2px solid var(--red)' : '2px solid transparent',
                  color: mode === m ? 'var(--red-bright)' : 'var(--muted)',
                  fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 2,
                  padding: '8px 0', marginBottom: -1,
                  cursor: 'pointer', transition: 'all 0.2s',
                  boxShadow: mode === m ? '0 2px 8px rgba(232,53,74,0.15)' : 'none',
                }}
              >
                {label.toUpperCase()}
              </button>
            ))}
          </div>
 
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
 
            {/* Username */}
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, display: 'block', marginBottom: 6 }}>
                <span style={{ color: 'var(--red)', marginRight: 4 }}>›</span>
                USERNAME
              </label>
              <input
                type="text"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="enter identifier..."
                required
                autoComplete="username"
              />
            </div>
 
            {mode === 'register' && (
              <div>
                <label style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, display: 'block', marginBottom: 6 }}>
                  <span style={{ color: 'var(--red)', marginRight: 4 }}>›</span>
                  EMAIL
                </label>
                <input
                  type="email"
                  value={form.email}
                  onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                  placeholder="enter email..."
                  required
                />
              </div>
            )}
 
            {/* Password */}
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, display: 'block', marginBottom: 6 }}>
                <span style={{ color: 'var(--red)', marginRight: 4 }}>›</span>
                PASSWORD
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  placeholder="enter passphrase..."
                  required
                  autoComplete="current-password"
                  style={{ paddingRight: 48 }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  style={{
                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--muted)', fontSize: 14, padding: 0, letterSpacing: 0,
                  }}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
                      fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
                      fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                  )}
                </button>
              </div>
            </div>
 
            {/* Turnstile */}
            <div style={{ display: 'flex', justifyContent: 'center', margin: '2px 0' }}>
              <div ref={turnstileRef} />
            </div>
            {!turnstileToken && (
              <div style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1 }}>
                <span className="terminal-cursor">Loading security check</span>
              </div>
            )}
 
            {/* Error */}
            {error && (
              <div className="terminal-block" style={{ borderLeftColor: 'var(--red)', background: 'var(--red-dim)' }}>
                <span style={{ color: 'var(--red)', marginRight: 6 }}>⚠</span>
                <span style={{ color: 'var(--text)', fontSize: 11 }}>{error}</span>
              </div>
            )}
 
            {/* Submit */}
            <button
              type="submit"
              className="btn-primary"
              style={{ marginTop: 4, padding: '13px 20px', fontSize: 11, letterSpacing: 3, fontWeight: 700 }}
              disabled={loading || !turnstileToken}
            >
              {loading
                ? <><span className="spinner" style={{ width: 12, height: 12, marginRight: 8 }} />AUTHENTICATING</>
                : mode === 'login'
                  ? '▶ AUTHENTICATE'
                  : '▶ CREATE ACCOUNT'
              }
            </button>
          </form>
        </div>
 
        {/* Footer note */}
        <div style={{ textAlign: 'center', marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted2)', letterSpacing: 1 }}>
          ALL CONNECTIONS ENCRYPTED · NETGUARD SECURITY PLATFORM
        </div>
      </div>
    </div>
  )
}