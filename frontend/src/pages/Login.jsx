import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth } from '../services/api.js'
 
const TURNSTILE_SITE_KEY = '0x4AAAAAADBVh15Y0oJUYMbv'
 
export default function Login() {
  const navigate = useNavigate()
  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({ username: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState('')
  const turnstileRef = useRef(null)
  const widgetIdRef = useRef(null)
 
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
      'expired-callback': () => setTurnstileToken(''),
      'error-callback': () => setTurnstileToken(''),
    })
  }
 
  useEffect(() => {
    // Poll until turnstile is ready (script loaded from index.html)
    let attempts = 0
    const interval = setInterval(() => {
      attempts++
      if (window.turnstile) {
        clearInterval(interval)
        renderWidget()
      } else if (attempts > 50) {
        clearInterval(interval) // give up after 5s
      }
    }, 100)
    return () => clearInterval(interval)
  }, [mode])
 
  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
 
    if (!turnstileToken) {
      setError('Please wait for CAPTCHA to load and complete verification.')
      return
    }
 
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
      if (widgetIdRef.current !== null) {
        try { window.turnstile.reset(widgetIdRef.current) } catch {}
      }
      setTurnstileToken('')
    } finally {
      setLoading(false)
    }
  }
 
  function switchMode(newMode) {
    setMode(newMode)
    setShowPassword(false)
    setError('')
    setForm({ username: '', email: '', password: '' })
  }
 
  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 20,
    }}>
      <div style={{ width: '100%', maxWidth: 400, animation: 'fadeIn 0.4s ease' }}>
 
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 56, height: 56, border: '2px solid var(--green)',
            borderRadius: 12, fontSize: 24, color: 'var(--green)', marginBottom: 16,
          }}>⬡</div>
          <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)', fontSize: 22, letterSpacing: 4 }}>NETGUARD</div>
          <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 10, letterSpacing: 2, marginTop: 4 }}>NETWORK SECURITY MONITOR</div>
        </div>
 
        {/* Card */}
        <div className="card">
          <div className="card-title">
            {mode === 'login' ? 'Access Terminal' : 'Register Account'}
          </div>
 
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', letterSpacing: 1.5, display: 'block', marginBottom: 6 }}>
                USERNAME
              </label>
              <input
                type="text"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="enter username..."
                required
              />
            </div>
 
            {mode === 'register' && (
              <div>
                <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', letterSpacing: 1.5, display: 'block', marginBottom: 6 }}>
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
 
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', letterSpacing: 1.5, display: 'block', marginBottom: 6 }}>
                PASSWORD
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  placeholder="enter password..."
                  required
                  style={{ paddingRight: 40, width: '100%', boxSizing: 'border-box' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  style={{
                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--muted)', fontSize: 14, padding: 0, lineHeight: 1,
                  }}
                >
                  {showPassword ? '🙈' : '👁'}
                </button>
              </div>
            </div>
 
            {/* Turnstile widget */}
            <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}>
              <div ref={turnstileRef} />
            </div>
 
            {!turnstileToken && (
              <div style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)' }}>
                Loading security check...
              </div>
            )}
 
            {error && (
              <div style={{
                background: 'var(--red-dim)', border: '1px solid rgba(255,68,68,0.3)',
                borderRadius: 'var(--radius)', padding: '10px 14px',
                fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)',
              }}>
                ⚠ {error}
              </div>
            )}
 
            <button
              type="submit"
              className="btn-primary"
              style={{ marginTop: 4, padding: '12px 20px', fontSize: 12 }}
              disabled={loading || !turnstileToken}
            >
              {loading ? <span className="spinner" /> : (mode === 'login' ? 'AUTHENTICATE' : 'CREATE ACCOUNT')}
            </button>
          </form>
 
          <div style={{ marginTop: 20, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>
            {mode === 'login' ? (
              <>No account? <button onClick={() => switchMode('register')} style={{ background: 'none', border: 'none', color: 'var(--green)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10 }}>REGISTER</button></>
            ) : (
              <>Have an account? <button onClick={() => switchMode('login')} style={{ background: 'none', border: 'none', color: 'var(--green)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10 }}>LOGIN</button></>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}