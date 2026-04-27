import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth } from '../services/api.js'
 
const TURNSTILE_SITE_KEY = '0x4AAAAAADBVh15Y0oJUYMbv'
 
// ── Radar Canvas ───────────────────────────────────────────────────────────────
function RadarCanvas() {
  const canvasRef = useRef(null)
 
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const SIZE = canvas.offsetWidth
    canvas.width = SIZE
    canvas.height = SIZE
    const cx = SIZE / 2, cy = SIZE / 2, R = SIZE / 2 - 4
 
    const blips = Array.from({ length: 8 }, () => ({
      angle: Math.random() * Math.PI * 2,
      dist: (0.3 + Math.random() * 0.6) * R,
      alpha: 0,
    }))
 
    let angle = 0
    let animId
 
    function draw() {
      ctx.clearRect(0, 0, SIZE, SIZE)
 
      ctx.strokeStyle = 'rgba(232,53,74,0.15)'
      ctx.lineWidth = 0.5
      for (let r = R * 0.25; r <= R; r += R * 0.25) {
        ctx.beginPath()
        ctx.arc(cx, cy, r, 0, Math.PI * 2)
        ctx.stroke()
      }
 
      ctx.strokeStyle = 'rgba(232,53,74,0.1)'
      ctx.beginPath(); ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy); ctx.stroke()
      ctx.beginPath(); ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R); ctx.stroke()
 
      ctx.fillStyle = 'rgba(232,53,74,0.4)'
      ctx.font = '8px Share Tech Mono, monospace'
      ctx.textAlign = 'center'
      ;[0, 60, 120, 180, 240, 300].forEach(deg => {
        const rad = (deg - 90) * Math.PI / 180
        const tx = cx + (R + 12) * Math.cos(rad)
        const ty = cy + (R + 12) * Math.sin(rad)
        ctx.fillText(deg, tx, ty + 3)
      })
 
      const gradStart = angle - 1.2
      for (let a = gradStart; a < angle; a += 0.02) {
        const t = (a - gradStart) / 1.2
        ctx.beginPath()
        ctx.moveTo(cx, cy)
        ctx.arc(cx, cy, R, a, a + 0.03)
        ctx.closePath()
        ctx.fillStyle = `rgba(232,53,74,${t * 0.18})`
        ctx.fill()
      }
 
      ctx.beginPath()
      ctx.moveTo(cx, cy)
      ctx.lineTo(cx + Math.cos(angle) * R, cy + Math.sin(angle) * R)
      ctx.strokeStyle = 'rgba(232,53,74,0.9)'
      ctx.lineWidth = 1.5
      ctx.stroke()
 
      blips.forEach(blip => {
        const diff = ((angle - blip.angle) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2)
        if (diff < 0.15) blip.alpha = 1
        blip.alpha *= 0.985
 
        if (blip.alpha > 0.05) {
          const bx = cx + Math.cos(blip.angle) * blip.dist
          const by = cy + Math.sin(blip.angle) * blip.dist
          ctx.beginPath()
          ctx.arc(bx, by, 3, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(232,53,74,${blip.alpha})`
          ctx.fill()
          ctx.beginPath()
          ctx.arc(bx, by, 6, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(232,53,74,${blip.alpha * 0.3})`
          ctx.fill()
        }
      })
 
      ctx.beginPath()
      ctx.arc(cx, cy, R, 0, Math.PI * 2)
      ctx.strokeStyle = 'rgba(232,53,74,0.35)'
      ctx.lineWidth = 1.5
      ctx.stroke()
 
      angle += 0.025
      animId = requestAnimationFrame(draw)
    }
 
    draw()
    return () => cancelAnimationFrame(animId)
  }, [])
 
  return (
    <canvas
      ref={canvasRef}
      style={{ width: '100%', height: '100%', display: 'block', opacity: 0.85 }}
    />
  )
}
 
// ── Oscilloscope Wave ─────────────────────────────────────────────────────────
function WaveCanvas() {
  const canvasRef = useRef(null)
 
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    canvas.width = canvas.offsetWidth
    canvas.height = canvas.offsetHeight
    const W = canvas.width, H = canvas.height
    let t = 0, animId
 
    function draw() {
      ctx.clearRect(0, 0, W, H)
      ctx.beginPath()
      for (let x = 0; x < W; x++) {
        const y = H / 2 + Math.sin((x / W) * 8 * Math.PI + t) * (H * 0.25) +
          Math.sin((x / W) * 3 * Math.PI + t * 0.7) * (H * 0.1)
        x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
      }
      ctx.strokeStyle = 'rgba(232,53,74,0.4)'
      ctx.lineWidth = 1
      ctx.stroke()
      t += 0.04
      animId = requestAnimationFrame(draw)
    }
    draw()
    return () => cancelAnimationFrame(animId)
  }, [])
 
  return <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />
}
 
// ── System Status Widget ──────────────────────────────────────────────────────
const SYSTEM_ITEMS = [
  { label: 'NETWORK',    status: 'SECURE',    ok: true },
  { label: 'FIREWALL',   status: 'ACTIVE',    ok: true },
  { label: 'IDS/IPS',    status: 'ACTIVE',    ok: true },
  { label: 'ENDPOINTS',  status: '1,287',     ok: true },
  { label: 'THREATS(24H)', status: '2,341',   ok: false },
]
 
// ── Real-time Threat Feed ─────────────────────────────────────────────────────
const THREAT_FEED = [
  { type: 'PORT SCAN',    loc: '192.168.1.45',  sev: 'MEDIUM',   time: '10:24:31' },
  { type: 'SQL INJECT',   loc: '203.0.113.77',  sev: 'HIGH',     time: '10:24:28' },
  { type: 'DDoS ATTACK',  loc: '198.51.100.23', sev: 'CRITICAL', time: '10:24:17' },
  { type: 'UNAUTH ACCESS',loc: '172.16.0.9',    sev: 'HIGH',     time: '10:24:12' },
  { type: 'MALWARE',      loc: '192.0.2.55',    sev: 'MEDIUM',   time: '10:24:05' },
]
 
const SEV_COLOR = { CRITICAL: 'var(--red-bright)', HIGH: 'var(--red)', MEDIUM: 'var(--amber)' }
 
// ── Boot sequence lines ───────────────────────────────────────────────────────
const BOOT_LINES = [
  '> NETGUARD SECURITY MONITOR v2.0',
  '> Initializing cryptographic modules...',
  '> Loading threat database...',
  '> Establishing secure channel...',
  '> System ready.',
]
 
export default function Login() {
  const navigate = useNavigate()
  const [mode, setMode]               = useState('login')
  const [form, setForm]               = useState({ username: '', email: '', password: '' })
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState('')
  const turnstileRef = useRef(null)
  const widgetIdRef  = useRef(null)
  const [bootLines, setBootLines]     = useState([])
  const [bootDone, setBootDone]       = useState(false)
 
  useEffect(() => {
    let i = 0
    const id = setInterval(() => {
      if (i < BOOT_LINES.length) { setBootLines(l => [...l, BOOT_LINES[i]]); i++ }
      else { clearInterval(id); setTimeout(() => setBootDone(true), 300) }
    }, 180)
    return () => clearInterval(id)
  }, [])
 
  function renderWidget() {
    if (!window.turnstile || !turnstileRef.current) return
    if (widgetIdRef.current !== null) { try { window.turnstile.remove(widgetIdRef.current) } catch {} widgetIdRef.current = null }
    setTurnstileToken('')
    widgetIdRef.current = window.turnstile.render(turnstileRef.current, {
      sitekey: TURNSTILE_SITE_KEY, theme: 'dark',
      callback: (token) => setTurnstileToken(token),
      'expired-callback': () => setTurnstileToken(''),
      'error-callback':   () => setTurnstileToken(''),
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
      if (mode === 'login') await auth.login(form.username, form.password, turnstileToken)
      else await auth.register(form.username, form.email, form.password, turnstileToken)
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
    <div style={{ minHeight: '100vh', display: 'flex', overflow: 'hidden', position: 'relative', background: 'var(--bg)' }}>
 
      {/* ── Boot overlay — no blinking cursor ── */}
      {!bootDone && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, background: 'var(--bg-deep)', display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '0 40px', animation: bootLines.length === BOOT_LINES.length ? 'fadeOutBoot 0.4s 0.5s forwards' : 'none' }}>
          <style>{`@keyframes fadeOutBoot { to { opacity: 0; pointer-events: none; } }`}</style>
          {bootLines.map((line, i) => (
            <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: i === bootLines.length - 1 ? 'var(--red-bright)' : 'var(--muted)', letterSpacing: 1, marginBottom: 6, animation: 'hudBootUp 0.2s ease both' }}>
              {line}
            </div>
          ))}
        </div>
      )}
 
      {/* ── LEFT: Radar Panel ── */}
      <div style={{ width: 320, flexShrink: 0, background: 'var(--surface)', borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column', padding: '24px 20px', gap: 16, position: 'relative', overflow: 'hidden' }}
        className="login-left-panel">
 
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 32, height: 32, border: '2px solid var(--red)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--red)', fontSize: 16, background: 'var(--red-dim)', boxShadow: '0 0 10px var(--red-glow)' }}>⬡</div>
          <div>
            <div style={{ fontFamily: 'var(--font-display)', color: 'var(--text-bright)', fontSize: 15, letterSpacing: 4, fontWeight: 700 }}>NETGUARD</div>
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 7, letterSpacing: 2 }}>NETWORK SECURITY PLATFORM</div>
          </div>
        </div>
 
        {/* Global status line */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', background: 'var(--surface2)', borderRadius: 4, border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 1 }}>SYSTEM STATUS</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--blue)', animation: 'pulse 2s ease infinite', boxShadow: '0 0 5px var(--blue)' }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--blue)', letterSpacing: 1 }}>SECURE</span>
          </div>
        </div>
 
        {/* Radar */}
        <div style={{ aspectRatio: '1', width: '100%', maxWidth: 260, margin: '0 auto', position: 'relative' }}>
          <RadarCanvas />
        </div>
 
        {/* System Status list */}
        <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '10px 12px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--red)', letterSpacing: 2, marginBottom: 8 }}>SYSTEM STATUS</div>
          {SYSTEM_ITEMS.map((item, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '3px 0', borderBottom: i < SYSTEM_ITEMS.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1 }}>{item.label}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 5, height: 5, borderRadius: '50%', background: item.ok ? 'var(--blue)' : 'var(--red)' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: item.ok ? 'var(--blue)' : 'var(--red)' }}>{item.status}</span>
              </div>
            </div>
          ))}
        </div>
 
        {/* Threat feed */}
        <div style={{ flex: 1, background: 'var(--surface2)', border: '1px solid var(--border)', borderLeft: '2px solid var(--red)', borderRadius: 4, padding: '10px 12px', overflow: 'hidden' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--red)', letterSpacing: 2, marginBottom: 8 }}>REAL-TIME THREAT MONITOR</div>
          {THREAT_FEED.map((t, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)', fontSize: 9, fontFamily: 'var(--font-mono)' }}>
              <span style={{ color: 'var(--muted)', flexShrink: 0, fontSize: 8 }}>{t.time}</span>
              <span style={{ color: SEV_COLOR[t.sev] || 'var(--muted)', flexShrink: 0, fontSize: 8 }}>●</span>
              <span style={{ color: 'var(--text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9 }}>{t.type}</span>
              <span style={{ color: SEV_COLOR[t.sev] || 'var(--muted)', flexShrink: 0, fontSize: 8 }}>{t.sev}</span>
            </div>
          ))}
        </div>
 
        {/* Version */}
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted2)', letterSpacing: 1 }}>
          v2.0.0 · © 2026 NetGuard
        </div>
      </div>
 
      {/* ── CENTER: Login form ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px 24px', position: 'relative', overflow: 'hidden' }}>
 
        {/* Background wave */}
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 60, opacity: 0.5 }}>
          <WaveCanvas />
        </div>
 
        {/* Background grid glow */}
        <div style={{ position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%,-50%)', width: 500, height: 500, background: 'radial-gradient(ellipse, rgba(232,53,74,0.05) 0%, transparent 70%)', pointerEvents: 'none' }} />
 
        {/* Corner accents */}
        {[{ top: 20, left: 20, borderWidth: '2px 0 0 2px' }, { top: 20, right: 20, borderWidth: '2px 2px 0 0' }, { bottom: 20, left: 20, borderWidth: '0 0 2px 2px' }, { bottom: 20, right: 20, borderWidth: '0 2px 2px 0' }].map((pos, i) => (
          <div key={i} style={{ position: 'absolute', width: 40, height: 40, borderStyle: 'solid', borderColor: 'rgba(232,53,74,0.2)', ...pos }} />
        ))}
 
        <div style={{ width: '100%', maxWidth: 400, zIndex: 1, animation: 'hudBootUp 0.5s 0.8s both cubic-bezier(0.22,1,0.36,1)' }}>
 
          {/* Logo */}
          <div style={{ textAlign: 'center', marginBottom: 28 }}>
            <div style={{ width: 56, height: 56, border: '2px solid var(--red)', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, color: 'var(--red)', background: 'var(--red-dim)', boxShadow: '0 0 20px var(--red-glow)', margin: '0 auto 10px' }}>⬡</div>
            <div style={{ fontFamily: 'var(--font-display)', color: 'var(--text-bright)', fontSize: 22, letterSpacing: 5, fontWeight: 700 }}>NETGUARD</div>
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 9, letterSpacing: 3, marginTop: 2 }}>NETWORK SECURITY MONITOR</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--red)', letterSpacing: 2, marginTop: 8 }}>[ AUTHENTICATION REQUIRED ]</div>
          </div>
 
          {/* Card */}
          <div className="card" style={{ padding: '24px' }}>
            {/* Tabs */}
            <div style={{ display: 'flex', marginBottom: 20, borderBottom: '1px solid var(--border)' }}>
              {[['login', 'Access Terminal'], ['register', 'Register']].map(([m, label]) => (
                <button key={m} onClick={() => switchMode(m)} style={{ flex: 1, background: 'none', border: 'none', borderBottom: mode === m ? '2px solid var(--red)' : '2px solid transparent', color: mode === m ? 'var(--red-bright)' : 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 2, padding: '8px 0', marginBottom: -1, cursor: 'pointer', transition: 'all 0.2s' }}>
                  {label.toUpperCase()}
                </button>
              ))}
            </div>
 
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
 
              {/* Username */}
              <div>
                <label style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, display: 'block', marginBottom: 5 }}>
                  <span style={{ color: 'var(--red)', marginRight: 4 }}>›</span>USERNAME
                </label>
                <div style={{ position: 'relative' }}>
                  <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)', fontSize: 13 }}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                  </span>
                  <input type="text" value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} placeholder="enter identifier..." required autoComplete="username" style={{ paddingLeft: 34 }} />
                </div>
              </div>
 
              {mode === 'register' && (
                <div>
                  <label style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, display: 'block', marginBottom: 5 }}>
                    <span style={{ color: 'var(--red)', marginRight: 4 }}>›</span>EMAIL
                  </label>
                  <input type="email" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} placeholder="enter email..." required />
                </div>
              )}
 
              {/* Password */}
              <div>
                <label style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, display: 'block', marginBottom: 5 }}>
                  <span style={{ color: 'var(--red)', marginRight: 4 }}>›</span>PASSWORD
                </label>
                <div style={{ position: 'relative' }}>
                  <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)', fontSize: 13 }}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                  </span>
                  <input type={showPassword ? 'text' : 'password'} value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} placeholder="enter passphrase..." required autoComplete="current-password" style={{ paddingLeft: 34, paddingRight: 44 }} />
                  <button type="button" onClick={() => setShowPassword(p => !p)} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--muted)', fontSize: 14, padding: 0, letterSpacing: 0 }}>
                    {showPassword ? (
                      <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                    ) : (
                      <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
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
                  Loading security check...
                </div>
              )}
 
              {/* Error */}
              {error && (
                <div className="terminal-block" style={{ borderLeftColor: 'var(--red)', background: 'var(--red-dim)', padding: '8px 12px' }}>
                  <span style={{ color: 'var(--red)', marginRight: 6 }}>⚠</span>
                  <span style={{ color: 'var(--text)', fontSize: 11 }}>{error}</span>
                </div>
              )}
 
              {/* Submit */}
              <button type="submit" className="btn-primary" style={{ marginTop: 4, padding: '12px 20px', fontSize: 11, letterSpacing: 3, fontWeight: 700 }} disabled={loading || !turnstileToken}>
                {loading
                  ? <><span className="spinner" style={{ width: 12, height: 12, marginRight: 8 }} />AUTHENTICATING</>
                  : mode === 'login' ? '▶ AUTHENTICATE' : '▶ CREATE ACCOUNT'
                }
              </button>
            </form>
          </div>
 
          {/* Version tag */}
          <div style={{ textAlign: 'right', marginTop: 10, fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted2)', letterSpacing: 1 }}>
            SECURE ACCESS GATEWAY · v2.0.0
          </div>
        </div>
      </div>
 
      {/* ── RIGHT: Live stats ── */}
      <div style={{ width: 240, flexShrink: 0, background: 'var(--surface)', borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column', padding: '24px 16px', gap: 14, overflow: 'hidden' }}
        className="login-right-panel">
 
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 3, marginBottom: 4 }}>NETWORK OVERVIEW</div>
 
        {[
          { label: 'ACTIVE CONNECTIONS', val: '8,482',  color: 'var(--blue)' },
          { label: 'BLOCKED THREATS',    val: '248',    color: 'var(--red-bright)' },
          { label: 'DATA TRANSFER',      val: '2.34 TB', color: 'var(--amber)' },
        ].map(item => (
          <div key={item.label} style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '10px 12px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 1, marginBottom: 4 }}>{item.label}</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: item.color, fontWeight: 700 }}>{item.val}</div>
          </div>
        ))}
 
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 3, marginTop: 6 }}>THREAT LEVEL</div>
        <div style={{ background: 'var(--surface2)', border: '1px solid rgba(245,166,35,0.3)', borderRadius: 4, padding: '10px 12px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 1, marginBottom: 6 }}>CURRENT STATUS</div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--amber)', fontWeight: 700, marginBottom: 6 }}>MEDIUM</div>
          <div style={{ display: 'flex', gap: 3 }}>
            {[1,2,3].map(i => <div key={i} style={{ flex: 1, height: 4, borderRadius: 2, background: i <= 2 ? 'var(--amber)' : 'var(--border)', boxShadow: i <= 2 ? '0 0 4px var(--amber)' : 'none' }} />)}
          </div>
        </div>
 
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 3, marginTop: 6 }}>SYSTEM HEALTH</div>
        {[
          { label: 'FIREWALL',       status: 'ACTIVE', ok: true },
          { label: 'IDS/IPS',        status: 'ACTIVE', ok: true },
          { label: 'MALWARE PROT.',  status: 'ACTIVE', ok: true },
          { label: 'SSL INSPECTION', status: 'ACTIVE', ok: true },
        ].map((item, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 9 }}>
            <span style={{ color: 'var(--muted)' }}>{item.label}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--blue)' }} />
              <span style={{ color: 'var(--blue)' }}>{item.status}</span>
            </div>
          </div>
        ))}
 
        <div style={{ flex: 1 }} />
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted2)', letterSpacing: 0.5, lineHeight: 1.8, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
          <div>SYSTEM BOOT TIME:</div>
          <div style={{ color: 'var(--muted)' }}>2026-04-25 08:15:32 UTC</div>
          <div style={{ marginTop: 4 }}>PLATFORM VERSION: 2.0.0</div>
        </div>
      </div>
 
      {/* Hide side panels on mobile */}
      <style>{`
        @media (max-width: 900px) {
          .login-left-panel, .login-right-panel { display: none !important; }
        }
      `}</style>
    </div>
  )
}