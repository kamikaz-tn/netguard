/**
 * netguard/frontend/src/pages/Verify.jsx
 * ────────────────────────────────────────
 * Handles email verification links.
 * The backend email now points here: /verify?token=xxx
 * This page calls the backend, shows success/error, then redirects.
 */

import { useState, useEffect, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { auth_state } from '../services/api.js'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function Verify() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token')

  const [status, setStatus] = useState('loading') // loading | success | error
  const [message, setMessage] = useState('')
  const [countdown, setCountdown] = useState(4)
  const calledRef = useRef(false)

  useEffect(() => {
    if (calledRef.current) return
    calledRef.current = true

    if (!token) {
      setStatus('error')
      setMessage('No verification token found in the URL. Please request a new verification email.')
      return
    }

    verifyToken(token)
  }, [token])

  // Countdown + redirect after success
  useEffect(() => {
    if (status !== 'success') return
    if (countdown <= 0) {
      const dest = auth_state.isLoggedIn() ? '/profile' : '/login'
      navigate(dest, { replace: true })
      return
    }
    const t = setTimeout(() => setCountdown(c => c - 1), 1000)
    return () => clearTimeout(t)
  }, [status, countdown, navigate])

  async function verifyToken(tok) {
    try {
      const res = await fetch(`${BASE_URL}/api/auth/verify-email?token=${encodeURIComponent(tok)}`, {
        method: 'GET',
        credentials: 'include',
        redirect: 'manual', // don't follow the redirect — we handle it ourselves
      })

      // Backend returns a redirect (302) to /profile?verified=1 — that means success
      if (res.type === 'opaqueredirect' || res.status === 0 || (res.status >= 300 && res.status < 400)) {
        setStatus('success')
        return
      }

      if (res.ok) {
        setStatus('success')
        return
      }

      const data = await res.json().catch(() => ({}))
      throw new Error(data.detail || `Verification failed (${res.status})`)
    } catch (err) {
      // Network errors when redirect is manual = success (CORS redirect)
      if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
        setStatus('success')
        return
      }
      setStatus('error')
      setMessage(err.message || 'Verification failed. The link may have expired.')
    }
  }

  const isLoggedIn = auth_state.isLoggedIn()
  const redirectDest = isLoggedIn ? 'your profile' : 'login'

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 24,
      fontFamily: 'var(--font)',
      backgroundImage: `
        repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.35) 2px, rgba(0,0,0,0.35) 3px),
        repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(232,53,74,0.04) 40px),
        repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(232,53,74,0.04) 40px)
      `,
    }}>
      <div style={{ width: '100%', maxWidth: 620, animation: 'hudBootUp 0.5s cubic-bezier(0.22,1,0.36,1) both' }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <img
            src="/netguard-logo.png"
            alt="NetGuard"
            style={{ width: 250, maxWidth: '92%', height: 'auto', margin: '0 auto 10px', display: 'block', filter: 'drop-shadow(0 0 16px rgba(232,53,74,0.22))' }}
          />
          <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)', fontSize: 12, letterSpacing: 2, marginTop: 4 }}>EMAIL VERIFICATION</div>
        </div>

        {/* Card */}
        <div className="card" style={{ padding: 38, textAlign: 'center' }}>

          {/* ── LOADING ── */}
          {status === 'loading' && (
            <div style={{ animation: 'hudBootUp 0.3s both' }}>
              <div style={{ marginBottom: 20 }}>
                <span className="spinner" style={{ width: 36, height: 36, borderWidth: 3 }} />
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, color: 'var(--text)', letterSpacing: 2, marginBottom: 10 }}>
                VERIFYING TOKEN
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--muted)', letterSpacing: 0.8 }}>
                Contacting verification server...
              </div>
              <div className="scan-bar" style={{ marginTop: 24, width: '100%' }} />
            </div>
          )}

          {/* ── SUCCESS ── */}
          {status === 'success' && (
            <div style={{ animation: 'hudBootUp 0.4s both' }}>
              {/* Animated checkmark */}
              <div style={{
                width: 72, height: 72,
                borderRadius: '50%',
                background: 'rgba(77,184,232,0.1)',
                border: '2px solid var(--blue)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                margin: '0 auto 20px',
                boxShadow: '0 0 24px rgba(77,184,232,0.2)',
                fontSize: 32,
                animation: 'hudBootUp 0.5s 0.1s both',
              }}>
                ✓
              </div>

              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--blue)', letterSpacing: 2, marginBottom: 10 }}>
                EMAIL VERIFIED
              </div>
              <div style={{ fontSize: 16, color: 'var(--text)', lineHeight: 1.7, marginBottom: 24 }}>
                Your email address has been successfully verified. Your NetGuard account is now fully active.
              </div>

              {/* Countdown */}
              <div style={{
                background: 'var(--surface2)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '12px 16px',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                color: 'var(--text)',
                letterSpacing: 1,
                marginBottom: 20,
              }}>
                Redirecting to {redirectDest} in{' '}
                <span style={{ color: 'var(--blue)', fontWeight: 700, fontSize: 16 }}>{countdown}</span>
                {' '}second{countdown !== 1 ? 's' : ''}...
              </div>

              <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
                {isLoggedIn ? (
                  <button className="btn-primary" onClick={() => navigate('/profile', { replace: true })}>
                    ▶ GO TO PROFILE
                  </button>
                ) : (
                  <button className="btn-primary" onClick={() => navigate('/login', { replace: true })}>
                    ▶ GO TO LOGIN
                  </button>
                )}
              </div>
            </div>
          )}

          {/* ── ERROR ── */}
          {status === 'error' && (
            <div style={{ animation: 'hudBootUp 0.4s both' }}>
              {/* Error icon */}
              <div style={{
                width: 72, height: 72,
                borderRadius: '50%',
                background: 'var(--red-dim)',
                border: '2px solid var(--red)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                margin: '0 auto 20px',
                boxShadow: '0 0 24px var(--red-glow)',
                fontSize: 28,
                animation: 'hudBootUp 0.5s 0.1s both',
              }}>
                ⚠
              </div>

              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--red)', letterSpacing: 2, marginBottom: 10 }}>
                VERIFICATION FAILED
              </div>
              <div style={{ fontSize: 16, color: 'var(--text)', lineHeight: 1.7, marginBottom: 16 }}>
                {message}
              </div>

              <div style={{
                background: 'var(--red-dim)',
                border: '1px solid rgba(232,53,74,0.3)',
                borderRadius: 'var(--radius)',
                padding: '12px 16px',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                color: 'var(--text)',
                letterSpacing: 1,
                marginBottom: 20,
                textAlign: 'left',
                lineHeight: 1.8,
              }}>
                <div style={{ color: 'var(--amber)', marginBottom: 6 }}>POSSIBLE CAUSES:</div>
                <div>· Link expired (tokens are valid for 24 hours)</div>
                <div>· Link already used (each token is single-use)</div>
                <div>· Invalid or malformed token in URL</div>
              </div>

              <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
                <button className="btn-primary" onClick={() => navigate('/login', { replace: true })}>
                  ▶ GO TO LOGIN
                </button>
                {isLoggedIn && (
                  <button className="btn-ghost" onClick={() => navigate('/profile', { replace: true })}>
                    REQUEST NEW LINK
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ textAlign: 'center', marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted2)', letterSpacing: 1 }}>
          NETGUARD SECURITY PLATFORM · v2.0.0
        </div>
      </div>
    </div>
  )
}
