import { useState } from 'react'
import { password as pwdApi } from '../services/api.js'

export default function PwnedCheck() {
  const [pwd, setPwd] = useState('')
  const [show, setShow] = useState(false)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function checkPassword() {
    if (!pwd) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const res = await pwdApi.check(pwd)
      setResult(res)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="animate-in">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>PASSWORD BREACH CHECK</h1>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
          k-anonymity model — your password never leaves this browser
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

        {/* Checker */}
        <div className="card">
          <div className="card-title">Check Password</div>

          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <div style={{ flex: 1, position: 'relative' }}>
                <input
                  type={show ? 'text' : 'password'}
                  value={pwd}
                  onChange={e => { setPwd(e.target.value); setResult(null) }}
                  placeholder="enter password to check..."
                  onKeyDown={e => e.key === 'Enter' && checkPassword()}
                />
              </div>
              <button className="btn-ghost" onClick={() => setShow(s => !s)} style={{ padding: '10px 14px', flexShrink: 0 }}>
                {show ? 'HIDE' : 'SHOW'}
              </button>
            </div>
            <button className="btn-primary" onClick={checkPassword} disabled={loading || !pwd} style={{ width: '100%' }}>
              {loading ? <><span className="spinner" style={{ width: 12, height: 12 }} /> CHECKING...</> : 'CHECK BREACH STATUS'}
            </button>
          </div>

          {/* Privacy badges */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
            {['SHA-1 hash only', 'Never stored', 'k-anonymity', 'HIBP API'].map(t => (
              <span key={t} className="badge badge-safe">{t}</span>
            ))}
          </div>

          {error && (
            <div style={{ background: 'var(--red-dim)', border: '1px solid rgba(255,68,68,0.3)', borderRadius: 'var(--radius)', padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)' }}>
              ⚠ {error}
            </div>
          )}

          {result && (
            <div style={{
              background: result.pwned ? 'var(--red-dim)' : 'var(--green-dim)',
              border: `1px solid ${result.pwned ? 'rgba(255,68,68,0.3)' : 'rgba(0,229,160,0.3)'}`,
              borderRadius: 'var(--radius)', padding: '16px',
              animation: 'fadeIn 0.3s ease',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: result.pwned ? 'var(--red)' : 'var(--green)', marginBottom: 6 }}>
                {result.pwned ? '⚠ PASSWORD COMPROMISED' : '✓ PASSWORD NOT FOUND'}
              </div>
              {result.pwned ? (
                <>
                  <div style={{ fontSize: 12, color: 'var(--text)', marginBottom: 8 }}>
                    Found <strong style={{ color: 'var(--red)' }}>{result.count.toLocaleString()}</strong> times in known data breaches.
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>
                    Change this password immediately on every service where you use it. Use a password manager to generate a unique replacement.
                  </div>
                </>
              ) : (
                <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>
                  Not found in breach databases. Still make sure it's long, unique, and not reused across accounts.
                </div>
              )}
            </div>
          )}
        </div>

        {/* How it works */}
        <div className="card">
          <div className="card-title">How k-Anonymity Works</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {[
              { n: '01', title: 'SHA-1 Hash', desc: 'Your password is hashed locally in the browser using SHA-1. The actual password never leaves your device.' },
              { n: '02', title: 'Prefix Only', desc: 'Only the first 5 characters of the hash are sent to the HaveIBeenPwned API — never the full hash.' },
              { n: '03', title: 'API Returns Matches', desc: 'HIBP returns all hash suffixes that match that 5-char prefix. Could be hundreds of hashes — HIBP can\'t tell which one you care about.' },
              { n: '04', title: 'Local Comparison', desc: 'Your browser checks whether your full hash is in the returned list. The comparison happens entirely locally.' },
            ].map(({ n, title, desc }) => (
              <div key={n} style={{ display: 'flex', gap: 14 }}>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--green)', fontSize: 20, flexShrink: 0, lineHeight: 1 }}>{n}</div>
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', marginBottom: 4 }}>{title}</div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 16, background: '#060a0b', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '12px 14px', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', lineHeight: 2 }}>
            <span style={{ color: 'var(--green)' }}>hash</span> = SHA1("yourpassword")<br />
            <span style={{ color: 'var(--green)' }}>sent</span> = hash[0:5]  <span style={{ color: 'var(--muted)' }}>← only this leaves browser</span><br />
            <span style={{ color: 'var(--green)' }}>kept</span> = hash[5:]  <span style={{ color: 'var(--muted)' }}>← checked locally</span>
          </div>
        </div>
      </div>
    </div>
  )
}
