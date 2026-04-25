import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth, auth_state } from '../services/api.js'
 
// ── Use the same BASE_URL as the rest of the app ──────────────────────────────
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
 
// ── API calls — all use BASE_URL + credentials:include (cookie auth) ──────────
const profileApi = {
  get: () =>
    fetch(`${BASE_URL}/api/auth/profile`, { credentials: 'include' }).then(async r => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Failed to load profile')
      return r.json()
    }),
 
  update: (body) =>
    fetch(`${BASE_URL}/api/auth/profile`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(async r => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Update failed')
      return r.json()
    }),
 
  changePassword: (body) =>
    fetch(`${BASE_URL}/api/auth/change-password`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(async r => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Failed to change password')
      return r.json()
    }),
 
  sendVerification: () =>
    fetch(`${BASE_URL}/api/auth/send-verification`, {
      method: 'POST',
      credentials: 'include',
    }).then(async r => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Failed to send email')
      return r.json()
    }),
 
  deleteAccount: () =>
    fetch(`${BASE_URL}/api/auth/account`, {
      method: 'DELETE',
      credentials: 'include',
    }).then(async r => {
      if (!r.ok) throw new Error((await r.json()).detail || 'Failed to delete account')
      return r.json()
    }),
}
 
// ── Avatar — initials + color if no URL set ───────────────────────────────────
const AVATAR_COLORS = ['#e8354a','#ff6b35','#4db8e8','#a855f7','#22c55e','#f59e0b','#ec4899']
 
function Avatar({ username, avatarUrl, size = 80 }) {
  const [imgError, setImgError] = useState(false)
  const color = AVATAR_COLORS[(username?.charCodeAt(0) ?? 0) % AVATAR_COLORS.length]
  const initials = (username ?? 'U').slice(0, 2).toUpperCase()
 
  if (avatarUrl && !imgError) {
    return (
      <img
        src={avatarUrl}
        alt={username}
        style={{ width: size, height: size, borderRadius: '50%', objectFit: 'cover', border: '2px solid var(--border2)' }}
        onError={() => setImgError(true)}
      />
    )
  }
 
  return (
    <div style={{
      width: size, height: size, borderRadius: '50%',
      background: color + '22',
      border: `2px solid ${color}`,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--font-display)', fontSize: size * 0.35,
      color, fontWeight: 700, flexShrink: 0,
      boxShadow: `0 0 16px ${color}44`,
    }}>
      {initials}
    </div>
  )
}
 
// ── Section wrapper ───────────────────────────────────────────────────────────
function Section({ title, children, danger = false }) {
  return (
    <div className="card" style={{
      marginBottom: 16,
      borderColor: danger ? 'rgba(232,53,74,0.3)' : undefined,
    }}>
      <div className="card-title" style={{ color: danger ? 'var(--red-bright)' : undefined }}>
        {title}
      </div>
      {children}
    </div>
  )
}
 
// ── Inline alert ──────────────────────────────────────────────────────────────
function Alert({ msg, type = 'error' }) {
  if (!msg) return null
  const color = type === 'success' ? 'var(--blue)' : 'var(--red)'
  const bg    = type === 'success' ? 'rgba(77,184,232,0.08)' : 'var(--red-dim)'
  return (
    <div style={{
      padding: '10px 14px', borderRadius: 'var(--radius)',
      background: bg, border: `1px solid ${color}`,
      fontFamily: 'var(--font-mono)', fontSize: 11, color,
      marginTop: 12, letterSpacing: 0.5,
    }}>
      {type === 'success' ? '✓ ' : '⚠ '}{msg}
    </div>
  )
}
 
// ── Stat chip ─────────────────────────────────────────────────────────────────
function StatChip({ label, value, color }) {
  return (
    <div style={{
      flex: 1, textAlign: 'center', padding: '14px 10px',
      background: 'var(--surface2)', borderRadius: 'var(--radius)',
      border: '1px solid var(--border)',
    }}>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, color, fontWeight: 700, lineHeight: 1 }}>{value ?? 0}</div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 6, letterSpacing: 2 }}>{label}</div>
    </div>
  )
}
 
// ── Password strength meter ───────────────────────────────────────────────────
function PasswordStrength({ password }) {
  const checks = [
    { label: '8+ characters',      ok: password.length >= 8 },
    { label: 'Uppercase letter',   ok: /[A-Z]/.test(password) },
    { label: 'Number',             ok: /[0-9]/.test(password) },
    { label: 'Special character',  ok: /[^A-Za-z0-9]/.test(password) },
  ]
  const score  = checks.filter(c => c.ok).length
  const colors = ['var(--red)', 'var(--red)', 'var(--amber)', 'var(--amber)', 'var(--blue)']
  const labels = ['', 'WEAK', 'WEAK', 'FAIR', 'STRONG']
 
  return (
    <div>
      <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
        {[0,1,2,3].map(i => (
          <div key={i} style={{
            flex: 1, height: 3, borderRadius: 2,
            background: i < score ? colors[score] : 'var(--border)',
            transition: 'background 0.3s',
          }} />
        ))}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: colors[score], letterSpacing: 1, marginLeft: 6, minWidth: 50 }}>
          {labels[score]}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {checks.map(({ label, ok }) => (
          <span key={label} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: ok ? 'var(--blue)' : 'var(--muted)', letterSpacing: 0.5 }}>
            {ok ? '✓' : '○'} {label}
          </span>
        ))}
      </div>
    </div>
  )
}
 
// ── Shared label style ────────────────────────────────────────────────────────
const labelStyle = {
  fontFamily:    'var(--font-mono)',
  fontSize:      9,
  color:         'var(--muted)',
  letterSpacing: 2,
  display:       'block',
  marginBottom:  6,
  textTransform: 'uppercase',
}
 
// ── Eye icon ──────────────────────────────────────────────────────────────────
const EyeIcon = ({ show }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24"
    fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {show ? (
      <>
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
        <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
      </>
    ) : (
      <>
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </>
    )}
  </svg>
)
 
// ── Main Profile page ─────────────────────────────────────────────────────────
export default function Profile() {
  const navigate = useNavigate()
  const [profile, setProfile]       = useState(null)
  const [loading, setLoading]       = useState(true)
  const [loadError, setLoadError]   = useState('')
 
  // Info form
  const [infoForm, setInfoForm]     = useState({ username: '', email: '', bio: '', avatar_url: '' })
  const [infoSaving, setInfoSaving] = useState(false)
  const [infoMsg, setInfoMsg]       = useState(null)
 
  // Password form
  const [pwForm, setPwForm]         = useState({ current_password: '', new_password: '', confirm: '' })
  const [pwSaving, setPwSaving]     = useState(false)
  const [pwMsg, setPwMsg]           = useState(null)
  const [showPw, setShowPw]         = useState({ current: false, new: false, confirm: false })
 
  // Misc states
  const [verifyMsg, setVerifyMsg]         = useState(null)
  const [verifyLoading, setVerifyLoading] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState('')
  const [deleteLoading, setDeleteLoading] = useState(false)
  const [deleteMsg, setDeleteMsg]         = useState(null)
 
  useEffect(() => { loadProfile() }, [])
 
  async function loadProfile() {
    setLoading(true)
    setLoadError('')
    try {
      const data = await profileApi.get()
      setProfile(data)
      setInfoForm({
        username:   data.username   ?? '',
        email:      data.email      ?? '',
        bio:        data.bio        ?? '',
        avatar_url: data.avatar_url ?? '',
      })
    } catch (e) {
      setLoadError(e.message || 'Failed to load profile. Make sure you are logged in.')
    } finally {
      setLoading(false)
    }
  }
 
  async function saveInfo(e) {
    e.preventDefault()
    setInfoSaving(true)
    setInfoMsg(null)
    try {
      const res = await profileApi.update({
        username:   infoForm.username   || undefined,
        email:      infoForm.email      || undefined,
        bio:        infoForm.bio,
        avatar_url: infoForm.avatar_url || undefined,
      })
      setInfoMsg({ type: 'success', text: 'Profile updated successfully.' })
      if (res.username) auth_state.setUsername(res.username)
      await loadProfile()
    } catch (err) {
      setInfoMsg({ type: 'error', text: err.message || 'Update failed.' })
    } finally {
      setInfoSaving(false)
    }
  }
 
  async function savePassword(e) {
    e.preventDefault()
    setPwMsg(null)
    if (pwForm.new_password !== pwForm.confirm) {
      setPwMsg({ type: 'error', text: 'New passwords do not match.' })
      return
    }
    if (pwForm.new_password.length < 8) {
      setPwMsg({ type: 'error', text: 'Password must be at least 8 characters.' })
      return
    }
    setPwSaving(true)
    try {
      await profileApi.changePassword({
        current_password: pwForm.current_password,
        new_password:     pwForm.new_password,
      })
      setPwMsg({ type: 'success', text: 'Password changed successfully.' })
      setPwForm({ current_password: '', new_password: '', confirm: '' })
    } catch (err) {
      setPwMsg({ type: 'error', text: err.message || 'Failed to change password.' })
    } finally {
      setPwSaving(false)
    }
  }
 
  async function sendVerification() {
    setVerifyLoading(true)
    setVerifyMsg(null)
    try {
      const res = await profileApi.sendVerification()
      setVerifyMsg({ type: 'success', text: res.detail ?? 'Verification email sent.' })
    } catch (err) {
      setVerifyMsg({ type: 'error', text: err.message || 'Failed to send verification email.' })
    } finally {
      setVerifyLoading(false)
    }
  }
 
  async function deleteAccount() {
    if (!profile?.username) return
    if (deleteConfirm !== profile.username) {
      setDeleteMsg({ type: 'error', text: `Type your username "${profile.username}" to confirm.` })
      return
    }
    setDeleteLoading(true)
    try {
      await profileApi.deleteAccount()
      auth_state.clearUsername()
      navigate('/login')
    } catch (err) {
      setDeleteMsg({ type: 'error', text: err.message || 'Failed to delete account. Try again.' })
      setDeleteLoading(false)
    }
  }
 
  // ── Loading state ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: 12 }}>
        <div className="spinner" />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', letterSpacing: 2 }}>
          LOADING PROFILE...
        </span>
      </div>
    )
  }
 
  // ── Load error state ──────────────────────────────────────────────────────
  if (loadError) {
    return (
      <div style={{ maxWidth: 500, margin: '60px auto', textAlign: 'center' }}>
        <div className="card" style={{ borderColor: 'rgba(232,53,74,0.3)' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)', marginBottom: 12 }}>
            ⚠ {loadError}
          </div>
          <button className="btn-primary" onClick={loadProfile}>↺ RETRY</button>
        </div>
      </div>
    )
  }
 
  const joinDate = profile?.created_at
    ? new Date(profile.created_at).toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })
    : 'Unknown'
 
  return (
    <div className="animate-in" style={{ maxWidth: 700 }}>
 
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 3, marginBottom: 4 }}>
          MODULE_ID: PRF-001
        </div>
        <h1 style={{ fontSize: 22, letterSpacing: 3, color: 'var(--text-bright)', marginBottom: 4 }}>
          ACCOUNT PROFILE
        </h1>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>
          Manage your identity, security, and preferences
        </div>
      </div>
 
      {/* ── Identity card ── */}
      <Section title="IDENTITY">
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 20 }}>
          <Avatar username={profile?.username} avatarUrl={profile?.avatar_url} size={72} />
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, color: 'var(--text-bright)', letterSpacing: 2, fontWeight: 700 }}>
              {profile?.username}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
              {profile?.email}
              {profile?.email_verified
                ? <span style={{ marginLeft: 8, color: 'var(--blue)', fontSize: 9 }}>✓ VERIFIED</span>
                : <span style={{ marginLeft: 8, color: 'var(--amber)', fontSize: 9 }}>⚠ UNVERIFIED</span>
              }
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 4, letterSpacing: 1 }}>
              Member since {joinDate}
            </div>
          </div>
        </div>
 
        {/* Scan stats */}
        <div style={{ display: 'flex', gap: 10 }}>
          <StatChip label="TOTAL SCANS"   value={profile?.total_scans}   color="var(--blue)" />
          <StatChip label="DEVICES FOUND" value={profile?.total_devices} color="var(--amber)" />
          <StatChip label="THREATS FOUND" value={profile?.total_threats} color="var(--red-bright)" />
        </div>
      </Section>
 
      {/* ── Edit profile ── */}
      <Section title="EDIT PROFILE">
        <form onSubmit={saveInfo} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
 
          {/* Avatar URL */}
          <div>
            <label style={labelStyle}>AVATAR URL <span style={{ color: 'var(--muted2)', fontWeight: 400 }}>(optional)</span></label>
            <input
              type="url"
              value={infoForm.avatar_url}
              onChange={e => setInfoForm(f => ({ ...f, avatar_url: e.target.value }))}
              placeholder="https://example.com/your-photo.jpg"
            />
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 4 }}>
              Paste any public image URL. Leave blank to use your initials.
            </div>
          </div>
 
          {/* Username */}
          <div>
            <label style={labelStyle}>USERNAME</label>
            <input
              type="text"
              value={infoForm.username}
              onChange={e => setInfoForm(f => ({ ...f, username: e.target.value }))}
              minLength={3} maxLength={32} required
            />
          </div>
 
          {/* Email */}
          <div>
            <label style={labelStyle}>EMAIL ADDRESS</label>
            <input
              type="email"
              value={infoForm.email}
              onChange={e => setInfoForm(f => ({ ...f, email: e.target.value }))}
              required
            />
          </div>
 
          {/* Bio */}
          <div>
            <label style={labelStyle}>BIO <span style={{ color: 'var(--muted2)', fontWeight: 400 }}>(max 200 chars)</span></label>
            <textarea
              value={infoForm.bio}
              onChange={e => setInfoForm(f => ({ ...f, bio: e.target.value }))}
              maxLength={200} rows={3}
              placeholder="A short description about yourself..."
              style={{ resize: 'vertical', minHeight: 72 }}
            />
            <div style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 2 }}>
              {infoForm.bio.length}/200
            </div>
          </div>
 
          <Alert msg={infoMsg?.text} type={infoMsg?.type} />
 
          <button
            type="submit"
            className="btn-primary"
            disabled={infoSaving}
            style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            {infoSaving
              ? <><span className="spinner" style={{ width: 12, height: 12 }} />SAVING</>
              : '▶ SAVE CHANGES'
            }
          </button>
        </form>
      </Section>
 
      {/* ── Email verification ── */}
      <Section title="EMAIL VERIFICATION">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', marginBottom: 4 }}>
              {profile?.email_verified
                ? <><span style={{ color: 'var(--blue)' }}>✓</span> Your email address is verified.</>
                : <><span style={{ color: 'var(--amber)' }}>⚠</span> Your email address is not verified.</>
              }
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>
              {profile?.email}
            </div>
          </div>
          {!profile?.email_verified && (
            <button
              className="btn-ghost"
              onClick={sendVerification}
              disabled={verifyLoading}
              style={{ whiteSpace: 'nowrap' }}
            >
              {verifyLoading
                ? <><span className="spinner" style={{ width: 10, height: 10, marginRight: 6 }} />SENDING</>
                : '✉ SEND VERIFICATION EMAIL'
              }
            </button>
          )}
        </div>
        <Alert msg={verifyMsg?.text} type={verifyMsg?.type} />
      </Section>
 
      {/* ── Change password ── */}
      <Section title="CHANGE PASSWORD">
        <form onSubmit={savePassword} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {[
            { key: 'current', field: 'current_password', label: 'CURRENT PASSWORD',      placeholder: 'Current password' },
            { key: 'new',     field: 'new_password',     label: 'NEW PASSWORD',           placeholder: 'Min. 8 characters' },
            { key: 'confirm', field: 'confirm',          label: 'CONFIRM NEW PASSWORD',   placeholder: 'Repeat new password' },
          ].map(({ key, field, label, placeholder }) => (
            <div key={field}>
              <label style={labelStyle}>{label}</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPw[key] ? 'text' : 'password'}
                  value={pwForm[field]}
                  onChange={e => setPwForm(f => ({ ...f, [field]: e.target.value }))}
                  required
                  style={{ paddingRight: 40 }}
                  placeholder={placeholder}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(p => ({ ...p, [key]: !p[key] }))}
                  style={{
                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--muted)', padding: 0,
                  }}
                >
                  <EyeIcon show={showPw[key]} />
                </button>
              </div>
            </div>
          ))}
 
          {pwForm.new_password.length > 0 && (
            <PasswordStrength password={pwForm.new_password} />
          )}
 
          <Alert msg={pwMsg?.text} type={pwMsg?.type} />
 
          <button
            type="submit"
            className="btn-primary"
            disabled={pwSaving}
            style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            {pwSaving
              ? <><span className="spinner" style={{ width: 12, height: 12 }} />UPDATING</>
              : '▶ UPDATE PASSWORD'
            }
          </button>
        </form>
      </Section>
 
      {/* ── Danger zone ── */}
      <Section title="DANGER ZONE" danger>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', marginBottom: 16, lineHeight: 1.8 }}>
          Permanently delete your account and all associated data — scans, devices, alerts, findings.
          <span style={{ color: 'var(--red)', display: 'block', marginTop: 4 }}>This action cannot be undone.</span>
        </div>
 
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            value={deleteConfirm}
            onChange={e => setDeleteConfirm(e.target.value)}
            placeholder={profile?.username ? `Type "${profile.username}" to confirm` : 'Loading...'}
            style={{ maxWidth: 260, borderColor: deleteConfirm ? 'var(--red)' : undefined }}
          />
          <button
            className="btn-danger"
            onClick={deleteAccount}
            disabled={deleteLoading || deleteConfirm !== profile?.username}
            style={{
              opacity: deleteConfirm === profile?.username ? 1 : 0.4,
              cursor: deleteConfirm === profile?.username ? 'pointer' : 'not-allowed',
              display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            {deleteLoading
              ? <><span className="spinner" style={{ width: 10, height: 10 }} />DELETING</>
              : '✕ DELETE ACCOUNT'
            }
          </button>
        </div>
        <Alert msg={deleteMsg?.text} type={deleteMsg?.type} />
      </Section>
 
    </div>
  )
}