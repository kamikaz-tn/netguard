import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth, auth_state } from '../services/api.js'
 
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
 
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
 
const AVATAR_COLORS = ['#e8354a','#ff6b35','#4db8e8','#a855f7','#22c55e','#f59e0b','#ec4899']
 
// ── Secure image upload validator ─────────────────────────────────────────────
// Validates: extension, MIME type, magic bytes (file signature), and size
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
const MAX_SIZE_BYTES = 2 * 1024 * 1024 // 2 MB
 
// Magic bytes (file signatures) for allowed image types
const MAGIC_BYTES = [
  { sig: [0xFF, 0xD8, 0xFF],               type: 'jpeg' }, // JPEG
  { sig: [0x89, 0x50, 0x4E, 0x47],         type: 'png'  }, // PNG
  { sig: [0x47, 0x49, 0x46, 0x38],         type: 'gif'  }, // GIF
  { sig: [0x52, 0x49, 0x46, 0x46],         type: 'webp' }, // WEBP (RIFF)
]
 
async function validateImageFile(file) {
  // 1. Size check
  if (file.size > MAX_SIZE_BYTES) {
    throw new Error('Image must be under 2 MB.')
  }
 
  // 2. Extension check
  const ext = '.' + file.name.split('.').pop().toLowerCase()
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    throw new Error('Only JPG, PNG, GIF, or WEBP images are allowed.')
  }
 
  // 3. MIME type check (browser-reported, secondary check)
  if (!ALLOWED_TYPES.includes(file.type)) {
    throw new Error('Invalid image type. Only JPG, PNG, GIF, or WEBP are accepted.')
  }
 
  // 4. Magic bytes check (read first 12 bytes of file to verify real format)
  const header = await new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = e => resolve(new Uint8Array(e.target.result))
    reader.onerror = () => reject(new Error('Could not read file.'))
    reader.readAsArrayBuffer(file.slice(0, 12))
  })
 
  const matched = MAGIC_BYTES.some(({ sig }) =>
    sig.every((byte, i) => header[i] === byte)
  )
  if (!matched) {
    throw new Error('File content does not match a valid image format. Upload rejected.')
  }
 
  // 5. Convert to base64 data URL (safe — stays client-side, no server upload)
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = e => resolve(e.target.result)
    reader.onerror = () => reject(new Error('Could not process image.'))
    reader.readAsDataURL(file)
  })
}
 
// Avatar component
function Avatar({ username, avatarUrl, size = 80 }) {
  const [imgError, setImgError] = useState(false)
  const color = AVATAR_COLORS[(username?.charCodeAt(0) ?? 0) % AVATAR_COLORS.length]
  const initials = (username ?? 'U').slice(0, 2).toUpperCase()
 
  useEffect(() => { setImgError(false) }, [avatarUrl])
 
  if (avatarUrl && avatarUrl.trim() && !imgError) {
    return (
      <img
        src={avatarUrl}
        alt={username}
        style={{ width: size, height: size, borderRadius: '50%', objectFit: 'cover', border: `2px solid ${color}` }}
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
 
function Section({ title, children, danger = false }) {
  return (
    <div className="card" style={{ marginBottom: 16, borderColor: danger ? 'rgba(232,53,74,0.3)' : undefined }}>
      <div className="card-title" style={{ color: danger ? 'var(--red-bright)' : undefined }}>{title}</div>
      {children}
    </div>
  )
}
 
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
 
function PasswordStrength({ password }) {
  const checks = [
    { label: '8+ characters',     ok: password.length >= 8 },
    { label: 'Uppercase letter',  ok: /[A-Z]/.test(password) },
    { label: 'Number',            ok: /[0-9]/.test(password) },
    { label: 'Special character', ok: /[^A-Za-z0-9]/.test(password) },
  ]
  const score  = checks.filter(c => c.ok).length
  const colors = ['var(--red)', 'var(--red)', 'var(--amber)', 'var(--amber)', 'var(--blue)']
  const labels = ['', 'WEAK', 'WEAK', 'FAIR', 'STRONG']
  return (
    <div>
      <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
        {[0,1,2,3].map(i => (
          <div key={i} style={{ flex: 1, height: 3, borderRadius: 2, background: i < score ? colors[score] : 'var(--border)', transition: 'background 0.3s' }} />
        ))}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: colors[score], letterSpacing: 1, marginLeft: 6, minWidth: 50 }}>{labels[score]}</span>
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
 
const labelStyle = {
  fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)',
  letterSpacing: 2, display: 'block', marginBottom: 6, textTransform: 'uppercase',
}
 
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
 
// ── Avatar Upload Section ─────────────────────────────────────────────────────
function AvatarUploadSection({ username, currentAvatar, onAvatarChange }) {
  const fileInputRef = useRef(null)
  const [uploadError, setUploadError] = useState('')
  const [uploading, setUploading]     = useState(false)
  const [activeTab, setActiveTab]     = useState('upload') // 'upload' | 'url'
  const [urlInput, setUrlInput]       = useState(currentAvatar?.startsWith('http') ? currentAvatar : '')
  const [dragOver, setDragOver]       = useState(false)
 
  async function handleFile(file) {
    if (!file) return
    setUploadError('')
    setUploading(true)
    try {
      const dataUrl = await validateImageFile(file)
      onAvatarChange(dataUrl)
    } catch (err) {
      setUploadError(err.message)
    } finally {
      setUploading(false)
    }
  }
 
  function handleFileInput(e) {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    // Reset input so same file can be re-selected
    e.target.value = ''
  }
 
  function handleDrop(e) {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }
 
  function handleUrlApply() {
    setUploadError('')
    const url = urlInput.trim()
    if (!url) {
      onAvatarChange('')
      return
    }
    // Basic URL sanity — must be http/https and not a script
    if (!/^https?:\/\/.+\.(jpg|jpeg|png|gif|webp)(\?.*)?$/i.test(url)) {
      setUploadError('URL must be a direct link ending in .jpg, .jpeg, .png, .gif, or .webp')
      return
    }
    onAvatarChange(url)
  }
 
  return (
    <div>
      <label style={labelStyle}>AVATAR IMAGE</label>
 
      {/* Tab switcher */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 12, border: '1px solid var(--border2)', borderRadius: 'var(--radius)', overflow: 'hidden', width: 'fit-content' }}>
        {[['upload', '↑ Upload File'], ['url', '🔗 Image URL']].map(([tab, label]) => (
          <button
            key={tab}
            type="button"
            onClick={() => { setActiveTab(tab); setUploadError('') }}
            style={{
              padding: '6px 16px',
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5,
              background: activeTab === tab ? 'var(--red-dim)' : 'transparent',
              color: activeTab === tab ? 'var(--red-bright)' : 'var(--muted)',
              border: 'none',
              borderRight: tab === 'upload' ? '1px solid var(--border2)' : 'none',
              cursor: 'pointer', transition: 'all 0.15s',
            }}
          >
            {label}
          </button>
        ))}
      </div>
 
      {activeTab === 'upload' ? (
        <div>
          {/* Drop zone */}
          <div
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: `2px dashed ${dragOver ? 'var(--red)' : 'var(--border2)'}`,
              borderRadius: 'var(--radius)',
              padding: '20px 16px',
              textAlign: 'center',
              cursor: 'pointer',
              background: dragOver ? 'var(--red-dim)' : 'var(--surface2)',
              transition: 'all 0.15s',
              position: 'relative',
            }}
          >
            {uploading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                <span className="spinner" style={{ width: 14, height: 14 }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>Validating image...</span>
              </div>
            ) : (
              <>
                <div style={{ fontSize: 24, marginBottom: 8 }}>📁</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', letterSpacing: 1, marginBottom: 4 }}>
                  Drop image here or click to browse
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 0.5 }}>
                  JPG · PNG · GIF · WEBP · Max 2 MB
                </div>
              </>
            )}
          </div>
 
          {/* Hidden file input — accept attribute as first defense */}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/jpeg,image/png,image/gif,image/webp"
            onChange={handleFileInput}
            style={{ display: 'none' }}
          />
 
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 6, lineHeight: 1.7, letterSpacing: 0.5 }}>
            🛡 Image is validated client-side (extension, MIME type, file signature) and stored as a data URL — it never leaves your browser as a raw file.
          </div>
        </div>
      ) : (
        <div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="url"
              value={urlInput}
              onChange={e => setUrlInput(e.target.value)}
              placeholder="https://example.com/photo.jpg"
              onKeyDown={e => e.key === 'Enter' && handleUrlApply()}
            />
            <button
              type="button"
              className="btn-ghost"
              onClick={handleUrlApply}
              style={{ flexShrink: 0, padding: '8px 14px', fontSize: 9 }}
            >
              APPLY
            </button>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 6, letterSpacing: 0.5 }}>
            Must be a direct link ending in .jpg, .jpeg, .png, .gif, or .webp
          </div>
        </div>
      )}
 
      {uploadError && (
        <div style={{
          marginTop: 8, padding: '8px 12px',
          background: 'var(--red-dim)', border: '1px solid rgba(232,53,74,0.3)',
          borderRadius: 'var(--radius)', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)',
        }}>
          ⚠ {uploadError}
        </div>
      )}
 
      {/* Clear button */}
      {currentAvatar && (
        <button
          type="button"
          onClick={() => { onAvatarChange(''); setUrlInput(''); setUploadError('') }}
          style={{
            marginTop: 8, background: 'none', border: 'none',
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)',
            cursor: 'pointer', letterSpacing: 1, padding: 0,
          }}
          onMouseEnter={e => e.target.style.color = 'var(--red)'}
          onMouseLeave={e => e.target.style.color = 'var(--muted)'}
        >
          ✕ Remove avatar
        </button>
      )}
    </div>
  )
}
 
// ── Main Profile page ─────────────────────────────────────────────────────────
export default function Profile() {
  const navigate = useNavigate()
  const [profile, setProfile]     = useState(null)
  const [loading, setLoading]     = useState(true)
  const [loadError, setLoadError] = useState('')
 
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('verified') === '1') {
      setVerifyMsg({ type: 'success', text: 'Email verified successfully! Your account is now verified.' })
      window.history.replaceState({}, '', '/profile')
    }
  }, [])
 
  const [infoForm, setInfoForm]         = useState({ username: '', email: '', avatar_url: '' })
  const [avatarPreview, setAvatarPreview] = useState('')
  const [infoSaving, setInfoSaving]     = useState(false)
  const [infoMsg, setInfoMsg]           = useState(null)
 
  const [pwForm, setPwForm]     = useState({ current_password: '', new_password: '', confirm: '' })
  const [pwSaving, setPwSaving] = useState(false)
  const [pwMsg, setPwMsg]       = useState(null)
  const [showPw, setShowPw]     = useState({ current: false, new: false, confirm: false })
 
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
        avatar_url: data.avatar_url ?? '',
      })
      setAvatarPreview(data.avatar_url ?? '')
    } catch (e) {
      setLoadError(e.message || 'Failed to load profile. Make sure you are logged in.')
    } finally {
      setLoading(false)
    }
  }
 
  // Called when avatar changes (upload or URL)
  function handleAvatarChange(newValue) {
    setInfoForm(f => ({ ...f, avatar_url: newValue }))
    setAvatarPreview(newValue)
  }
 
  async function saveInfo(e) {
    e.preventDefault()
    setInfoSaving(true)
    setInfoMsg(null)
    try {
      const res = await profileApi.update({
        username:   infoForm.username   || undefined,
        email:      infoForm.email      || undefined,
        avatar_url: infoForm.avatar_url ?? '',
      })
      setInfoMsg({ type: 'success', text: 'Profile updated successfully.' })
      if (res.username) auth_state.setUsername(res.username)
 
      // Persist avatar to sessionStorage so sidebar picks it up immediately
      if (infoForm.avatar_url !== undefined) {
        sessionStorage.setItem('ng_avatar', infoForm.avatar_url)
        // Dispatch event so Layout can react without a page reload
        window.dispatchEvent(new CustomEvent('ng_avatar_updated', { detail: infoForm.avatar_url }))
      }
 
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
      await profileApi.changePassword({ current_password: pwForm.current_password, new_password: pwForm.new_password })
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
      setVerifyMsg({ type: 'success', text: res.detail ?? 'Verification email sent. Check your inbox.' })
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
      setDeleteMsg({ type: 'error', text: err.message || 'Failed to delete account.' })
      setDeleteLoading(false)
    }
  }
 
  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: 12 }}>
        <div className="spinner" />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', letterSpacing: 2 }}>LOADING PROFILE...</span>
      </div>
    )
  }
 
  if (loadError) {
    return (
      <div style={{ maxWidth: 500, margin: '60px auto', textAlign: 'center' }}>
        <div className="card" style={{ borderColor: 'rgba(232,53,74,0.3)' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)', marginBottom: 12 }}>⚠ {loadError}</div>
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
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 3, marginBottom: 4 }}>MODULE_ID: PRF-001</div>
        <h1 style={{ fontSize: 22, letterSpacing: 3, color: 'var(--text-bright)', marginBottom: 4 }}>ACCOUNT PROFILE</h1>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>Manage your identity and security settings</div>
      </div>
 
      {/* ── Identity card ── */}
      <Section title="IDENTITY">
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 20 }}>
          <Avatar username={profile?.username} avatarUrl={avatarPreview} size={72} />
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 20, color: 'var(--text-bright)', letterSpacing: 2, fontWeight: 700 }}>{profile?.username}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
              {profile?.email}
              {profile?.email_verified
                ? <span style={{ marginLeft: 8, color: 'var(--blue)', fontSize: 9 }}>✓ VERIFIED</span>
                : <span style={{ marginLeft: 8, color: 'var(--amber)', fontSize: 9 }}>⚠ UNVERIFIED</span>}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 4, letterSpacing: 1 }}>Member since {joinDate}</div>
          </div>
        </div>
 
        <div style={{ display: 'flex', gap: 10 }}>
          <StatChip label="TOTAL SCANS"   value={profile?.total_scans}   color="var(--blue)" />
          <StatChip label="DEVICES FOUND" value={profile?.total_devices} color="var(--amber)" />
          <StatChip label="THREATS FOUND" value={profile?.total_threats} color="var(--red-bright)" />
        </div>
      </Section>
 
      {/* ── Edit profile ── */}
      <Section title="EDIT PROFILE">
        <form onSubmit={saveInfo} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
 
          {/* Avatar section — upload or URL */}
          <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', flexWrap: 'wrap' }}>
            {/* Live preview */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <Avatar username={profile?.username} avatarUrl={avatarPreview} size={80} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 1 }}>PREVIEW</span>
            </div>
 
            <div style={{ flex: 1, minWidth: 240 }}>
              <AvatarUploadSection
                username={profile?.username}
                currentAvatar={avatarPreview}
                onAvatarChange={handleAvatarChange}
              />
            </div>
          </div>
 
          {/* Divider */}
          <div style={{ height: 1, background: 'var(--border)' }} />
 
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
 
          <Alert msg={infoMsg?.text} type={infoMsg?.type} />
 
          <button
            type="submit"
            className="btn-primary"
            disabled={infoSaving}
            style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            {infoSaving
              ? <><span className="spinner" style={{ width: 12, height: 12 }} />SAVING</>
              : '▶ SAVE CHANGES'}
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
                : <><span style={{ color: 'var(--amber)' }}>⚠</span> Your email address is not verified.</>}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>{profile?.email}</div>
          </div>
          {!profile?.email_verified && (
            <button className="btn-ghost" onClick={sendVerification} disabled={verifyLoading} style={{ whiteSpace: 'nowrap' }}>
              {verifyLoading
                ? <><span className="spinner" style={{ width: 10, height: 10, marginRight: 6 }} />SENDING</>
                : '✉ SEND VERIFICATION EMAIL'}
            </button>
          )}
        </div>
        {!profile?.email_verified && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 10, lineHeight: 1.8, padding: '8px 12px', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            ℹ After clicking the link in the email, you will be redirected back here and your account will be marked as verified.
            If the button in the email doesn't work, copy the full URL and paste it into your browser while logged in.
          </div>
        )}
        <Alert msg={verifyMsg?.text} type={verifyMsg?.type} />
      </Section>
 
      {/* ── Change password ── */}
      <Section title="CHANGE PASSWORD">
        <form onSubmit={savePassword} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {[
            { key: 'current', field: 'current_password', label: 'CURRENT PASSWORD',    placeholder: 'Current password' },
            { key: 'new',     field: 'new_password',     label: 'NEW PASSWORD',         placeholder: 'Min. 8 characters' },
            { key: 'confirm', field: 'confirm',          label: 'CONFIRM NEW PASSWORD', placeholder: 'Repeat new password' },
          ].map(({ key, field, label, placeholder }) => (
            <div key={field}>
              <label style={labelStyle}>{label}</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPw[key] ? 'text' : 'password'}
                  value={pwForm[field]}
                  onChange={e => setPwForm(f => ({ ...f, [field]: e.target.value }))}
                  required style={{ paddingRight: 40 }} placeholder={placeholder}
                />
                <button type="button" onClick={() => setShowPw(p => ({ ...p, [key]: !p[key] }))}
                  style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--muted)', padding: 0 }}>
                  <EyeIcon show={showPw[key]} />
                </button>
              </div>
            </div>
          ))}
          {pwForm.new_password.length > 0 && <PasswordStrength password={pwForm.new_password} />}
          <Alert msg={pwMsg?.text} type={pwMsg?.type} />
          <button type="submit" className="btn-primary" disabled={pwSaving}
            style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8 }}>
            {pwSaving ? <><span className="spinner" style={{ width: 12, height: 12 }} />UPDATING</> : '▶ UPDATE PASSWORD'}
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
          <button className="btn-danger" onClick={deleteAccount}
            disabled={deleteLoading || deleteConfirm !== profile?.username}
            style={{ opacity: deleteConfirm === profile?.username ? 1 : 0.4, cursor: deleteConfirm === profile?.username ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8 }}>
            {deleteLoading ? <><span className="spinner" style={{ width: 10, height: 10 }} />DELETING</> : '✕ DELETE ACCOUNT'}
          </button>
        </div>
        <Alert msg={deleteMsg?.text} type={deleteMsg?.type} />
      </Section>
    </div>
  )
}