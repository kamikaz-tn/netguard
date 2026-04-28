import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth } from '../services/api.js'
 
// ── OS-specific config ─────────────────────────────────────────────────────────
const OS_OPTIONS = [
  { id: 'windows', label: 'WINDOWS', icon: '⊞' },
  { id: 'linux', label: 'LINUX', icon: '🐧' },
  { id: 'mac', label: 'MACOS', icon: '◉' },
]
 
function getSteps(os) {
  const isWin = os === 'windows'
 
  return [
    {
      num: '01',
      title: 'Step 1: Get Python',
      desc: 'Ensure Python 3.11 or later is installed.',
      code: isWin ? 'python --version' : 'python3 --version',
      link: { label: '+ Download Python', url: 'https://python.org/downloads' },
    },
    {
      num: '02',
      title: 'Step 2: Install Nmap',
      desc: 'Install Nmap to enable accurate host and port discovery.',
      code: null,
      note: isWin
        ? 'Important: Download the official Nmap installer for Windows and run it as an Administrator.'
        : os === 'linux'
          ? 'Use your package manager for installation.'
          : 'Use Homebrew for installation.',
      extraCode: isWin ? null : os === 'linux' ? 'sudo apt install nmap' : 'brew install nmap',
      link: { label: '+ Download Nmap', url: 'https://nmap.org/download' },
    },
    {
      num: '03',
      title: 'Step 3: Setup Dependencies',
      desc: 'Install required Python packages from requirements.txt.',
      code: isWin ? 'pip install -r requirements.txt' : 'pip3 install -r requirements.txt',
      link: null,
    },
    {
      num: '04',
      title: 'Step 4: Start the Scan',
      desc: isWin
        ? 'Run the command from your installation folder.'
        : 'Run with elevated permissions for ARP access.',
      code: isWin ? 'python agent.py --scan' : 'sudo python3 agent.py --scan',
      note: isWin
        ? 'Warning: Open PowerShell as an Administrator and run this from the installation folder.'
        : os === 'linux'
          ? 'Linux requires sudo for raw socket access used by ARP scanning.'
          : 'macOS requires sudo for raw socket access used by ARP scanning.',
      link: null,
    },
  ]
}
 
const AGENT_URL        = 'https://raw.githubusercontent.com/kamikaz-tn/netguard/refs/heads/main/agent/agent.py'
const REQUIREMENTS_URL = 'https://raw.githubusercontent.com/kamikaz-tn/netguard/refs/heads/main/agent/requirements.txt'
 
export default function AgentSetup() {
  const navigate = useNavigate()
  const [agreed, setAgreed]   = useState(false)
  const [copied, setCopied]   = useState(null)
  const [os, setOs]           = useState('windows')
  const [envError, setEnvError] = useState('')
 
  const steps = getSteps(os)
 
  function copyCode(code, id) {
    navigator.clipboard.writeText(code)
    setCopied(id)
    setTimeout(() => setCopied(null), 2000)
  }
 
  async function downloadFile(url, filename) {
    const response = await fetch(url)
    const blob = await response.blob()
    const blobUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = blobUrl
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(blobUrl)
  }
 
  async function downloadEnv() {
    setEnvError('')
    try {
      const me = await auth.me()
      const content = [
        `BACKEND_URL=https://netguard-production-4f1d.up.railway.app`,
        `AGENT_SECRET=netguard_agent_secret_2026`,
        `USER_ID=${me.user_id}`,
        `NETWORK_RANGE=`,
        `SCAN_TYPE=full`,
      ].join('\n')
 
      const blob = new Blob([content], { type: 'text/plain' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = 'netguard.env'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('downloadEnv failed:', err)
      setEnvError('Could not fetch your user ID. Make sure you are logged in.')
    }
  }
 
  return (
    <div className="animate-in" style={{ maxWidth: 980, margin: '0 auto', paddingBottom: 28 }}>
 
      {/* Header */}
      <div style={{ marginBottom: 30 }}>
        <button
          onClick={() => navigate('/overview')}
          style={{ background: 'none', border: 'none', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: 1.5, cursor: 'pointer', marginBottom: 16, padding: 0 }}
        >
          ← BACK TO OVERVIEW
        </button>
        <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 30, color: 'var(--text-bright)', letterSpacing: 2, marginBottom: 10 }}>
          RUN SCAN SETUP
        </h1>
        <p style={{ fontSize: 16, color: 'var(--text)', lineHeight: 1.7, maxWidth: 860 }}>
          Clean setup, clear steps, and high-contrast commands. Follow this once to deploy the local agent and send scan results
          securely to your NetGuard dashboard.
        </p>
      </div>
 
      {/* How it works */}
      <div className="card" style={{ marginBottom: 24, padding: '24px 24px' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-bright)', letterSpacing: 2, marginBottom: 16 }}>
          HOW IT WORKS
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 14 }}>
          {[
            { title: '1. Your Machine', text: 'The setup agent is deployed on your computer.', icon: '🖥' },
            { title: '2. ARP + Port Scan', text: 'It performs an automated scan of your local network.', icon: '🔎' },
            { title: '3. NetGuard Cloud', text: 'Scan results are securely sent for analysis.', icon: '☁' },
            { title: '4. Your Dashboard', text: 'View detailed results on your NetGuard account.', icon: '📊' },
          ].map((item, i, arr) => (
            <div key={item.title}>
              <div style={{
                background: 'var(--setup-flow-card-bg)',
                border: '1px solid var(--setup-flow-card-border)',
                borderRadius: 12,
                padding: '16px 18px',
                display: 'flex',
                alignItems: 'center',
                gap: 14,
              }}>
                <div style={{
                  width: 46, height: 46, flexShrink: 0,
                  borderRadius: 10,
                  border: '1px solid var(--setup-flow-icon-border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 24, background: 'var(--setup-flow-icon-bg)',
                }}>{item.icon}</div>
                <div>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--setup-flow-title)', marginBottom: 2 }}>{item.title}</div>
                  <div style={{ fontSize: 16, color: 'var(--setup-flow-text)', lineHeight: 1.55, fontWeight: 600 }}>{item.text}</div>
                </div>
              </div>
              {i < arr.length - 1 && <div style={{ textAlign: 'center', color: '#58b7ff', fontSize: 24, lineHeight: 1, margin: '8px 0' }}>↓</div>}
            </div>
          ))}
        </div>
      </div>
 
      {/* OS SELECTOR */}
      <div className="card" style={{ marginBottom: 24, padding: '24px 24px' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-bright)', letterSpacing: 2, marginBottom: 16 }}>
          SELECT YOUR OPERATING SYSTEM
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12 }}>
          {OS_OPTIONS.map(opt => (
            <button
              key={opt.id}
              onClick={() => setOs(opt.id)}
              style={{
                padding: '18px 10px',
                borderRadius: 12,
                border: os === opt.id ? '1px solid #58b7ff' : '1px solid var(--border)',
                background: os === opt.id ? 'rgba(88,183,255,0.14)' : 'rgba(255,255,255,0.01)',
                color: os === opt.id ? '#7ed2ff' : 'var(--muted)',
                fontFamily: 'var(--font-display)', fontSize: 18, letterSpacing: 1,
                cursor: 'pointer', transition: 'all 0.15s',
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                boxShadow: os === opt.id ? '0 0 18px rgba(88,183,255,0.14)' : 'none',
              }}
            >
              <span style={{ fontSize: 30 }}>{opt.icon}</span>
              {opt.label}
              {os === opt.id && (
                <span style={{ fontSize: 12, color: 'var(--green)', letterSpacing: 1, fontFamily: 'var(--font-mono)' }}>+ SELECTED</span>
              )}
            </button>
          ))}
        </div>
 
        <div style={{
          marginTop: 16, padding: '14px 16px',
          background: 'rgba(88,183,255,0.08)', border: '1px solid rgba(88,183,255,0.24)',
          borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 10,
          color: 'var(--text)', letterSpacing: 0.2, lineHeight: 1.8,
        }}>
          {os === 'windows' && 'NOTE: You must run PowerShell as an Administrator. Right-click the icon → "Run as Administrator".'}
          {os === 'linux' && 'NOTE: Run commands using sudo for ARP scan permissions (raw socket access).'}
          {os === 'mac' && 'NOTE: Use sudo for ARP scan permissions and Homebrew for Nmap installation.'}
        </div>
      </div>
 
      {/* Steps */}
      <div className="card" style={{ marginBottom: 24, padding: '24px 24px' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-bright)', letterSpacing: 2, marginBottom: 18 }}>
          SETUP STEPS
        </div>
        {steps.map((step, i) => (
          <div key={`${os}-${i}`} style={{
            display: 'flex', gap: 18, marginBottom: i < steps.length - 1 ? 18 : 0,
            background: 'var(--setup-step-card-bg)',
            border: '1px solid var(--setup-step-card-border)',
            borderRadius: 12, padding: 16,
          }}>
            <div style={{
              fontFamily: 'var(--font-display)', fontSize: 28, color: '#58b7ff',
              flexShrink: 0, lineHeight: 1, minWidth: 48, textAlign: 'center',
            }}>{step.num}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, color: 'var(--text-bright)', marginBottom: 8 }}>{step.title}</div>
              <div style={{ fontSize: 16, color: 'var(--text)', lineHeight: 1.6, marginBottom: 10 }}>{step.desc}</div>
 
              {step.code && (
                <div style={{ display: 'flex', alignItems: 'stretch', gap: 10, marginBottom: step.extraCode || step.note || step.link ? 10 : 0 }}>
                  <code style={{
                    background: 'var(--setup-code-bg)',
                    border: '1px solid var(--setup-code-border)',
                    borderRadius: 8, padding: '12px 14px',
                    fontFamily: 'var(--font-mono)', fontSize: 16, color: 'var(--setup-code-text)', flex: 1, display: 'flex', alignItems: 'center',
                  }}>
                    {step.code}
                  </code>
                  <button
                    onClick={() => copyCode(step.code, `${os}-${i}-main`)}
                    style={{
                      background: 'rgba(88,183,255,0.12)', border: '1px solid rgba(88,183,255,0.5)',
                      borderRadius: 8, padding: '0 16px', fontFamily: 'var(--font-mono)',
                      fontSize: 13, color: '#8dd8ff', cursor: 'pointer', flexShrink: 0, minWidth: 88,
                    }}
                  >
                    {copied === `${os}-${i}-main` ? '✓ COPIED' : 'COPY'}
                  </button>
                </div>
              )}
 
              {step.extraCode && (
                <div style={{ display: 'flex', alignItems: 'stretch', gap: 10, marginBottom: step.note || step.link ? 10 : 0 }}>
                  <code style={{
                    background: 'var(--setup-code-bg)',
                    border: '1px solid var(--setup-code-border)',
                    borderRadius: 8, padding: '12px 14px',
                    fontFamily: 'var(--font-mono)', fontSize: 16, color: 'var(--setup-code-text)', flex: 1, display: 'flex', alignItems: 'center',
                  }}>
                    {step.extraCode}
                  </code>
                  <button
                    onClick={() => copyCode(step.extraCode, `${os}-${i}-extra`)}
                    style={{
                      background: 'rgba(88,183,255,0.12)', border: '1px solid rgba(88,183,255,0.5)',
                      borderRadius: 8, padding: '0 16px', fontFamily: 'var(--font-mono)',
                      fontSize: 13, color: '#8dd8ff', cursor: 'pointer', flexShrink: 0, minWidth: 88,
                    }}
                  >
                    {copied === `${os}-${i}-extra` ? '✓ COPIED' : 'COPY'}
                  </button>
                </div>
              )}
 
              {step.note && (
                <div style={{
                  fontSize: 14, color: '#c3d8e8', marginBottom: step.link ? 8 : 0,
                  background: 'rgba(88,183,255,0.08)', border: '1px solid rgba(88,183,255,0.2)', borderRadius: 8, padding: '8px 10px',
                }}>
                  {step.note}
                </div>
              )}
 
              {step.link && (
                <a href={step.link.url} target="_blank" rel="noopener noreferrer"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 8,
                    fontFamily: 'var(--font-display)', fontSize: 15, color: '#8dd8ff',
                    textDecoration: 'none', letterSpacing: 0.5, border: '1px solid rgba(88,183,255,0.4)',
                    padding: '8px 12px', borderRadius: 8, background: 'rgba(88,183,255,0.09)',
                  }}>
                  ⭳ {step.link.label}
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
 
      {/* Safety notice */}
      <div style={{
        background: 'var(--setup-safe-bg)',
        border: '1px solid var(--setup-safe-border)',
        borderRadius: 12, padding: '22px 22px', marginBottom: 24,
      }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-bright)', letterSpacing: 2, marginBottom: 14 }}>
          WHAT THE AGENT DOES & DOES NOT DO
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {[
            { ok: true,  text: 'Scans devices on your local network (192.168.x.x)' },
            { ok: true,  text: 'Checks open ports on discovered devices' },
            { ok: true,  text: 'Sends scan results to your NetGuard account only' },
            { ok: true,  text: '100% open source — you can read every line' },
            { ok: false, text: 'Does NOT install anything on your machine' },
            { ok: false, text: 'Does NOT access your files, browser, or passwords' },
            { ok: false, text: 'Does NOT run in the background unless you use --watch' },
            { ok: false, text: 'Does NOT share data with any third party' },
          ].map((item, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 15, color: 'var(--text)',
              lineHeight: 1.55, border: '1px solid var(--border)', borderRadius: 10, padding: '10px 12px', background: 'rgba(255,255,255,0.01)',
            }}>
              <span style={{ color: item.ok ? 'var(--green)' : 'var(--red)', flexShrink: 0, marginTop: 1, fontSize: 18, fontWeight: 700 }}>
                {item.ok ? '🛡' : '✖'}
              </span>
              {item.text}
            </div>
          ))}
        </div>
      </div>
 
      {/* Consent + Download */}
      <div className="card" style={{ padding: '24px 24px' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-bright)', letterSpacing: 2, marginBottom: 14 }}>
          DOWNLOAD AGENT
        </div>
 
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', marginBottom: 20 }}>
          <input
            type="checkbox"
            checked={agreed}
            onChange={e => setAgreed(e.target.checked)}
            style={{ marginTop: 2, accentColor: 'var(--green)', width: 19, height: 19, flexShrink: 0 }}
          />
          <span style={{ fontSize: 16, color: 'var(--text)', lineHeight: 1.6, fontWeight: 600 }}>
            I understand that this script is open source, scans my network only, and does not harm my machine. I explicitly start it.
          </span>
        </label>
 
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <button
            className="btn-primary"
            disabled={!agreed}
            onClick={() => downloadFile(AGENT_URL, 'agent.py')}
            style={{ opacity: agreed ? 1 : 0.45, cursor: agreed ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, padding: '12px 16px' }}
          >
            ⇓ Download agent.py
          </button>
          <button
            className="btn-primary"
            disabled={!agreed}
            onClick={() => downloadFile(REQUIREMENTS_URL, 'requirements.txt')}
            style={{ opacity: agreed ? 1 : 0.45, cursor: agreed ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, padding: '12px 16px' }}
          >
            ⇓ Download requirements.txt
          </button>
          <button
            className="btn-primary"
            disabled={!agreed}
            onClick={downloadEnv}
            style={{ opacity: agreed ? 1 : 0.45, cursor: agreed ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, padding: '12px 16px' }}
          >
            ⇓ Download netguard.env
          </button>
          <a
            href="https://github.com/kamikaz-tn/netguard/tree/main/agent"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontFamily: 'var(--font-display)', fontSize: 14, color: 'var(--text)',
              textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 7,
              padding: '12px 16px', border: '1px solid var(--border2)', borderRadius: 'var(--radius)', background: 'rgba(255,255,255,0.01)',
            }}
          >
            View Source on Github
          </a>
        </div>
 
        {agreed && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', marginTop: 12, letterSpacing: 0.4, lineHeight: 1.8 }}>
            ℹ After downloading, rename{' '}
            <span style={{ color: 'var(--green)' }}>netguard.env</span>
            {' → '}
            <span style={{ color: 'var(--green)' }}>.env</span>
            {' '}and place it in the same folder as agent.py
          </div>
        )}
 
        {envError && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red)', marginTop: 10, letterSpacing: 0.4 }}>
            ⚠ {envError}
          </div>
        )}
 
        {!agreed && (
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 17, color: 'var(--text)', marginTop: 14, letterSpacing: 0.5, fontWeight: 600 }}>
            Check the box above to enable downloads.
          </div>
        )}
      </div>

      <style>{`
        @media (max-width: 900px) {
          .main-content { padding: 14px !important; }
        }
        @media (max-width: 820px) {
          .card {
            padding: 18px 16px !important;
          }
        }
      `}</style>
    </div>
  )
}