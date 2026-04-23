import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth } from '../services/api.js'   // ← FIX 1: was missing
 
// ── OS-specific config ─────────────────────────────────────────────────────────
const OS_OPTIONS = [
  { id: 'windows', label: 'Windows',  icon: '🪟' },
  { id: 'linux',   label: 'Linux',    icon: '🐧' },
  { id: 'mac',     label: 'macOS',    icon: '🍎' },
]
 
function getSteps(os) {
  const isWin = os === 'windows'
 
  return [
    {
      num: '01',
      title: 'Install Python',
      desc: 'Make sure Python 3.11 or higher is installed on your machine.',
      code: isWin ? 'python --version' : 'python3 --version',
      link: { label: 'Download Python', url: 'https://python.org/downloads' },
    },
    {
      num: '02',
      title: 'Install Nmap',
      desc: 'The agent uses Nmap to scan open ports on your network.',
      code: null,
      note: isWin
        ? 'Download the Windows installer from nmap.org and run it as Administrator.'
        : os === 'linux'
          ? 'Or install via terminal:'
          : 'Or install via Homebrew:',
      extraCode: isWin ? null : os === 'linux' ? 'sudo apt install nmap' : 'brew install nmap',
      link: { label: 'Download Nmap', url: 'https://nmap.org/download' },
    },
    {
      num: '03',
      title: 'Install Agent Dependencies',
      desc: 'Open a terminal in the folder where you downloaded the agent and run:',
      code: isWin ? 'pip install -r requirements.txt' : 'pip3 install -r requirements.txt',
      link: null,
    },
    {
      num: '04',
      title: 'Run the Agent',
      desc: isWin
        ? 'Run PowerShell or Command Prompt as Administrator, then run:'
        : 'ARP scanning requires root access. Run with sudo:',
      code: isWin ? 'python agent.py --scan' : 'sudo python3 agent.py --scan',
      note: isWin
        ? 'Right-click PowerShell → "Run as Administrator" before running the command.'
        : os === 'linux'
          ? 'On Linux, sudo grants the raw socket access needed for ARP scanning.'
          : 'On macOS, sudo grants the raw socket access needed for ARP scanning.',
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
 
  // FIX 2: renamed to netguard.env (browsers block dotfiles)
  // FIX 3: removed accidental leading spaces in template literal
  // FIX 4: added document.body.appendChild for cross-browser support
  async function downloadEnv() {
    setEnvError('')
    try {
      const me = await auth.me()
      const content = [
        `BACKEND_URL=https://netguard-production-4f1d.up.railway.app`,
        `AGENT_SECRET=netguard_agent_secret_2024`,
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
    <div className="animate-in" style={{ maxWidth: 760 }}>
 
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <button
          onClick={() => navigate('/overview')}
          style={{ background: 'none', border: 'none', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 2, cursor: 'pointer', marginBottom: 16, padding: 0 }}
        >
          ← BACK TO OVERVIEW
        </button>
        <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2, marginBottom: 8 }}>
          LOCAL AGENT SETUP
        </h1>
        <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.7, maxWidth: 600 }}>
          NetGuard uses a lightweight local agent to scan your network. Because your router and devices
          live on your home LAN, the scan must run <span style={{ color: 'var(--green)' }}>on your machine</span> — not from the cloud.
          Results are pushed securely to your NetGuard dashboard.
        </p>
      </div>
 
      {/* How it works */}
      <div className="card" style={{ marginBottom: 20, padding: '20px 24px' }}>
        <div className="card-title" style={{ marginBottom: 16 }}>HOW IT WORKS</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 0, flexWrap: 'wrap' }}>
          {[
            { icon: '💻', label: 'Your Machine' },
            { icon: '→',  label: null },
            { icon: '🔍', label: 'ARP + Port Scan' },
            { icon: '→',  label: null },
            { icon: '☁️', label: 'NetGuard Cloud' },
            { icon: '→',  label: null },
            { icon: '📊', label: 'Your Dashboard' },
          ].map((item, i) => (
            item.label === null
              ? <div key={i} style={{ color: 'var(--muted)', fontSize: 18, margin: '0 8px' }}>→</div>
              : (
                <div key={i} style={{ textAlign: 'center', padding: '10px 16px', background: 'var(--bg)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 22 }}>{item.icon}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 4, letterSpacing: 1 }}>{item.label}</div>
                </div>
              )
          ))}
        </div>
      </div>
 
      {/* OS SELECTOR */}
      <div className="card" style={{ marginBottom: 20, padding: '20px 24px' }}>
        <div className="card-title" style={{ marginBottom: 14 }}>SELECT YOUR OPERATING SYSTEM</div>
        <div style={{ display: 'flex', gap: 10 }}>
          {OS_OPTIONS.map(opt => (
            <button
              key={opt.id}
              onClick={() => setOs(opt.id)}
              style={{
                flex: 1, padding: '12px 8px',
                borderRadius: 'var(--radius)',
                border: os === opt.id ? '1px solid var(--green)' : '1px solid var(--border)',
                background: os === opt.id ? 'rgba(0,229,160,0.08)' : 'var(--bg)',
                color: os === opt.id ? 'var(--green)' : 'var(--muted)',
                fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 1,
                cursor: 'pointer', transition: 'all 0.15s',
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                boxShadow: os === opt.id ? '0 0 12px rgba(0,229,160,0.1)' : 'none',
              }}
            >
              <span style={{ fontSize: 22 }}>{opt.icon}</span>
              {opt.label.toUpperCase()}
              {os === opt.id && (
                <span style={{ fontSize: 8, color: 'var(--green)', letterSpacing: 2 }}>● SELECTED</span>
              )}
            </button>
          ))}
        </div>
 
        <div style={{
          marginTop: 14, padding: '10px 14px',
          background: 'rgba(0,229,160,0.04)', border: '1px solid rgba(0,229,160,0.15)',
          borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 10,
          color: 'var(--muted)', letterSpacing: 0.5, lineHeight: 1.7,
        }}>
          {os === 'windows' && '⚠ Windows: Run PowerShell or CMD as Administrator. Right-click the icon → "Run as Administrator".'}
          {os === 'linux'   && '⚠ Linux: sudo is required for ARP scanning (raw socket access). Commands below use python3 and pip3.'}
          {os === 'mac'     && '⚠ macOS: sudo is required for ARP scanning (raw socket access). Make sure Homebrew is installed for Nmap.'}
        </div>
      </div>
 
      {/* Steps */}
      <div className="card" style={{ marginBottom: 20, padding: '20px 24px' }}>
        <div className="card-title" style={{ marginBottom: 20 }}>SETUP STEPS</div>
        {steps.map((step, i) => (
          <div key={`${os}-${i}`} style={{ display: 'flex', gap: 16, marginBottom: i < steps.length - 1 ? 28 : 0 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, color: 'var(--green)', opacity: 0.4, flexShrink: 0, lineHeight: 1 }}>{step.num}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', letterSpacing: 1, marginBottom: 6 }}>{step.title}</div>
              <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.6, marginBottom: 8 }}>{step.desc}</div>
 
              {step.code && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: step.extraCode || step.note ? 8 : 0 }}>
                  <code style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '6px 12px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--green)', flex: 1 }}>
                    {step.code}
                  </code>
                  <button
                    onClick={() => copyCode(step.code, `${os}-${i}-main`)}
                    style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '6px 10px', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', cursor: 'pointer', flexShrink: 0 }}
                  >
                    {copied === `${os}-${i}-main` ? '✓ COPIED' : 'COPY'}
                  </button>
                </div>
              )}
 
              {step.extraCode && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: step.note ? 8 : 0 }}>
                  <code style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '6px 12px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--green)', flex: 1 }}>
                    {step.extraCode}
                  </code>
                  <button
                    onClick={() => copyCode(step.extraCode, `${os}-${i}-extra`)}
                    style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '6px 10px', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', cursor: 'pointer', flexShrink: 0 }}
                  >
                    {copied === `${os}-${i}-extra` ? '✓ COPIED' : 'COPY'}
                  </button>
                </div>
              )}
 
              {step.note && (
                <div style={{ fontSize: 11, color: 'var(--muted)', fontStyle: 'italic', opacity: 0.75, marginBottom: step.link ? 6 : 0 }}>
                  ℹ {step.note}
                </div>
              )}
 
              {step.link && (
                <a href={step.link.url} target="_blank" rel="noopener noreferrer"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--green)', textDecoration: 'none', letterSpacing: 1 }}>
                  ↗ {step.link.label}
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
 
      {/* Safety notice */}
      <div style={{
        background: 'rgba(0,229,160,0.05)', border: '1px solid rgba(0,229,160,0.2)',
        borderRadius: 'var(--radius)', padding: '16px 20px', marginBottom: 20,
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--green)', letterSpacing: 1, marginBottom: 10 }}>🛡 WHAT THE AGENT DOES & DOES NOT DO</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
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
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>
              <span style={{ color: item.ok ? 'var(--green)' : 'var(--red)', flexShrink: 0, marginTop: 1 }}>{item.ok ? '✓' : '✗'}</span>
              {item.text}
            </div>
          ))}
        </div>
      </div>
 
      {/* Consent + Download */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <div className="card-title" style={{ marginBottom: 16 }}>DOWNLOAD AGENT</div>
 
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', marginBottom: 20 }}>
          <input
            type="checkbox"
            checked={agreed}
            onChange={e => setAgreed(e.target.checked)}
            style={{ marginTop: 2, accentColor: 'var(--green)', width: 15, height: 15, flexShrink: 0 }}
          />
          <span style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>
            I understand that this is an open-source script that only scans my local network and sends results
            to my NetGuard account. It does not harm my machine, does not collect personal data, and does not
            run in the background unless I explicitly start it.
          </span>
        </label>
 
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <button
            className="btn-primary"
            disabled={!agreed}
            onClick={() => downloadFile(AGENT_URL, 'agent.py')}
            style={{ opacity: agreed ? 1 : 0.4, cursor: agreed ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            ↓ DOWNLOAD agent.py
          </button>
          <button
            className="btn-ghost"
            disabled={!agreed}
            onClick={() => downloadFile(REQUIREMENTS_URL, 'requirements.txt')}
            style={{ opacity: agreed ? 1 : 0.4, cursor: agreed ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            ↓ DOWNLOAD requirements.txt
          </button>
          <button
            className="btn-ghost"
            disabled={!agreed}
            onClick={downloadEnv}
            style={{ opacity: agreed ? 1 : 0.4, cursor: agreed ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', gap: 8 }}
          >
            ↓ DOWNLOAD netguard.env
          </button>
          <a
            href="https://github.com/kamikaz-tn/netguard/tree/main/agent"
            target="_blank"
            rel="noopener noreferrer"
            style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}
          >
            ↗ VIEW SOURCE ON GITHUB
          </a>
        </div>
 
        {/* Rename hint */}
        {agreed && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 12, letterSpacing: 0.5, lineHeight: 1.8 }}>
            ℹ After downloading, rename{' '}
            <span style={{ color: 'var(--green)' }}>netguard.env</span>
            {' → '}
            <span style={{ color: 'var(--green)' }}>.env</span>
            {' '}and place it in the same folder as agent.py
          </div>
        )}
 
        {/* Error */}
        {envError && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)', marginTop: 10, letterSpacing: 0.5 }}>
            ⚠ {envError}
          </div>
        )}
 
        {!agreed && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 10, letterSpacing: 1 }}>
            ↑ Check the box above to enable download
          </div>
        )}
      </div>
    </div>
  )
}