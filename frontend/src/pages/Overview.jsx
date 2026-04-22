import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { scan } from '../services/api.js'
 
// ── Stat Card — "Data Module" ─────────────────────────────────────────────────
function StatCard({ label, value, color = 'var(--red)', sub, icon, delay = 0 }) {
  const [displayed, setDisplayed] = useState(0)
 
  // Number roll-up animation
  useEffect(() => {
    if (typeof value !== 'number') return
    let start = 0
    const end   = value
    const dur   = 600
    const step  = 16
    const inc   = (end / (dur / step))
    const t = setInterval(() => {
      start = Math.min(start + inc, end)
      setDisplayed(Math.round(start))
      if (start >= end) clearInterval(t)
    }, step)
    return () => clearInterval(t)
  }, [value])
 
  return (
    <div className="card" style={{
      padding: '16px 20px',
      animation: `hudBootUp 0.4s ${delay}s both cubic-bezier(0.22,1,0.36,1)`,
    }}>
      {/* Top: label */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2 }}>
          {label.toUpperCase()}
        </div>
        {icon && <span style={{ fontSize: 14, opacity: 0.4 }}>{icon}</span>}
      </div>
 
      {/* Value */}
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 36, color, lineHeight: 1, fontWeight: 700, letterSpacing: 1 }}>
        {typeof value === 'number' ? displayed : (value ?? '—')}
      </div>
 
      {/* Sub */}
      {sub && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 6, letterSpacing: 1 }}>
          {sub}
        </div>
      )}
 
      {/* Bottom accent line */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0, height: 1,
        background: `linear-gradient(90deg, ${color}, transparent)`,
        opacity: 0.3, borderRadius: '0 0 var(--radius) var(--radius)',
      }} />
    </div>
  )
}
 
// ── Risk Ring ─────────────────────────────────────────────────────────────────
function RiskRing({ score }) {
  const r      = 44
  const circ   = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color  = score >= 70 ? 'var(--red-bright)'
    : score >= 40 ? 'var(--amber)'
    : 'var(--blue)'
 
  return (
    <div style={{ position: 'relative', width: 110, height: 110, flexShrink: 0 }}>
      <svg width="110" height="110" viewBox="0 0 110 110" style={{ transform: 'rotate(-90deg)' }}>
        {/* Outer track */}
        <circle cx="55" cy="55" r={r} fill="none" stroke="var(--border)" strokeWidth="6" />
        {/* Glow behind the arc */}
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round" opacity="0.15"
          style={{ filter: 'blur(4px)' }} />
        {/* Main arc */}
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="5"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.22,1,0.36,1)' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 26, color, lineHeight: 1, fontWeight: 700 }}>
          {score}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 2, marginTop: 2 }}>
          RISK
        </div>
      </div>
    </div>
  )
}
 
// ── Finding Row ───────────────────────────────────────────────────────────────
function FindingRow({ finding }) {
  const sev = finding.severity
  const color = sev === 'critical' ? 'var(--red-bright)'
    : sev === 'high'     ? 'var(--red)'
    : sev === 'medium'   ? 'var(--amber)'
    : 'var(--blue)'
 
  return (
    <div className="threat-row" style={{ display: 'flex', gap: 10, padding: '8px 6px', borderBottom: '1px solid var(--border)', alignItems: 'flex-start' }}>
      {/* Severity dot */}
      <div style={{
        width: 6, height: 6, borderRadius: '50%', marginTop: 5,
        background: color, flexShrink: 0,
        boxShadow: sev === 'critical' ? `0 0 6px ${color}` : 'none',
      }} />
      <div style={{ flex: 1, fontSize: 12, lineHeight: 1.5, minWidth: 0, wordBreak: 'break-word', color: 'var(--text)' }}>
        {finding.description?.slice(0, 80)}…
      </div>
      <span className={`badge badge-${sev === 'critical' || sev === 'high' ? 'danger' : 'warning'}`} style={{ flexShrink: 0 }}>
        {sev}
      </span>
    </div>
  )
}
 
// ── Main Overview ─────────────────────────────────────────────────────────────
export default function Overview() {
  const navigate     = useNavigate()
  const [latestScan, setLatestScan] = useState(null)
  const [loading, setLoading] = useState(true)
 
  useEffect(() => { loadLatest() }, [])
 
  async function loadLatest() {
    setLoading(true)
    try {
      const results = await scan.history(1)
      if (results?.length > 0) setLatestScan(results[0])
    } catch {}
    finally { setLoading(false) }
  }
 
  const riskScore = Math.round(latestScan?.risk_score ?? 0)
  const riskColor = riskScore >= 70 ? 'var(--red-bright)' : riskScore >= 40 ? 'var(--amber)' : 'var(--blue)'
 
  return (
    <div className="animate-in">
 
      {/* Header */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 3, marginBottom: 4 }}>
            MODULE_ID: OVR-001
          </div>
          <h1 style={{ fontSize: 22, letterSpacing: 3, color: 'var(--text-bright)', marginBottom: 4 }}>
            NETWORK OVERVIEW
          </h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', display: 'flex', alignItems: 'center', gap: 8 }}>
            {latestScan ? (
              <>
                <span style={{ color: 'var(--blue)' }}>LAST_SCAN</span>
                <span>{new Date(latestScan.created_at).toLocaleString()}</span>
              </>
            ) : (
              <span className="terminal-cursor">Awaiting scan data</span>
            )}
          </div>
        </div>
 
        <button
          className="btn-primary"
          onClick={() => navigate('/agent-setup')}
          style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }}
        >
          ▶ INITIATE SCAN
        </button>
      </div>
 
      {/* No scan banner */}
      {!latestScan && !loading && (
        <div style={{
          background: 'var(--red-dim)',
          border: '1px solid rgba(232,53,74,0.2)',
          borderLeft: '3px solid var(--red)',
          borderRadius: 'var(--radius)',
          padding: '14px 18px',
          marginBottom: 20,
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span><span style={{ color: 'var(--red)', marginRight: 8 }}>⬡</span> No scan data. Deploy the local agent to scan your network.</span>
          <button className="btn-ghost" onClick={() => navigate('/agent-setup')} style={{ fontSize: 9, padding: '4px 12px' }}>
            SETUP AGENT →
          </button>
        </div>
      )}
 
      {/* Stat cards grid */}
      <div className="stat-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <StatCard
          label="Devices Found" value={latestScan?.hosts_up}
          color="var(--blue)" sub={latestScan?.network_range ?? 'no range'}
          icon="◉" delay={0.05}
        />
        <StatCard
          label="Open Ports" value={latestScan?.total_ports}
          color="var(--amber)" sub="across all hosts"
          icon="◎" delay={0.1}
        />
        <StatCard
          label="Threats Detected" value={latestScan?.threats_found}
          color="var(--red-bright)" sub="critical findings"
          icon="⚠" delay={0.15}
        />
        <StatCard
          label="Risk Score" value={latestScan?.risk_score !== undefined ? Math.round(latestScan.risk_score) : undefined}
          color={riskColor} sub="/ 100"
          icon="◈" delay={0.2}
        />
      </div>
 
      {/* Two-col bottom */}
      <div className="two-col-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
 
        {/* Risk module */}
        <div className="card">
          <div className="card-title">RISK ASSESSMENT</div>
          {latestScan ? (
            <div className="risk-inner" style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              <RiskRing score={riskScore} />
              <div style={{ flex: 1, width: '100%' }}>
                {[
                  { label: 'Threats Found', val: latestScan.threats_found, max: 10,  color: 'var(--red)' },
                  { label: 'Open Ports',    val: latestScan.total_ports,   max: 50,  color: 'var(--amber)' },
                  { label: 'Devices',       val: latestScan.hosts_up,      max: 20,  color: 'var(--blue)' },
                ].map(({ label, val, max, color }) => (
                  <div key={label} style={{ marginBottom: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginBottom: 5, letterSpacing: 1 }}>
                      <span>{label}</span>
                      <span style={{ color: 'var(--text-bright)', fontWeight: 700 }}>{val}</span>
                    </div>
                    <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: `${Math.min((val / max) * 100, 100)}%`,
                        background: color,
                        borderRadius: 2,
                        boxShadow: `0 0 6px ${color}`,
                        transition: 'width 1s cubic-bezier(0.22,1,0.36,1)',
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              <span className="terminal-cursor">Run a scan to see results</span>
            </div>
          )}
        </div>
 
        {/* Latest findings */}
        <div className="card">
          <div className="card-title">LATEST FINDINGS</div>
          {latestScan?.findings?.length > 0 ? (
            latestScan.findings.slice(0, 5).map((f, i) => (
              <FindingRow key={i} finding={f} />
            ))
          ) : (
            <div style={{ textAlign: 'center', padding: '30px 0', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              {latestScan
                ? <span style={{ color: 'var(--blue)' }}>◉ NO CRITICAL FINDINGS</span>
                : <span style={{ color: 'var(--muted)' }} className="terminal-cursor">No data yet</span>
              }
            </div>
          )}
        </div>
      </div>
    </div>
  )
}