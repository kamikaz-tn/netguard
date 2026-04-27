import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { scan, alerts } from '../services/api.js'
 
// ── Mini Sparkline (SVG) ──────────────────────────────────────────────────────
function Sparkline({ data, color, height = 28, width = 80 }) {
  if (!data || data.length < 2) return null
  const max = Math.max(...data, 1)
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width
    const y = height - (v / max) * height
    return `${x},${y}`
  }).join(' ')
  return (
    <svg width={width} height={height} style={{ display: 'block' }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
 
// ── Real-Time Traffic Graph ───────────────────────────────────────────────────
function TrafficGraph({ scanHistory }) {
  const labels = scanHistory.slice().reverse().map((s, i) => {
    const d = new Date(s.created_at)
    return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
  })
  const portsData  = scanHistory.slice().reverse().map(s => s.total_ports || 0)
  const threatsData = scanHistory.slice().reverse().map(s => s.threats_found || 0)
  const devicesData = scanHistory.slice().reverse().map(s => s.hosts_up || 0)
 
  const maxPorts = Math.max(...portsData, 1)
  const W = 560, H = 120, PAD = 36
 
  function toPoints(data) {
    return data.map((v, i) => {
      const x = PAD + (i / Math.max(data.length - 1, 1)) * (W - PAD * 2)
      const y = H - PAD - (v / maxPorts) * (H - PAD * 1.5)
      return [x, y]
    })
  }
 
  function pointsToPath(pts) {
    if (pts.length === 0) return ''
    if (pts.length === 1) return `M ${pts[0][0]} ${pts[0][1]}`
    let d = `M ${pts[0][0]} ${pts[0][1]}`
    for (let i = 1; i < pts.length; i++) {
      const cx = (pts[i - 1][0] + pts[i][0]) / 2
      d += ` C ${cx} ${pts[i - 1][1]}, ${cx} ${pts[i][1]}, ${pts[i][0]} ${pts[i][1]}`
    }
    return d
  }
 
  const portsPts   = toPoints(portsData)
  const threatsPts = toPoints(threatsData.map(v => (v / Math.max(...threatsData, 1)) * maxPorts))
 
  const portsPath   = pointsToPath(portsPts)
  const threatsPath = pointsToPath(threatsPts)
 
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map(t => ({
    y: H - PAD - t * (H - PAD * 1.5),
    val: Math.round(t * maxPorts),
  }))
 
  return (
    <div style={{ width: '100%', overflowX: 'auto' }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', display: 'block' }}>
        {gridLines.map(({ y, val }) => (
          <g key={y}>
            <line x1={PAD} y1={y} x2={W - PAD} y2={y} stroke="var(--border)" strokeWidth="1" strokeDasharray="3,4" />
            <text x={PAD - 6} y={y + 4} fill="var(--muted)" fontSize="8" textAnchor="end" fontFamily="Share Tech Mono, monospace">{val}</text>
          </g>
        ))}
        {portsPts.length > 1 && (
          <path
            d={`${portsPath} L ${portsPts[portsPts.length-1][0]} ${H - PAD} L ${portsPts[0][0]} ${H - PAD} Z`}
            fill="rgba(77,184,232,0.08)"
          />
        )}
        {threatsPts.length > 1 && (
          <path
            d={`${threatsPath} L ${threatsPts[threatsPts.length-1][0]} ${H - PAD} L ${threatsPts[0][0]} ${H - PAD} Z`}
            fill="rgba(232,53,74,0.08)"
          />
        )}
        {portsPath   && <path d={portsPath}   fill="none" stroke="var(--blue)"      strokeWidth="1.8" strokeLinecap="round" />}
        {threatsPath && <path d={threatsPath} fill="none" stroke="var(--red)"       strokeWidth="1.8" strokeLinecap="round" />}
        {portsPts.length > 0 && (
          <circle cx={portsPts[portsPts.length-1][0]} cy={portsPts[portsPts.length-1][1]} r="3" fill="var(--blue)" />
        )}
        {threatsPts.length > 0 && (
          <circle cx={threatsPts[threatsPts.length-1][0]} cy={threatsPts[threatsPts.length-1][1]} r="3" fill="var(--red)" />
        )}
        {labels.map((label, i) => {
          const x = PAD + (i / Math.max(labels.length - 1, 1)) * (W - PAD * 2)
          return (
            <text key={i} x={x} y={H - 4} fill="var(--muted)" fontSize="7" textAnchor="middle" fontFamily="Share Tech Mono, monospace">
              {label}
            </text>
          )
        })}
      </svg>
    </div>
  )
}
 
// ── Security Log Terminal ─────────────────────────────────────────────────────
function SecurityLog({ findings, scanHistory }) {
  const logRef = useRef(null)
 
  const entries = []
 
  scanHistory.slice(0, 5).forEach(s => {
    const d = new Date(s.created_at)
    const ts = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`
    entries.push({ ts, level: 'INFO', msg: `Scan completed — ${s.hosts_up} devices, ${s.total_ports} ports, risk ${s.risk_score}/100`, color: 'var(--blue)' })
    if (s.threats_found > 0) {
      entries.push({ ts, level: 'ALERT', msg: `${s.threats_found} threat(s) detected on network ${s.network_range}`, color: 'var(--red)' })
    }
  })
 
  findings.slice(0, 6).forEach(f => {
    const level = f.severity === 'critical' ? 'CRITICAL' : f.severity === 'high' ? 'ALERT' : 'WARN'
    const color = f.severity === 'critical' ? 'var(--red-bright)' : f.severity === 'high' ? 'var(--red)' : 'var(--amber)'
    entries.push({ ts: '--:--:--', level, msg: `${f.host_ip}${f.port ? ':' + f.port : ''} — ${f.description?.slice(0, 60)}`, color })
  })
 
  entries.sort(() => Math.random() - 0.5)
 
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [entries.length])
 
  return (
    <div
      ref={logRef}
      style={{
        background: 'var(--bg-deep)',
        border: '1px solid var(--border)',
        borderLeft: '3px solid var(--red)',
        borderRadius: 'var(--radius)',
        padding: '10px 12px',
        height: 180,
        overflowY: 'auto',
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        lineHeight: 1.9,
      }}
    >
      {entries.length === 0 ? (
        <div style={{ color: 'var(--muted)' }}>Awaiting scan data...</div>
      ) : (
        entries.map((e, i) => (
          <div key={i} style={{ display: 'flex', gap: 8, borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: 1 }}>
            <span style={{ color: 'var(--muted2)', flexShrink: 0 }}>{e.ts}</span>
            <span style={{ color: e.color, flexShrink: 0, minWidth: 56 }}>[{e.level}]</span>
            <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{e.msg}</span>
          </div>
        ))
      )}
    </div>
  )
}
 
// ── Stat Card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, color = 'var(--red)', sub, icon, delay = 0, sparkData, sparkColor }) {
  const [displayed, setDisplayed] = useState(0)
 
  useEffect(() => {
    if (typeof value !== 'number') return
    let start = 0
    const end = value, dur = 600, step = 16
    const inc = end / (dur / step)
    const t = setInterval(() => {
      start = Math.min(start + inc, end)
      setDisplayed(Math.round(start))
      if (start >= end) clearInterval(t)
    }, step)
    return () => clearInterval(t)
  }, [value])
 
  return (
    <div className="card" style={{ padding: '16px 20px', animation: `hudBootUp 0.4s ${delay}s both cubic-bezier(0.22,1,0.36,1)` }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2 }}>{label.toUpperCase()}</div>
        {icon && <span style={{ fontSize: 14, opacity: 0.4 }}>{icon}</span>}
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 34, color, lineHeight: 1, fontWeight: 700 }}>
          {typeof value === 'number' ? displayed : (value ?? '—')}
        </div>
        {sparkData && <Sparkline data={sparkData} color={sparkColor || color} />}
      </div>
      {sub && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 6, letterSpacing: 1 }}>{sub}</div>
      )}
      <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, ${color}, transparent)`, opacity: 0.3, borderRadius: '0 0 var(--radius) var(--radius)' }} />
    </div>
  )
}
 
// ── Risk Ring ─────────────────────────────────────────────────────────────────
function RiskRing({ score }) {
  const r = 44, circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color = score >= 70 ? 'var(--red-bright)' : score >= 40 ? 'var(--amber)' : 'var(--blue)'
  return (
    <div style={{ position: 'relative', width: 110, height: 110, flexShrink: 0 }}>
      <svg width="110" height="110" viewBox="0 0 110 110" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="55" cy="55" r={r} fill="none" stroke="var(--border)" strokeWidth="6" />
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" opacity="0.15" style={{ filter: 'blur(4px)' }} />
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="5"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.22,1,0.36,1)' }} />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 26, color, lineHeight: 1, fontWeight: 700 }}>{score}</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 2, marginTop: 2 }}>RISK</div>
      </div>
    </div>
  )
}
 
// ── Finding Row ───────────────────────────────────────────────────────────────
function FindingRow({ finding }) {
  const sev = finding.severity
  const color = sev === 'critical' ? 'var(--red-bright)' : sev === 'high' ? 'var(--red)' : sev === 'medium' ? 'var(--amber)' : 'var(--blue)'
  return (
    <div className="threat-row" style={{ display: 'flex', gap: 10, padding: '8px 6px', borderBottom: '1px solid var(--border)', alignItems: 'flex-start' }}>
      <div style={{ width: 6, height: 6, borderRadius: '50%', marginTop: 5, background: color, flexShrink: 0, boxShadow: sev === 'critical' ? `0 0 6px ${color}` : 'none' }} />
      <div style={{ flex: 1, fontSize: 12, lineHeight: 1.5, minWidth: 0, wordBreak: 'break-word', color: 'var(--text)' }}>
        {finding.description?.slice(0, 80)}…
      </div>
      <span className={`badge badge-${sev === 'critical' || sev === 'high' ? 'danger' : 'warning'}`} style={{ flexShrink: 0 }}>{sev}</span>
    </div>
  )
}
 
// ── Main Overview ─────────────────────────────────────────────────────────────
export default function Overview() {
  const navigate = useNavigate()
  const [latestScan, setLatestScan]   = useState(null)
  const [scanHistory, setScanHistory] = useState([])
  const [allFindings, setAllFindings] = useState([])
  const [loading, setLoading]         = useState(true)
  const [uptime, setUptime]           = useState(0)
 
  useEffect(() => { loadData() }, [])
 
  useEffect(() => {
    const t = setInterval(() => setUptime(u => u + 1), 1000)
    return () => clearInterval(t)
  }, [])
 
  async function loadData() {
    setLoading(true)
    try {
      const results = await scan.history(10)
      if (results?.length > 0) {
        setScanHistory(results)
        setLatestScan(results[0])
        try {
          const detail = await scan.detail(results[0].id)
          setAllFindings(detail.findings || [])
        } catch {}
      }
    } catch {}
    finally { setLoading(false) }
  }
 
  const riskScore = Math.round(latestScan?.risk_score ?? 0)
  const riskColor = riskScore >= 70 ? 'var(--red-bright)' : riskScore >= 40 ? 'var(--amber)' : 'var(--blue)'
 
  const sparkPorts   = scanHistory.slice().reverse().map(s => s.total_ports || 0)
  const sparkThreats = scanHistory.slice().reverse().map(s => s.threats_found || 0)
  const sparkDevices = scanHistory.slice().reverse().map(s => s.hosts_up || 0)
  const sparkRisk    = scanHistory.slice().reverse().map(s => s.risk_score || 0)
 
  const uptimeMins = Math.floor(uptime / 60)
  const uptimeSecs = uptime % 60
  const uptimeStr  = uptimeMins > 0 ? `${uptimeMins}m ${uptimeSecs}s` : `${uptimeSecs}s`
 
  const threatLabel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'ELEVATED' : riskScore > 0 ? 'NOMINAL' : 'STANDBY'
  const threatColor = riskScore >= 70 ? 'var(--red-bright)' : riskScore >= 40 ? 'var(--amber)' : 'var(--blue)'
 
  return (
    <div className="animate-in">
 
      {/* ── Header ── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 3, marginBottom: 4 }}>MODULE_ID: OVR-001</div>
          <h1 style={{ fontSize: 20, letterSpacing: 3, color: 'var(--text-bright)', marginBottom: 4 }}>NETWORK OVERVIEW</h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            {latestScan ? (
              <>
                <span><span style={{ color: 'var(--blue)' }}>LAST_SCAN</span> {new Date(latestScan.created_at).toLocaleString()}</span>
                <span>·</span>
                <span style={{ color: threatColor }}>THREAT: {threatLabel}</span>
                <span>·</span>
                <span>SESSION: {uptimeStr}</span>
              </>
            ) : (
              <span style={{ color: 'var(--muted)' }}>Awaiting scan data</span>
            )}
          </div>
        </div>
        <button className="btn-primary" onClick={() => navigate('/agent-setup')} style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }}>
          ▶ INITIATE SCAN
        </button>
      </div>
 
      {/* ── No scan banner ── */}
      {!latestScan && !loading && (
        <div style={{ background: 'var(--red-dim)', border: '1px solid rgba(232,53,74,0.2)', borderLeft: '3px solid var(--red)', borderRadius: 'var(--radius)', padding: '14px 18px', marginBottom: 20, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span><span style={{ color: 'var(--red)', marginRight: 8 }}>⬡</span> No scan data. Deploy the local agent to scan your network.</span>
          <button className="btn-ghost" onClick={() => navigate('/agent-setup')} style={{ fontSize: 9, padding: '4px 12px' }}>SETUP AGENT →</button>
        </div>
      )}
 
      {/* ── KPI Stats ── */}
      <div className="stat-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
        <StatCard label="Devices Found"    value={latestScan?.hosts_up}         color="var(--blue)"       sub={latestScan?.network_range ?? 'no range'} icon="◉" delay={0.05} sparkData={sparkDevices} sparkColor="var(--blue)" />
        <StatCard label="Open Ports"       value={latestScan?.total_ports}      color="var(--amber)"      sub="across all hosts"   icon="◎" delay={0.10} sparkData={sparkPorts}   sparkColor="var(--amber)" />
        <StatCard label="Threats Detected" value={latestScan?.threats_found}    color="var(--red-bright)" sub="critical findings"  icon="⚠" delay={0.15} sparkData={sparkThreats} sparkColor="var(--red)" />
        <StatCard label="Risk Score"       value={latestScan?.risk_score !== undefined ? Math.round(latestScan.risk_score) : undefined} color={riskColor} sub="/ 100" icon="◈" delay={0.20} sparkData={sparkRisk} sparkColor={riskColor} />
      </div>
 
      {/* ── Traffic Graph + Risk ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16, marginBottom: 16 }} className="two-col-grid">
 
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div className="card-title" style={{ margin: 0 }}>SCAN HISTORY — PORT & THREAT TRENDS</div>
            <div style={{ display: 'flex', gap: 16, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)' }}>
              <span><span style={{ color: 'var(--blue)', marginRight: 4 }}>●</span>PORTS</span>
              <span><span style={{ color: 'var(--red)', marginRight: 4 }}>●</span>THREATS</span>
            </div>
          </div>
          {scanHistory.length >= 2 ? (
            <TrafficGraph scanHistory={scanHistory} />
          ) : (
            <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              {loading ? <span className="spinner" /> : <span>Need 2+ scans to show trends</span>}
            </div>
          )}
        </div>
 
        <div className="card">
          <div className="card-title">RISK ASSESSMENT</div>
          {latestScan ? (
            <div className="risk-inner" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <RiskRing score={riskScore} />
              <div style={{ flex: 1 }}>
                {[
                  { label: 'Threats', val: latestScan.threats_found, max: 10,  color: 'var(--red)' },
                  { label: 'Ports',   val: latestScan.total_ports,   max: 50,  color: 'var(--amber)' },
                  { label: 'Devices', val: latestScan.hosts_up,      max: 20,  color: 'var(--blue)' },
                ].map(({ label, val, max, color }) => (
                  <div key={label} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginBottom: 4, letterSpacing: 1 }}>
                      <span>{label}</span>
                      <span style={{ color: 'var(--text-bright)', fontWeight: 700 }}>{val}</span>
                    </div>
                    <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${Math.min((val / max) * 100, 100)}%`, background: color, borderRadius: 2, boxShadow: `0 0 6px ${color}`, transition: 'width 1s cubic-bezier(0.22,1,0.36,1)' }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              Run a scan to see results
            </div>
          )}
        </div>
      </div>
 
      {/* ── Findings + Security Log ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }} className="two-col-grid">
 
        <div className="card">
          <div className="card-title">LATEST FINDINGS</div>
          {allFindings.length > 0 ? (
            allFindings.slice(0, 5).map((f, i) => <FindingRow key={i} finding={f} />)
          ) : (
            <div style={{ textAlign: 'center', padding: '30px 0', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              {latestScan
                ? <span style={{ color: 'var(--blue)' }}>◉ NO CRITICAL FINDINGS</span>
                : <span style={{ color: 'var(--muted)' }}>No data yet</span>}
            </div>
          )}
        </div>
 
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div className="card-title" style={{ margin: 0 }}>SECURITY LOG</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--red)', animation: 'pulse 1.5s ease infinite', boxShadow: '0 0 6px var(--red-glow)' }} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--red)', letterSpacing: 1 }}>LIVE</span>
            </div>
          </div>
          <SecurityLog findings={allFindings} scanHistory={scanHistory} />
        </div>
      </div>
    </div>
  )
}
 