/**
 * netguard/frontend/src/pages/PortScan.jsx
 * ──────────────────────────────────────────
 * Port scan results + inline CVE lookup per open port / service.
 *
 * Session 16: Added CVE lookup panel.
 * Clicking any port row opens a slide-in CVE panel that queries the
 * NVD API (via our backend proxy) and renders matching vulnerabilities.
 */
 
import { useState, useEffect, useRef } from 'react'
import { scan } from '../services/api.js'
import { lookupCVE, lookupCVEByPort, SEVERITY_COLOR, SEVERITY_BADGE } from '../services/cve.js'
 
// ── Constants ─────────────────────────────────────────────────────────────────
const RISK_BADGE = {
  critical: 'badge-danger',
  high:     'badge-danger',
  medium:   'badge-warning',
  low:      'badge-safe',
}
 
// ── CVE severity score ring ───────────────────────────────────────────────────
function CvssRing({ score }) {
  const r      = 18
  const circ   = 2 * Math.PI * r
  const offset = circ - (score / 10) * circ
  const color  = score >= 9 ? 'var(--red-bright)'
    : score >= 7 ? 'var(--red)'
    : score >= 4 ? 'var(--amber)'
    : 'var(--blue)'
 
  return (
    <div style={{ position: 'relative', width: 44, height: 44, flexShrink: 0 }}>
      <svg width="44" height="44" viewBox="0 0 44 44" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="22" cy="22" r={r} fill="none" stroke="var(--border2)" strokeWidth="3" />
        <circle cx="22" cy="22" r={r} fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.6s ease', filter: `drop-shadow(0 0 3px ${color})` }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color,
      }}>
        {score.toFixed(1)}
      </div>
    </div>
  )
}
 
// ── Single CVE card ───────────────────────────────────────────────────────────
function CveCard({ cve, index }) {
  const color = SEVERITY_COLOR[cve.severity] || 'var(--muted)'
  return (
    <div style={{
      background: 'var(--surface2)',
      border: `1px solid var(--border)`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 'var(--radius)',
      padding: '10px 12px',
      animation: `hudBootUp 0.3s ${index * 0.06}s both`,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <CvssRing score={cve.cvss_score} />
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* CVE ID + severity */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, flexWrap: 'wrap' }}>
            <a
              href={cve.url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                fontFamily: 'var(--font-mono)', fontSize: 11, color,
                textDecoration: 'none', letterSpacing: 1,
              }}
              onMouseEnter={e => e.target.style.textDecoration = 'underline'}
              onMouseLeave={e => e.target.style.textDecoration = 'none'}
            >
              {cve.cve_id}
            </a>
            <span className={`badge ${SEVERITY_BADGE[cve.severity] || 'badge-info'}`}>
              {cve.severity}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginLeft: 'auto' }}>
              {cve.published}
            </span>
          </div>
          {/* Description */}
          <div style={{ fontSize: 11, color: 'var(--text)', lineHeight: 1.6 }}>
            {cve.description}
          </div>
        </div>
      </div>
    </div>
  )
}
 
// ── CVE panel (slide-in from right) ──────────────────────────────────────────
function CvePanel({ port, onClose }) {
  const [state, setState] = useState('idle')   // idle | loading | done | error
  const [result, setResult] = useState(null)
  const [error, setError]   = useState('')
  const panelRef = useRef()
 
  // Fetch on mount / when port changes
  useEffect(() => {
    if (!port) return
    fetchCves()
  }, [port?.port, port?.service, port?.version])
 
  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])
 
  async function fetchCves() {
    setState('loading')
    setError('')
    setResult(null)
    try {
      let data
      if (port.service && port.service !== 'Unknown') {
        data = await lookupCVE(port.service, port.version || '')
      } else {
        data = await lookupCVEByPort(port.port)
      }
      setResult(data)
      setState('done')
    } catch (err) {
      setError(err.message)
      setState('error')
    }
  }
 
  if (!port) return null
 
  const riskColor = port.risk_level === 'critical' ? 'var(--red-bright)'
    : port.risk_level === 'high'   ? 'var(--red)'
    : port.risk_level === 'medium' ? 'var(--amber)'
    : 'var(--blue)'
 
  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 40,
          background: 'rgba(4,5,6,0.6)',
          backdropFilter: 'blur(2px)',
          animation: 'fadeIn 0.15s ease',
        }}
      />
 
      {/* Panel */}
      <div
        ref={panelRef}
        style={{
          position: 'fixed', top: 0, right: 0, bottom: 0,
          width: 480, zIndex: 41,
          background: 'var(--surface)',
          borderLeft: '1px solid var(--border)',
          boxShadow: '-8px 0 40px rgba(0,0,0,0.5)',
          display: 'flex', flexDirection: 'column',
          animation: 'slideInRight 0.25s cubic-bezier(0.22,1,0.36,1)',
          overflow: 'hidden',
        }}
      >
        {/* Panel header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--surface2)',
          flexShrink: 0,
        }}>
          {/* Scan bar */}
          {state === 'loading' && (
            <div className="scan-bar" style={{ position: 'absolute', top: 0, left: 0, right: 0, width: '100%' }} />
          )}
 
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, marginBottom: 4 }}>
                CVE INTELLIGENCE
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 16, color: riskColor, fontWeight: 700 }}>
                  :{port.port}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)' }}>
                  {port.service}
                </span>
                {port.version && (
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', background: 'var(--surface3)', padding: '2px 6px', borderRadius: 2 }}>
                    {port.version}
                  </span>
                )}
                <span className={`badge ${RISK_BADGE[port.risk_level] || 'badge-safe'}`}>
                  {port.risk_level}
                </span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', marginTop: 6 }}>
                {port.protocol?.toUpperCase()} · {port.host_ip}
                {port.is_suspicious && (
                  <span style={{ color: 'var(--red)', marginLeft: 8 }}>⚠ SUSPICIOUS PORT</span>
                )}
              </div>
            </div>
            <button
              onClick={onClose}
              style={{
                background: 'transparent', border: '1px solid var(--border2)',
                color: 'var(--muted)', borderRadius: 'var(--radius)',
                padding: '4px 10px', fontFamily: 'var(--font-mono)', fontSize: 10,
                cursor: 'pointer', flexShrink: 0, letterSpacing: 1,
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => { e.target.style.color = 'var(--red)'; e.target.style.borderColor = 'var(--red)' }}
              onMouseLeave={e => { e.target.style.color = 'var(--muted)'; e.target.style.borderColor = 'var(--border2)' }}
            >
              ✕ ESC
            </button>
          </div>
        </div>
 
        {/* Panel body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
 
          {/* Loading */}
          {state === 'loading' && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '40px 0', gap: 16 }}>
              <span className="spinner" style={{ width: 24, height: 24 }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', letterSpacing: 1 }}>
                QUERYING NVD DATABASE...
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted2)', textAlign: 'center' }}>
                Searching for: <span style={{ color: 'var(--red)' }}>{port.service} {port.version}</span>
              </div>
            </div>
          )}
 
          {/* Error */}
          {state === 'error' && (
            <div>
              <div className="terminal-block" style={{ marginBottom: 16 }}>
                <span style={{ color: 'var(--red)', marginRight: 8 }}>⚠</span>
                <span style={{ color: 'var(--text)', fontSize: 11 }}>{error}</span>
              </div>
              <button className="btn-primary" onClick={fetchCves} style={{ fontSize: 9 }}>
                ↺ RETRY
              </button>
            </div>
          )}
 
          {/* Results */}
          {state === 'done' && result && (
            <>
              {/* Summary bar */}
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                marginBottom: 14, padding: '8px 12px',
                background: 'var(--surface2)', borderRadius: 'var(--radius)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>
                  <span style={{ color: result.total_results > 0 ? 'var(--red-bright)' : 'var(--blue)' }}>
                    {result.total_results}
                  </span>
                  <span style={{ color: 'var(--muted)', marginLeft: 6 }}>
                    CVE{result.total_results !== 1 ? 's' : ''} found for
                    <span style={{ color: 'var(--text)', marginLeft: 4 }}>"{result.query}"</span>
                  </span>
                </div>
                {result.cached && (
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted)', letterSpacing: 1, background: 'var(--surface3)', padding: '2px 6px', borderRadius: 2 }}>
                    CACHED
                  </span>
                )}
              </div>
 
              {/* No results */}
              {result.cves.length === 0 && (
                <div style={{
                  textAlign: 'center', padding: '32px 0',
                  fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--blue)',
                }}>
                  <div style={{ fontSize: 24, marginBottom: 10 }}>◉</div>
                  No known CVEs found for this service/version.
                  <div style={{ fontSize: 9, color: 'var(--muted)', marginTop: 8, lineHeight: 1.7 }}>
                    This could mean the service is up to date,<br />or the version string wasn't recognized by NVD.
                  </div>
                </div>
              )}
 
              {/* CVE list */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.cves.map((cve, i) => (
                  <CveCard key={cve.cve_id} cve={cve} index={i} />
                ))}
              </div>
 
              {/* Footer link */}
              {result.cves.length > 0 && (
                <div style={{ marginTop: 16, textAlign: 'center' }}>
                  <a
                    href={`https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(result.query)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1 }}
                  >
                    ↗ VIEW ALL ON NVD.NIST.GOV
                  </a>
                </div>
              )}
            </>
          )}
        </div>
 
        {/* NVD attribution footer */}
        <div style={{
          padding: '10px 20px',
          borderTop: '1px solid var(--border)',
          background: 'var(--surface2)',
          flexShrink: 0,
        }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--muted2)', letterSpacing: 0.5, lineHeight: 1.8 }}>
            Data source: NIST National Vulnerability Database (NVD) · CVE 2.0 API
          </div>
        </div>
      </div>
    </>
  )
}
 
// ── Main PortScan page ────────────────────────────────────────────────────────
export default function PortScan() {
  const [findings, setFindings]       = useState([])
  const [devices,  setDevices]        = useState([])
  const [filter,   setFilter]         = useState('all')
  const [loading,  setLoading]        = useState(true)
  const [selectedPort, setSelectedPort] = useState(null)  // port object for CVE panel
 
  useEffect(() => { loadLatest() }, [])
 
  async function loadLatest() {
    setLoading(true)
    try {
      const history = await scan.history(1)
      if (history?.length > 0) {
        const detail = await scan.detail(history[0].id)
        setFindings(detail.findings || [])
        setDevices(detail.devices || [])
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }
 
  // Flatten all ports from all devices, attach host_ip
  const allPorts = devices.flatMap(d =>
    (d.ports || []).map(p => ({ ...p, host_ip: d.ip, vendor: d.vendor }))
  )
 
  const filtered = filter === 'all'        ? allPorts
    : filter === 'suspicious'              ? allPorts.filter(p => p.is_suspicious || p.is_critical)
    : allPorts.filter(p => p.risk_level === filter)
 
  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high')
 
  return (
    <div className="animate-in" style={{ position: 'relative' }}>
 
      {/* CVE slide-in panel */}
      {selectedPort && (
        <CvePanel
          port={selectedPort}
          onClose={() => setSelectedPort(null)}
        />
      )}
 
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 3, marginBottom: 3 }}>
            MODULE_ID: PSC-001
          </div>
          <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>
            PORT SCAN
          </h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
            {allPorts.length} open ports across {devices.length} devices
            <span style={{ color: 'var(--border3)', margin: '0 8px' }}>·</span>
            <span style={{ color: 'var(--blue)' }}>Click any row to look up CVEs</span>
          </div>
        </div>
        <button className="btn-primary" onClick={loadLatest} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          ↻ REFRESH
        </button>
      </div>
 
      {/* Critical findings */}
      {criticalFindings.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--red)', letterSpacing: 2, marginBottom: 10 }}>
            ▸ CRITICAL FINDINGS
          </div>
          {criticalFindings.map((f, i) => (
            <div key={i} style={{
              background: 'var(--red-dim)',
              border: '1px solid rgba(255,68,68,0.25)',
              borderRadius: 'var(--radius)',
              padding: '12px 16px',
              marginBottom: 8,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4, flexWrap: 'wrap' }}>
                <span className="badge badge-danger">{f.severity}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)' }}>
                  {f.host_ip}{f.port ? `:${f.port}` : ''} — {f.service || f.category}
                </span>
                {/* CVE quick-lookup from finding */}
                {f.service && f.port && (
                  <button
                    onClick={() => setSelectedPort({
                      port: f.port, protocol: 'tcp', service: f.service || '',
                      version: '', risk_level: f.severity, host_ip: f.host_ip,
                      is_suspicious: false,
                    })}
                    style={{
                      marginLeft: 'auto', background: 'transparent',
                      border: '1px solid rgba(232,53,74,0.4)', color: 'var(--red)',
                      fontFamily: 'var(--font-mono)', fontSize: 8, letterSpacing: 1,
                      padding: '2px 8px', borderRadius: 2, cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={e => e.target.style.background = 'var(--red-dim)'}
                    onMouseLeave={e => e.target.style.background = 'transparent'}
                  >
                    🔍 CVE LOOKUP
                  </button>
                )}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text)', marginBottom: f.remediation ? 6 : 0 }}>
                {f.description}
              </div>
              {f.remediation && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--amber)', cursor: 'pointer', letterSpacing: 1 }}>
                    ▶ REMEDIATION STEPS
                  </summary>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8, lineHeight: 1.7, paddingLeft: 12 }}>
                    {f.remediation}
                  </div>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
 
      {/* Port table */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="card-title" style={{ margin: 0 }}>ALL OPEN PORTS</div>
          </div>
          {/* Filters */}
          <div style={{ display: 'flex', gap: 4 }}>
            {['all', 'suspicious', 'critical', 'medium'].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  fontSize: 9, padding: '4px 10px',
                  background: filter === f ? 'var(--red-dim)' : 'transparent',
                  border: `1px solid ${filter === f ? 'var(--red)' : 'var(--border2)'}`,
                  color: filter === f ? 'var(--red)' : 'var(--muted)',
                  borderRadius: 'var(--radius)', cursor: 'pointer',
                  fontFamily: 'var(--font-mono)', letterSpacing: 1, textTransform: 'uppercase',
                  transition: 'all 0.15s',
                }}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
 
        {/* Hint */}
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)',
          marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <span style={{ color: 'var(--blue)' }}>ℹ</span>
          Click any row to query the NVD vulnerability database for that service.
        </div>
 
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <span className="spinner" />
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            No ports found — run a scan first
          </div>
        ) : (
          <div className="table-scroll">
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 600 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border2)' }}>
                  {['Port', 'Protocol', 'Service', 'Version', 'Host', 'Risk', 'CVE'].map(h => (
                    <th key={h} style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)',
                      letterSpacing: 1.5, padding: '0 12px 10px 0', textAlign: 'left', textTransform: 'uppercase',
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((p, i) => {
                  const isSelected = selectedPort?.port === p.port && selectedPort?.host_ip === p.host_ip
                  return (
                    <tr
                      key={i}
                      onClick={() => setSelectedPort(isSelected ? null : p)}
                      style={{
                        borderBottom: '1px solid var(--border)',
                        cursor: 'pointer',
                        background: isSelected ? 'var(--red-dim)' : 'transparent',
                        transition: 'background 0.15s',
                        borderLeft: isSelected ? '2px solid var(--red)' : '2px solid transparent',
                      }}
                      onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'rgba(232,53,74,0.04)' }}
                      onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent' }}
                    >
                      {/* Port */}
                      <td style={{ padding: '10px 12px 10px 0', fontFamily: 'var(--font-mono)', fontSize: 13, color: p.is_suspicious ? 'var(--red-bright)' : p.is_critical ? 'var(--amber)' : 'var(--blue)' }}>
                        {p.port}
                        {p.is_suspicious && <span style={{ fontSize: 9, marginLeft: 4, color: 'var(--red)' }}>⚠</span>}
                      </td>
                      {/* Protocol */}
                      <td style={{ padding: '10px 12px 10px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                        {p.protocol?.toUpperCase()}
                      </td>
                      {/* Service */}
                      <td style={{ padding: '10px 12px 10px 0', fontSize: 13 }}>
                        {p.service}
                      </td>
                      {/* Version */}
                      <td style={{ padding: '10px 12px 10px 0', fontSize: 11, color: 'var(--muted)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {p.version || '—'}
                      </td>
                      {/* Host IP */}
                      <td style={{ padding: '10px 12px 10px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--blue)' }}>
                        {p.host_ip}
                      </td>
                      {/* Risk badge */}
                      <td style={{ padding: '10px 12px 10px 0' }}>
                        <span className={`badge ${RISK_BADGE[p.risk_level] || 'badge-safe'}`}>
                          {p.risk_level}
                        </span>
                      </td>
                      {/* CVE lookup trigger */}
                      <td style={{ padding: '10px 0' }}>
                        <button
                          onClick={e => { e.stopPropagation(); setSelectedPort(isSelected ? null : p) }}
                          style={{
                            background: isSelected ? 'var(--red-dim)' : 'transparent',
                            border: `1px solid ${isSelected ? 'var(--red)' : 'var(--border2)'}`,
                            color: isSelected ? 'var(--red-bright)' : 'var(--muted)',
                            fontFamily: 'var(--font-mono)', fontSize: 8, letterSpacing: 1,
                            padding: '3px 8px', borderRadius: 2, cursor: 'pointer',
                            transition: 'all 0.15s', whiteSpace: 'nowrap',
                          }}
                        >
                          {isSelected ? '▶ OPEN' : '🔍 CVE'}
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
 
      {/* Slide-in animation CSS */}
      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);   opacity: 1; }
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
      `}</style>
    </div>
  )
}