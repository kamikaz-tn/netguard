import { useState, useEffect } from 'react'
import { scan } from '../services/api.js'

const RISK_BADGE = {
  critical: 'badge-danger',
  high:     'badge-danger',
  medium:   'badge-warning',
  low:      'badge-safe',
}

export default function PortScan() {
  const [findings, setFindings] = useState([])
  const [devices, setDevices] = useState([])
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)

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

  const allPorts = devices.flatMap(d =>
    (d.ports || []).map(p => ({ ...p, host_ip: d.ip, vendor: d.vendor }))
  )

  const filtered = filter === 'all' ? allPorts
    : filter === 'suspicious' ? allPorts.filter(p => p.is_suspicious || p.is_critical)
    : allPorts.filter(p => p.risk_level === filter)

  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high')

  return (
    <div className="animate-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>PORT SCAN</h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
            {allPorts.length} open ports across {devices.length} devices
          </div>
        </div>
        <button className="btn-primary" onClick={loadLatest}>↻ REFRESH</button>
      </div>

      {/* Critical findings */}
      {criticalFindings.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div className="card-title" style={{ marginBottom: 12 }}>Critical Findings</div>
          {criticalFindings.map((f, i) => (
            <div key={i} style={{
              background: 'var(--red-dim)', border: '1px solid rgba(255,68,68,0.25)',
              borderRadius: 'var(--radius)', padding: '12px 16px', marginBottom: 8,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                <span className="badge badge-danger">{f.severity}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)' }}>
                  {f.host_ip}{f.port ? `:${f.port}` : ''} — {f.service || f.category}
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text)', marginBottom: f.remediation ? 6 : 0 }}>{f.description}</div>
              {f.remediation && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--amber)', cursor: 'pointer', letterSpacing: 1 }}>▶ REMEDIATION STEPS</summary>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8, lineHeight: 1.7, paddingLeft: 12 }}>{f.remediation}</div>
                </details>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Port table */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div className="card-title" style={{ margin: 0 }}>All Open Ports</div>
          <div style={{ display: 'flex', gap: 4 }}>
            {['all', 'suspicious', 'critical', 'medium'].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                style={{
                  fontSize: 9, padding: '4px 10px',
                  background: filter === f ? 'var(--green-dim)' : 'transparent',
                  border: `1px solid ${filter === f ? 'var(--green)' : 'var(--border2)'}`,
                  color: filter === f ? 'var(--green)' : 'var(--muted)',
                  borderRadius: 'var(--radius)', cursor: 'pointer',
                  fontFamily: 'var(--font-mono)', letterSpacing: 1, textTransform: 'uppercase',
                }}>
                {f}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}><span className="spinner" /></div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            No ports found — run a scan first
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border2)' }}>
                {['Port', 'Protocol', 'Service', 'Version', 'Host', 'Risk'].map(h => (
                  <th key={h} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1.5, padding: '0 12px 10px 0', textAlign: 'left', textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((p, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 12px 10px 0', fontFamily: 'var(--font-mono)', fontSize: 13, color: p.is_suspicious ? 'var(--red)' : p.is_critical ? 'var(--amber)' : 'var(--blue)' }}>
                    {p.port}
                    {p.is_suspicious && <span style={{ fontSize: 9, marginLeft: 4, color: 'var(--red)' }}>⚠</span>}
                  </td>
                  <td style={{ padding: '10px 12px 10px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>{p.protocol?.toUpperCase()}</td>
                  <td style={{ padding: '10px 12px 10px 0', fontSize: 13 }}>{p.service}</td>
                  <td style={{ padding: '10px 12px 10px 0', fontSize: 11, color: 'var(--muted)' }}>{p.version || '—'}</td>
                  <td style={{ padding: '10px 12px 10px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--blue)' }}>{p.host_ip}</td>
                  <td style={{ padding: '10px 0' }}>
                    <span className={`badge ${RISK_BADGE[p.risk_level] || 'badge-safe'}`}>{p.risk_level}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
