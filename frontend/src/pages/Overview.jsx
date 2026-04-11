import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { scan } from '../services/api.js'
 
function StatCard({ label, value, color = 'var(--green)', sub }) {
  return (
    <div className="card" style={{ padding: '16px 20px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', letterSpacing: 2, marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, color, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}
 
function RiskRing({ score }) {
  const r = 42
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  const color = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)'
 
  return (
    <div style={{ position: 'relative', width: 100, height: 100, flexShrink: 0 }}>
      <svg width="100" height="100" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border)" strokeWidth="8" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" />
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, color, lineHeight: 1 }}>{score}</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1 }}>RISK</div>
      </div>
    </div>
  )
}
 
export default function Overview() {
  const navigate = useNavigate()
  const [latestScan, setLatestScan] = useState(null)
 
  useEffect(() => {
    loadLatest()
  }, [])
 
  async function loadLatest() {
    try {
      const results = await scan.history(1)
      if (results?.length > 0) setLatestScan(results[0])
    } catch {}
  }
 
  return (
    <div className="animate-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>NETWORK OVERVIEW</h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
            {latestScan ? `Last scan: ${new Date(latestScan.created_at).toLocaleString()}` : 'No scans yet'}
          </div>
        </div>
        <button
          className="btn-primary"
          onClick={() => navigate('/agent-setup')}
          style={{ display: 'flex', alignItems: 'center', gap: 8 }}
        >
          ▶ RUN SCAN
        </button>
      </div>
 
      {/* No scan yet — prompt */}
      {!latestScan && (
        <div style={{
          background: 'rgba(0,229,160,0.05)', border: '1px solid rgba(0,229,160,0.15)',
          borderRadius: 'var(--radius)', padding: '16px 20px', marginBottom: 20,
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>⬡ No scan data yet. Use the local agent to scan your network.</span>
          <button
            className="btn-ghost"
            onClick={() => navigate('/agent-setup')}
            style={{ fontSize: 9, padding: '4px 12px' }}
          >
            HOW TO SCAN →
          </button>
        </div>
      )}
 
      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
        <StatCard label="Devices Found"  value={latestScan?.hosts_up ?? '—'}       color="var(--blue)"  sub={latestScan?.network_range} />
        <StatCard label="Open Ports"     value={latestScan?.total_ports ?? '—'}     color="var(--amber)" sub="across all hosts" />
        <StatCard label="Threats"        value={latestScan?.threats_found ?? '—'}   color="var(--red)"   sub="critical findings" />
        <StatCard label="Risk Score"     value={latestScan?.risk_score ?? '—'}      color={latestScan?.risk_score >= 70 ? 'var(--red)' : latestScan?.risk_score >= 40 ? 'var(--amber)' : 'var(--green)'} sub="out of 100" />
      </div>
 
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Risk assessment */}
        <div className="card">
          <div className="card-title">Risk Assessment</div>
          {latestScan ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              <RiskRing score={Math.round(latestScan.risk_score)} />
              <div style={{ flex: 1 }}>
                {[
                  { label: 'Threats Found', val: latestScan.threats_found, max: 10 },
                  { label: 'Open Ports', val: latestScan.total_ports, max: 50 },
                  { label: 'Devices', val: latestScan.hosts_up, max: 20 },
                ].map(({ label, val, max }) => (
                  <div key={label} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>
                      <span>{label}</span><span style={{ color: 'var(--text)' }}>{val}</span>
                    </div>
                    <div style={{ height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${Math.min((val / max) * 100, 100)}%`, background: 'var(--green)', borderRadius: 2 }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              Run a scan to see results
            </div>
          )}
        </div>
 
        {/* Recent findings */}
        <div className="card">
          <div className="card-title">Latest Findings</div>
          {latestScan?.findings?.length > 0 ? (
            latestScan.findings.slice(0, 5).map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border)', alignItems: 'flex-start' }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', marginTop: 4, flexShrink: 0, background: f.severity === 'critical' ? 'var(--red)' : f.severity === 'high' ? 'var(--amber)' : 'var(--green)' }} />
                <div style={{ flex: 1, fontSize: 12, lineHeight: 1.5 }}>{f.description?.slice(0, 80)}...</div>
                <span className={`badge badge-${f.severity === 'critical' || f.severity === 'high' ? 'danger' : 'warning'}`}>{f.severity}</span>
              </div>
            ))
          ) : (
            <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              {latestScan ? '✓ No critical findings' : 'No data yet'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}