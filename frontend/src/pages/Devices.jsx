import { useState, useEffect } from 'react'
import { scan, devices as devicesApi } from '../services/api.js'
 
const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000"
 
const STATUS_MAP = {
  trusted: { badge: 'badge-safe',    label: 'Trusted' },
  unknown: { badge: 'badge-warning', label: 'Unknown' },
  threat:  { badge: 'badge-danger',  label: 'Threat'  },
}
 
const KICK_STATUS_MAP = {
  pending: { color: 'var(--amber)', label: '⏳ Kick pending...' },
  done:    { color: 'var(--green)', label: '✓ Kicked' },
  failed:  { color: 'var(--red)',   label: '✗ Kick failed' },
}
 
// ── API helpers — use credentials:include (cookie auth) ───────────────────────
async function kickDevice(macAddress, targetIp) {
  const res = await fetch(`${BASE_URL}/api/devices/kick`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'NetGuard' },
    credentials: 'include',   // ← sends httpOnly cookie
    body: JSON.stringify({ mac_address: macAddress, target_ip: targetIp || null }),
  })
  if (res.status === 409) {
    const data = await res.json()
    throw new Error(data.detail || 'Kick already pending')
  }
  if (!res.ok) throw new Error('Failed to queue kick')
  return res.json()
}
 
async function fetchKicks() {
  const res = await fetch(`${BASE_URL}/api/devices/kicks`, {
    credentials: 'include',   // ← sends httpOnly cookie
  })
  if (!res.ok) return []
  return res.json()
}
 
// ── Mobile card ───────────────────────────────────────────────────────────────
function DeviceCard({ device, onTrust, onKick, kickStatus }) {
  const st = STATUS_MAP[device.status] || STATUS_MAP.unknown
  const ks = kickStatus ? KICK_STATUS_MAP[kickStatus] : null
 
  return (
    <div style={{
      background: 'var(--surface2)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '14px', marginBottom: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--blue)' }}>{device.ip}</span>
        <span className={`badge ${st.badge}`}>{st.label}</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 12px', marginBottom: 10 }}>
        {[
          { label: 'MAC',        val: device.mac || '—' },
          { label: 'Vendor',     val: device.vendor || 'Unknown' },
          { label: 'OS',         val: device.os_guess || '—' },
          { label: 'Open Ports', val: device.ports?.length ?? 0 },
        ].map(({ label, val }) => (
          <div key={label}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1, marginBottom: 2 }}>{label}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', wordBreak: 'break-all' }}>{val}</div>
          </div>
        ))}
      </div>
      {ks && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: ks.color, marginBottom: 8 }}>{ks.label}</div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        {device.status !== 'trusted' && device.mac && (
          <button className="btn-ghost" style={{ fontSize: 9, padding: '5px 12px', flex: 1 }}
            onClick={() => onTrust(device.mac, device.vendor)}>✓ TRUST</button>
        )}
        {device.mac && (
          <button
            className="btn-danger"
            style={{ fontSize: 9, padding: '5px 12px', flex: 1, opacity: kickStatus === 'pending' ? 0.5 : 1 }}
            disabled={kickStatus === 'pending'}
            onClick={() => onKick(device.mac, device.ip)}
          >
            {kickStatus === 'pending' ? '⏳ PENDING' : '✕ KICK'}
          </button>
        )}
      </div>
    </div>
  )
}
 
// ── Main component ────────────────────────────────────────────────────────────
export default function Devices() {
  const [deviceList, setDeviceList]     = useState([])
  const [trustedMacs, setTrustedMacs]   = useState([])
  const [loading, setLoading]           = useState(true)
  const [actionMsg, setActionMsg]       = useState('')
  const [scanInfo, setScanInfo]         = useState(null)
  const [kickStatuses, setKickStatuses] = useState({})
 
  useEffect(() => { loadData() }, [])
 
  useEffect(() => {
    const hasPending = Object.values(kickStatuses).some(s => s === 'pending')
    if (!hasPending) return
    const interval = setInterval(refreshKickStatuses, 5000)
    return () => clearInterval(interval)
  }, [kickStatuses])
 
  async function loadData() {
    setLoading(true)
    try {
      const [history, trusted, kicks] = await Promise.all([
        scan.history(1),
        devicesApi.listTrusted(),
        fetchKicks(),
      ])
 
      const macs = trusted.map(d => d.mac_address.toUpperCase())
      setTrustedMacs(macs)
 
      const ksMap = {}
      for (const k of kicks) {
        const mac = k.mac_address.toUpperCase()
        if (!ksMap[mac]) ksMap[mac] = k.status
      }
      setKickStatuses(ksMap)
 
      if (history?.length > 0) {
        setScanInfo(history[0])
        const detail = await scan.detail(history[0].id)
        const allDevices = detail.devices || []
        const enriched = allDevices.map(d => ({
          ...d,
          status: macs.includes(d.mac?.toUpperCase()) ? 'trusted' : d.status || 'unknown',
        }))
        setDeviceList(enriched)
      }
    } catch (err) {
      console.error('loadData error:', err)
    } finally {
      setLoading(false)
    }
  }
 
  async function refreshKickStatuses() {
    try {
      const kicks = await fetchKicks()
      const ksMap = {}
      for (const k of kicks) {
        const mac = k.mac_address.toUpperCase()
        if (!ksMap[mac]) ksMap[mac] = k.status
      }
      setKickStatuses(ksMap)
    } catch {}
  }
 
  async function handleTrust(mac, label) {
    if (!mac) return
    try {
      await devicesApi.trust(mac, label)
      setActionMsg(`✓ Device ${mac} marked as trusted`)
      loadData()
    } catch (err) {
      setActionMsg(`⚠ Error: ${err.message}`)
    }
  }
 
  async function handleKick(mac, ip) {
    if (!mac) return
    try {
      await kickDevice(mac, ip)
      setKickStatuses(prev => ({ ...prev, [mac.toUpperCase()]: 'pending' }))
      setActionMsg(`⏳ Kick queued for ${mac} — agent will execute on next poll`)
    } catch (err) {
      setActionMsg(`⚠ ${err.message}`)
    }
  }
 
  const threatCount  = deviceList.filter(d => d.status === 'threat').length
  const unknownCount = deviceList.filter(d => d.status === 'unknown').length
  const trustedCount = deviceList.filter(d => d.status === 'trusted').length
 
  return (
    <div className="animate-in">
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>CONNECTED DEVICES</h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
            {deviceList.length} devices detected
            {scanInfo && ` · last scan ${new Date(scanInfo.created_at).toLocaleString()}`}
          </div>
        </div>
        <button className="btn-primary" onClick={loadData}>↻ REFRESH</button>
      </div>
 
      {deviceList.length > 0 && (
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
          <span className="badge badge-danger">{threatCount} Threat{threatCount !== 1 ? 's' : ''}</span>
          <span className="badge badge-warning">{unknownCount} Unknown</span>
          <span className="badge badge-safe">{trustedCount} Trusted</span>
        </div>
      )}
 
      <div style={{
        background: 'rgba(245,166,35,0.06)', border: '1px solid rgba(245,166,35,0.2)',
        borderRadius: 'var(--radius)', padding: '10px 16px', marginBottom: 16,
        fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', lineHeight: 1.7,
      }}>
        ⚡ <span style={{ color: 'var(--amber)' }}>Kick requires the local agent running.</span>{' '}
        Clicking Kick queues a command — your agent picks it up on the next{' '}
        <code style={{ color: 'var(--green)' }}>--scan</code> or{' '}
        <code style={{ color: 'var(--green)' }}>--watch</code> cycle and executes ARP deauth.
        Status updates every 5s automatically.
      </div>
 
      {actionMsg && (
        <div style={{
          background: actionMsg.startsWith('⚠') ? 'var(--red-dim)' : 'var(--green-dim)',
          border: `1px solid ${actionMsg.startsWith('⚠') ? 'rgba(255,68,68,0.3)' : 'rgba(0,229,160,0.3)'}`,
          borderRadius: 'var(--radius)', padding: '10px 16px',
          fontFamily: 'var(--font-mono)', fontSize: 11,
          color: actionMsg.startsWith('⚠') ? 'var(--red)' : 'var(--green)',
          marginBottom: 16,
        }}>
          {actionMsg}
        </div>
      )}
 
      <div className="card">
        <div className="card-title">Device List</div>
 
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}><span className="spinner" /></div>
        ) : deviceList.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            No devices found — run a scan from the Overview page first
          </div>
        ) : (
          <>
            <div className="devices-table table-scroll">
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 650 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border2)' }}>
                    {['IP Address', 'MAC Address', 'Hostname', 'Vendor', 'OS', 'Ports', 'Status', 'Actions'].map(h => (
                      <th key={h} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1.5, padding: '0 12px 10px 0', textAlign: 'left', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {deviceList.map((device, i) => {
                    const st = STATUS_MAP[device.status] || STATUS_MAP.unknown
                    const kickStatus = kickStatuses[device.mac?.toUpperCase()]
                    const ks = kickStatus ? KICK_STATUS_MAP[kickStatus] : null
 
                    return (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '12px 12px 12px 0', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--blue)', whiteSpace: 'nowrap' }}>{device.ip}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap' }}>{device.mac || '—'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontSize: 11, color: 'var(--muted)', maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{device.hostname || '—'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontSize: 12 }}>{device.vendor || 'Unknown'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontSize: 11, color: 'var(--muted)' }}>{device.os_guess || '—'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{device.ports?.length ?? 0}</td>
                        <td style={{ padding: '12px 12px 12px 0' }}>
                          <span className={`badge ${st.badge}`}>{st.label}</span>
                        </td>
                        <td style={{ padding: '12px 0' }}>
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                            {ks && (
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: ks.color, whiteSpace: 'nowrap' }}>
                                {ks.label}
                              </span>
                            )}
                            {device.status !== 'trusted' && device.mac && !ks && (
                              <button className="btn-ghost" style={{ fontSize: 9, padding: '4px 10px' }}
                                onClick={() => handleTrust(device.mac, device.vendor)}>
                                TRUST
                              </button>
                            )}
                            {device.mac && (
                              <button
                                className="btn-danger"
                                style={{ fontSize: 9, padding: '4px 10px', opacity: kickStatus === 'pending' ? 0.5 : 1 }}
                                disabled={kickStatus === 'pending'}
                                onClick={() => handleKick(device.mac, device.ip)}
                              >
                                {kickStatus === 'pending' ? '⏳' : 'KICK'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
 
            <div className="device-card-mobile">
              {deviceList.map((device, i) => (
                <DeviceCard
                  key={i}
                  device={device}
                  onTrust={handleTrust}
                  onKick={handleKick}
                  kickStatus={kickStatuses[device.mac?.toUpperCase()]}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}