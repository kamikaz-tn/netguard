import { useState, useEffect } from 'react'
import { scan, devices as devicesApi } from '../services/api.js'
 
const STATUS_MAP = {
  trusted: { badge: 'badge-safe',    label: 'Trusted' },
  unknown: { badge: 'badge-warning', label: 'Unknown' },
  threat:  { badge: 'badge-danger',  label: 'Threat'  },
}
 
// Mobile card for a single device
function DeviceCard({ device, trustedMacs, onTrust, onKick }) {
  const st = STATUS_MAP[device.status] || STATUS_MAP.unknown
  return (
    <div style={{
      background: 'var(--surface2)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '14px',
      marginBottom: 10,
    }}>
      {/* Top row: IP + status badge */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--blue)' }}>{device.ip}</span>
        <span className={`badge ${st.badge}`}>{st.label}</span>
      </div>
 
      {/* Details grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 12px', marginBottom: 10 }}>
        {[
          { label: 'MAC', val: device.mac || '—' },
          { label: 'Vendor', val: device.vendor || 'Unknown' },
          { label: 'OS', val: device.os_guess || '—' },
          { label: 'Open Ports', val: device.ports?.length ?? 0 },
        ].map(({ label, val }) => (
          <div key={label}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1, marginBottom: 2 }}>{label}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', wordBreak: 'break-all' }}>{val}</div>
          </div>
        ))}
      </div>
 
      {/* Actions */}
      <div style={{ display: 'flex', gap: 8 }}>
        {device.status !== 'trusted' && (
          <button className="btn-ghost" style={{ fontSize: 9, padding: '5px 12px', flex: 1 }}
            onClick={() => onTrust(device.mac, device.vendor)}>
            ✓ TRUST
          </button>
        )}
        <button className="btn-danger" style={{ fontSize: 9, padding: '5px 12px', flex: 1 }}
          onClick={() => onKick(device.mac)}>
          ✕ KICK
        </button>
      </div>
    </div>
  )
}
 
export default function Devices() {
  const [deviceList, setDeviceList] = useState([])
  const [trustedMacs, setTrustedMacs] = useState([])
  const [loading, setLoading] = useState(true)
  const [actionMsg, setActionMsg] = useState('')
 
  useEffect(() => { loadData() }, [])
 
  async function loadData() {
    setLoading(true)
    try {
      const [history, trusted] = await Promise.all([
        scan.history(1),
        devicesApi.listTrusted(),
      ])
      const macs = trusted.map(d => d.mac_address.toUpperCase())
      setTrustedMacs(macs)
      if (history?.length > 0) {
        const detail = await scan.detail(history[0].id)
        const enriched = (detail.devices || []).map(d => ({
          ...d,
          status: macs.includes(d.mac?.toUpperCase()) ? 'trusted' : d.status,
        }))
        setDeviceList(enriched)
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }
 
  async function handleTrust(mac, label) {
    try {
      await devicesApi.trust(mac, label)
      setActionMsg(`✓ Device ${mac} marked as trusted`)
      loadData()
    } catch (err) {
      setActionMsg(`⚠ Error: ${err.message}`)
    }
  }
 
  async function handleKick(mac) {
    try {
      await devicesApi.kick(mac)
      setActionMsg(`✓ Kick command sent for ${mac}`)
    } catch (err) {
      setActionMsg(`⚠ Error: ${err.message}`)
    }
  }
 
  return (
    <div className="animate-in">
      {/* Header */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>CONNECTED DEVICES</h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
            {deviceList.length} devices detected on network
          </div>
        </div>
        <button className="btn-primary" onClick={loadData}>↻ REFRESH</button>
      </div>
 
      {actionMsg && (
        <div style={{ background: 'var(--green-dim)', border: '1px solid rgba(0,229,160,0.3)', borderRadius: 'var(--radius)', padding: '10px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--green)', marginBottom: 16 }}>
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
            {/* Desktop table */}
            <div className="devices-table table-scroll">
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 600 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border2)' }}>
                    {['IP Address', 'MAC Address', 'Vendor', 'OS Guess', 'Ports', 'Status', 'Actions'].map(h => (
                      <th key={h} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 1.5, padding: '0 12px 10px 0', textAlign: 'left', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {deviceList.map((device, i) => {
                    const st = STATUS_MAP[device.status] || STATUS_MAP.unknown
                    return (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '12px 12px 12px 0', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--blue)', whiteSpace: 'nowrap' }}>{device.ip}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap' }}>{device.mac || '—'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontSize: 12 }}>{device.vendor || 'Unknown'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontSize: 11, color: 'var(--muted)' }}>{device.os_guess || '—'}</td>
                        <td style={{ padding: '12px 12px 12px 0', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{device.ports?.length ?? 0}</td>
                        <td style={{ padding: '12px 12px 12px 0' }}>
                          <span className={`badge ${st.badge}`}>{st.label}</span>
                        </td>
                        <td style={{ padding: '12px 0' }}>
                          <div style={{ display: 'flex', gap: 6 }}>
                            {device.status !== 'trusted' && (
                              <button className="btn-ghost" style={{ fontSize: 9, padding: '4px 10px' }} onClick={() => handleTrust(device.mac, device.vendor)}>
                                TRUST
                              </button>
                            )}
                            <button className="btn-danger" style={{ fontSize: 9, padding: '4px 10px' }} onClick={() => handleKick(device.mac)}>
                              KICK
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
 
            {/* Mobile cards */}
            <div className="device-card-mobile">
              {deviceList.map((device, i) => (
                <DeviceCard
                  key={i}
                  device={device}
                  trustedMacs={trustedMacs}
                  onTrust={handleTrust}
                  onKick={handleKick}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}