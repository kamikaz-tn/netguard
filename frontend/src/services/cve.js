/**
 * netguard/frontend/src/services/cve.js
 * ───────────────────────────────────────
 * CVE lookup helpers.  All calls go through the NetGuard backend proxy
 * (which caches results and handles NVD rate-limiting for us).
 *
 * Usage:
 *   import { lookupCVE, lookupCVEByPort } from './cve.js'
 *
 *   const result = await lookupCVE('apache', '2.4.51')
 *   // → { query, total_results, cves: [{cve_id, description, severity, cvss_score, published, url}] }
 */

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function _get(path) {
  const res = await fetch(`${BASE_URL}${path}`, {
    credentials: 'include',   // send httpOnly JWT cookie
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.detail || `CVE lookup failed (${res.status})`)
  }
  return res.json()
}

/**
 * Look up CVEs for a service name + optional version string.
 * @param {string} service  - e.g. "apache", "openssh", "mysql"
 * @param {string} [version] - e.g. "2.4.51"  (omit if unknown)
 */
export async function lookupCVE(service, version = '') {
  const params = new URLSearchParams({ service })
  if (version && version.trim()) params.set('version', version.trim())
  return _get(`/api/cve/lookup?${params}`)
}

/**
 * Look up CVEs for a well-known port number.
 * Uses the server-side port → service mapping.
 * @param {number} port
 */
export async function lookupCVEByPort(port) {
  return _get(`/api/cve/port/${port}`)
}

/**
 * Severity → CSS variable mapping (matches the Cyber-Red theme).
 */
export const SEVERITY_COLOR = {
  CRITICAL: 'var(--red-bright)',
  HIGH:     'var(--red)',
  MEDIUM:   'var(--amber)',
  LOW:      'var(--blue)',
  NONE:     'var(--muted)',
}

export const SEVERITY_BADGE = {
  CRITICAL: 'badge-danger',
  HIGH:     'badge-danger',
  MEDIUM:   'badge-warning',
  LOW:      'badge-info',
  NONE:     'badge-info',
}
