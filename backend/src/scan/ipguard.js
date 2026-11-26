// VPN / proxy / Tor gate for ClashGear Scan's free tier. Limits are per IP, so hopping IPs through a
// VPN would bypass them. AbuseIPDB's usage type tells a home or mobile line from a data centre:
// commercial VPNs and proxies exit from hosting networks, iCloud Private Relay and Cloudflare WARP
// from CDNs, plus Tor exits are flagged directly. One lookup per IP per day (free tier: 1000/day);
// if the lookup fails the visitor is let through rather than locked out.

import { db } from '../store.js'
import { http } from './http.js'

db.exec(`CREATE TABLE IF NOT EXISTS scan_ip_rep (
  ip TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  usage TEXT,
  isp TEXT,
  country TEXT,
  checked_at INTEGER NOT NULL
)`)

const TTL = 24 * 3600_000
const PRIVATE = /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i
export const vpnBlockOn = () => process.env.SCAN_BLOCK_VPN !== '0'

/** 'ok' | 'hosting' (VPN / proxy / server) | 'relay' (Private Relay, WARP…) | 'tor' — never throws. */
export async function ipKind(ip) {
  if (!ip || PRIVATE.test(ip) || !process.env.ABUSEIPDB_API_KEY) return { kind: 'ok' }
  const hit = db.prepare('SELECT * FROM scan_ip_rep WHERE ip = ?').get(ip)
  if (hit && Date.now() - hit.checked_at < TTL) return hit
  try {
    const r = await http(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=30`, {
      headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' }, timeout: 6000,
    })
    const d = r?.data || {}
    const usage = String(d.usageType || '')
    const kind = d.isTor ? 'tor' : /data center|web hosting|transit/i.test(usage) ? 'hosting' : /content delivery/i.test(usage) ? 'relay' : 'ok'
    const row = { ip, kind, usage, isp: String(d.isp || '').slice(0, 120), country: d.countryCode || null, checked_at: Date.now() }
    db.prepare('INSERT INTO scan_ip_rep (ip, kind, usage, isp, country, checked_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET kind = excluded.kind, usage = excluded.usage, isp = excluded.isp, country = excluded.country, checked_at = excluded.checked_at')
      .run(row.ip, row.kind, row.usage, row.isp, row.country, row.checked_at)
    return row
  } catch {
    return hit || { kind: 'ok' } // AbuseIPDB down or out of quota: fail open
  }
}

// What we tell the blocked visitor: a best guess at the VPN brand from the network owner (always
// marked as a guess), the network owner itself and the country, plus how to switch it off.
const BRANDS = [
  [/datacamp|cdn77/i, 'NordVPN / Surfshark / ExpressVPN'],
  [/m247/i, 'Proton VPN / PIA / Surfshark'],
  [/proton/i, 'Proton VPN'],
  [/tefincom|nordvpn/i, 'NordVPN'],
  [/31173|mullvad/i, 'Mullvad'],
  [/london trust|private internet access/i, 'Private Internet Access'],
  [/express ?vpn|kape/i, 'ExpressVPN'],
  [/windscribe/i, 'Windscribe'],
  [/hide\.?me|eventure/i, 'hide.me'],
  [/clouvider|zenlayer|leaseweb|packethub|ipxo|hydra|xtom|gsl networks|creanova/i, 'ticari bir VPN'],
]
export function describeMask(m) {
  const isp = m.isp || ''
  if (m.kind === 'tor') return { kind: 'tor', label: 'Tor ağı', isp, country: m.country || null, sure: true }
  if (m.kind === 'relay' || /akamai|apple|fastly/i.test(isp) && m.kind !== 'hosting' || /^akamai/i.test(isp)) {
    if (/cloudflare/i.test(isp)) return { kind: 'warp', label: 'Cloudflare WARP (1.1.1.1)', isp, country: m.country || null, sure: false }
    return { kind: 'relay', label: 'iCloud Özel Geçiş (Apple)', isp, country: m.country || null, sure: false }
  }
  if (/cloudflare/i.test(isp)) return { kind: 'warp', label: 'Cloudflare WARP (1.1.1.1)', isp, country: m.country || null, sure: false }
  const brand = BRANDS.find(([re]) => re.test(isp))?.[1]
  return { kind: 'vpn', label: brand || null, isp, country: m.country || null, sure: false }
}

/** True when this (non-owner) request comes through a VPN, proxy, relay or Tor. */
export async function isMasked(ip) {
  if (!vpnBlockOn()) return null
  const r = await ipKind(ip)
  return r.kind === 'ok' ? null : r
}
