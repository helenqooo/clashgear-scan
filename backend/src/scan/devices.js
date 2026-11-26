// Device tracking for free Scan keys (owner, 2026-11-05: track, don't ban). The page reports a persistent
// device id (localStorage / IndexedDB / cookie) and browser signals (lib/fp.ts); the server adds its own
// httpOnly device cookie. Keys sharing a device are linked, and when a key that Nyx flagged for misuse
// shows up again on another key, Discord gets one alert with both sides compared.

import { randomBytes } from 'node:crypto'
import { db } from '../store.js'
import { ipKind } from './ipguard.js'
import { sendAlert } from './alerts.js'

db.exec(`
  CREATE TABLE IF NOT EXISTS scan_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    device_id TEXT,
    srv_id TEXT,
    hash TEXT,
    hard_hash TEXT,
    ip TEXT,
    components_json TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    UNIQUE (key_id, device_id, hash)
  );
  CREATE INDEX IF NOT EXISTS scan_devices_dev ON scan_devices (device_id);
  CREATE INDEX IF NOT EXISTS scan_devices_srv ON scan_devices (srv_id);
  CREATE INDEX IF NOT EXISTS scan_devices_hash ON scan_devices (hash);
  CREATE INDEX IF NOT EXISTS scan_devices_hard ON scan_devices (hard_hash);
  CREATE TABLE IF NOT EXISTS scan_device_ips (key_id TEXT NOT NULL, ip TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY (key_id, ip));
  CREATE TABLE IF NOT EXISTS scan_device_alerts (key_id TEXT NOT NULL, other_key_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (key_id, other_key_id));
`)

export const SRV_COOKIE = 'cg_dev'
export const newSrvId = () => randomBytes(16).toString('hex')
const HEX32 = /^[0-9a-f]{32}$/
const now = () => Date.now()

/** Every IP a key was seen from (messages, device reports). */
export function touchKeyIp(keyId, ip) {
  if (!keyId || !ip) return
  db.prepare('INSERT INTO scan_device_ips (key_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?) ON CONFLICT(key_id, ip) DO UPDATE SET last_seen = excluded.last_seen').run(keyId, ip, now(), now())
}
/** A Nyx message's x-cg-dev header: the device was used from this IP just now. */
export function touchDevice(keyId, deviceId, ip) {
  touchKeyIp(keyId, ip)
  if (HEX32.test(String(deviceId || ''))) db.prepare('UPDATE scan_devices SET last_seen = ?, ip = ? WHERE key_id = ? AND device_id = ?').run(now(), ip, keyId, deviceId)
}

/** Stores a device report; returns the cleaned record. */
export function recordDevice({ keyId, ip, srvId, fp }) {
  const deviceId = HEX32.test(String(fp?.device_id || '')) ? fp.device_id : null
  const hash = HEX32.test(String(fp?.hash || '')) ? fp.hash : null
  const hard = HEX32.test(String(fp?.hard_hash || '')) ? fp.hard_hash : null
  let comps = {}
  try { comps = JSON.parse(JSON.stringify(fp?.components || {}).slice(0, 12_000)) } catch { /* cut mid-way: keep none */ }
  comps.restored_from = Array.isArray(fp?.restored_from) ? fp.restored_from.slice(0, 3) : []
  db.prepare(`INSERT INTO scan_devices (key_id, device_id, srv_id, hash, hard_hash, ip, components_json, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(key_id, device_id, hash) DO UPDATE SET srv_id = COALESCE(excluded.srv_id, srv_id), hard_hash = excluded.hard_hash, ip = excluded.ip,
      components_json = excluded.components_json, last_seen = excluded.last_seen, hits = hits + 1`)
    .run(keyId, deviceId, srvId, hash, hard, ip, JSON.stringify(comps), now(), now())
  touchKeyIp(keyId, ip)
  return { keyId, deviceId, srvId, hash, hard, ip, comps }
}

const subnet = (ip) => (String(ip || '').includes(':') ? String(ip).split(':').slice(0, 4).join(':') : String(ip || '').split('.').slice(0, 3).join('.'))

/**
 * Other keys on the same device. 'kesin': same device id or server cookie; 'güçlü': same full fingerprint
 * from the same network (subnet or ISP); 'olası': same hardware fingerprint from the same network. A bare
 * fingerprint match from another network is ignored (identical phones look alike).
 */
async function linkedKeys(rec) {
  const rows = db.prepare(`SELECT d.*, k.prefix, k.label, k.created_at AS key_created, k.created_ip FROM scan_devices d JOIN scan_keys k ON k.id = d.key_id
    WHERE d.key_id != ? AND k.label = 'self' AND ((? IS NOT NULL AND (d.device_id = ? OR d.srv_id = ?)) OR (? IS NOT NULL AND (d.srv_id = ? OR d.device_id = ?))
      OR (? IS NOT NULL AND d.hash = ?) OR (? IS NOT NULL AND d.hard_hash = ?))
    ORDER BY d.last_seen DESC LIMIT 50`)
    .all(rec.keyId, rec.deviceId, rec.deviceId, rec.deviceId, rec.srvId, rec.srvId, rec.srvId, rec.hash, rec.hash, rec.hard, rec.hard)
  const mine = await ipKind(rec.ip)
  const out = new Map()
  for (const r of rows) {
    let level = null, why = []
    if (rec.deviceId && r.device_id === rec.deviceId) { level = 'kesin'; why.push('aynı cihaz kimliği') }
    if (rec.srvId && (r.srv_id === rec.srvId || r.device_id === rec.srvId)) { level = 'kesin'; why.push('aynı sunucu çerezi') }
    if (rec.deviceId && r.srv_id === rec.deviceId) { level = 'kesin'; why.push('silinen kimlik sunucu çerezinden tanındı') }
    if (!level) {
      const theirs = await ipKind(r.ip)
      const sameNet = subnet(r.ip) === subnet(rec.ip) || (mine.isp && theirs.isp && mine.isp === theirs.isp)
      if (sameNet && rec.hash && r.hash === rec.hash) { level = 'güçlü'; why.push('aynı tarayıcı parmak izi + aynı ağ') }
      else if (sameNet && rec.hard && r.hard_hash === rec.hard) { level = 'olası'; why.push('aynı donanım parmak izi + aynı ağ') }
    }
    if (!level) continue
    const prev = out.get(r.key_id)
    const rank = { kesin: 3, 'güçlü': 2, 'olası': 1 }
    if (!prev || rank[level] > rank[prev.level]) out.set(r.key_id, { ...r, level, why })
  }
  return [...out.values()]
}

const strikesOfKey = (keyId) => db.prepare(`SELECT count(*) AS n, sum(pardoned) AS pardoned, max(created_at) AS last_at,
    (SELECT reason FROM scan_misuse x WHERE x.key_id = m.key_id ORDER BY created_at DESC LIMIT 1) AS reason FROM scan_misuse m WHERE key_id = ?`).get(keyId)
const ipsOfKey = (keyId) => db.prepare('SELECT ip FROM scan_device_ips WHERE key_id = ? ORDER BY last_seen DESC LIMIT 5').all(keyId).map((r) => r.ip)
const nyxOfKey = (keyId) => db.prepare('SELECT count(*) AS n FROM scan_chats WHERE key_id = ?').get(keyId).n

const esc = (s) => String(s ?? '').replace(/[\\`*_~|>\[\]()#<@]/g, '\\$&')
const code = (s) => `\`${String(s ?? '?').replace(/`/g, "'")}\`` // inside a code span nothing needs escaping
const when = (t) => (t ? new Date(t).toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '?')
const flag = (cc) => (/^[A-Z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) : '')
const ISP_SHORT = [[/turk telekom/i, 'Türk Telekom'], [/superonline/i, 'Turkcell Superonline'], [/vodafone/i, 'Vodafone'], [/turknet/i, 'TurkNet'],
  [/turkcell/i, 'Turkcell'], [/millenicom/i, 'Millenicom'], [/d-?smart/i, 'D-Smart'], [/kablonet|turksat/i, 'Türksat Kablo']]
const shortIsp = (isp) => ISP_SHORT.find(([re]) => re.test(isp || ''))?.[1] || isp || '?'
async function netLines(ip) {
  const k = await ipKind(ip)
  return `🌐 ${code(ip)}\n${esc(shortIsp(k.isp))} ${flag(k.country)}${k.kind && k.kind !== 'ok' ? `\n⚠ ${k.kind === 'hosting' ? 'VPN/sunucu' : k.kind}` : ''}`
}
const parse = (s) => { try { return JSON.parse(s) } catch { return {} } }

// Device rows for the comparison table (one code block, aligned): os, browser, GPU, screen, locale, hardware.
function osName(c) {
  const p = c.ua_data?.platform, v = parseInt(c.ua_data?.platformVersion || '', 10)
  if (p === 'Windows' && v) return v >= 13 ? 'Windows 11' : 'Windows 10'
  if (p) return `${p}${c.ua_data?.platformVersion ? ` ${c.ua_data.platformVersion}` : ''}${c.ua_data?.model ? ` (${c.ua_data.model})` : ''}`
  const ua = String(c.ua || '')
  return ua.match(/iPhone OS [\d_]+|iPad|Android [\d.]+|Mac OS X [\d_]+|Windows NT [\d.]+|Linux/)?.[0]?.replace(/_/g, '.') || '?'
}
function browserName(c) {
  const b = (c.ua_data?.fullVersionList || []).filter((x) => !/not.?a.?brand|chromium/i.test(x.brand))[0]
  if (b) return `${b.brand.replace('Google ', '')} ${String(b.version).split('.')[0]}`
  const m = String(c.ua || '').match(/(Edg|OPR|Firefox|Chrome|Version)\/(\d+)/)
  return m ? `${{ Edg: 'Edge', OPR: 'Opera', Version: 'Safari' }[m[1]] || m[1]} ${m[2]}` : '?'
}
const gpuName = (s) => String(s || '?').replace(/^ANGLE \((?:[^,()]+, )?/, '').replace(/ \(0x[0-9a-f]+\)/i, '').replace(/ Direct3D.*$|, D3D\d+\)?$|\)$/g, '').trim() || '?'
const ROWS = [
  ['Sistem', osName], ['Tarayıcı', browserName], ['GPU', (c) => gpuName(c.webgl_renderer)], ['Ekran', (c) => String(c.screen || '?').replace('x', '×').replace(/@1$/, '')],
  ['Konum', (c) => `${c.tz || '?'} · ${(c.languages || [])[0] || '?'}`], ['Donanım', (c) => `${c.cores ?? '?'} çekirdek${c.memory ? ` · ${c.memory} GB` : ''} · ${(c.fonts || []).length} font`],
]
function deviceTable(oldC = {}, newC = {}) {
  const rows = ROWS.map(([name, fn]) => { const a = fn(oldC), b = fn(newC); return `${name.padEnd(9)}${a === b ? b : `${a} → ${b}`}` })
  if (newC.webdriver || oldC.webdriver) rows.push(`${'Otomasyon'.padEnd(9)}⚠ webdriver (bot tarayıcısı)`)
  return `\`\`\`\n${rows.join('\n').replace(/`/g, "'")}\n\`\`\``
}
const DIFF_KEYS = [['ua', 'tarayıcı sürümü'], ['screen', 'ekran'], ['tz', 'saat dilimi'], ['languages', 'dil'], ['webgl_renderer', 'GPU'], ['canvas', 'canvas'], ['audio', 'ses'], ['fonts_hash', 'yazı tipleri']]
function diff(a = {}, b = {}) {
  const d = DIFF_KEYS.filter(([k]) => JSON.stringify(a[k] ?? null) !== JSON.stringify(b[k] ?? null)).map(([, n]) => n)
  return d.length ? `Değişen: ${d.join(', ')}` : 'Cihaz birebir aynı'
}
const RESTORED = { ls: 'localStorage', idb: 'IndexedDB', cookie: 'çerez' }

/** After a device report: alert once per pair when this key shares a device with a key Nyx has flagged. */
export async function checkReturn(rec, key) {
  const linked = await linkedKeys(rec)
  for (const o of linked) {
    const st = strikesOfKey(o.key_id)
    if (!st.n) continue // only people Nyx flagged before
    const fresh = db.prepare('INSERT OR IGNORE INTO scan_device_alerts (key_id, other_key_id, created_at) VALUES (?, ?, ?)').run(rec.keyId, o.key_id, now()).changes
    if (!fresh) continue
    const otherComps = parse(o.components_json)
    const oldIps = ipsOfKey(o.key_id)
    const restored = (rec.comps.restored_from || []).map((s) => RESTORED[s] || s)
    const level = { kesin: '🔴 Kesin eşleşme', 'güçlü': '🟠 Güçlü eşleşme', 'olası': '🟡 Olası eşleşme' }[o.level]
    sendAlert({
      title: '🕵️ İşaretli kullanıcı geri döndü',
      tone: 'warn',
      lines: [
        `**${level}** · ${o.why.join(', ')}${restored.length ? ` (kimlik ${restored.join(', ')} üzerinden geri yüklendi)` : ''}`,
        '-# Ban uygulanmadı, sadece takip.',
      ],
      fields: [
        { name: '🆕 Yeni anahtar', inline: true, value: `${code(`${key.prefix}…`)}\nOluşturuldu ${when(key.created_at)}\n${await netLines(rec.ip)}` },
        { name: '⏪ Eski anahtar', inline: true, value: `${code(`${o.prefix}…`)}\nSon görülme ${when(o.last_seen)}\n${(await Promise.all(oldIps.slice(0, 2).map(netLines))).join('\n') || '🌐 ?'}` },
        { name: '⚠️ Geçmişi', value: `Nyx strike **${st.n}**${st.pardoned ? ` (${st.pardoned} affedildi)` : ''} · ${nyxOfKey(o.key_id)} Nyx sohbeti\nSon sebep: *${esc(st.reason || '?')}* · ${when(st.last_at)}` },
        { name: `💻 Cihaz · ${diff(otherComps, rec.comps)}`, value: deviceTable(otherComps, rec.comps) },
      ],
    })
  }
  return linked
}

/** For the strike alert: the other keys this key's devices were seen on. */
export async function linkedSummary(keyId) {
  const recs = db.prepare('SELECT * FROM scan_devices WHERE key_id = ? ORDER BY last_seen DESC LIMIT 3').all(keyId)
  const seen = new Map()
  for (const r of recs) {
    for (const o of await linkedKeys({ keyId, deviceId: r.device_id, srvId: r.srv_id, hash: r.hash, hard: r.hard_hash, ip: r.ip })) {
      if (!seen.has(o.key_id)) seen.set(o.key_id, `\`${esc(o.prefix)}…\` (${o.level})`)
    }
  }
  return [...seen.values()]
}
