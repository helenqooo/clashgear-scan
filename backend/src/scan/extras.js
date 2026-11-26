// Scan extras (2026-11-16): link and hash scans, similar files, version diff, report badges, the 1/3/7-day
// re-checks, provider health for the admin panel and the score regression check.

import { createHash, createCipheriv, pbkdf2Sync } from 'node:crypto'
import { inflateRawSync } from 'node:zlib'
import { http, urlForm } from './http.js'
import { TUNNEL_FETCH_PORT, tunnelState } from './tunnel.js'
import { PROVIDERS, enabled } from './providers/index.js'
import { similarTo } from './providers/local.js'
import { capeQueue } from './providers/sandbox.js'
import {
  getJob, listResults, childJobs, fuzzyCandidates, dueWatches, advanceWatch, WATCH_DAYS, providerStats, scanCounts,
  allLabels, latestJobOf, getAiVerdict, aiSpentToday, chatSpentToday, aiTotalCap, counterToday,
} from './db.js'
import { computeScore } from './score.js'
import { recheckJob } from './jobs.js'
import { sendAlert } from './alerts.js'

const SITE = 'https://clashgear.shop'

/* ======================================================================== link scans */

export class LinkError extends Error {
  constructor(code, detail = '') { super(code); this.code = code; this.detail = detail }
}

/** One request through cg-fetch on the CAPE box (malware hosts never see the shop's address). */
async function fetchVia(url, { maxBytes = 105 * 1024 * 1024, headers = {} } = {}) {
  if (!process.env.CG_FETCH_TOKEN) throw new LinkError('link_disabled')
  let res
  try {
    res = await fetch(`http://127.0.0.1:${TUNNEL_FETCH_PORT}/fetch`, {
      method: 'POST',
      headers: { Authorization: `Token ${process.env.CG_FETCH_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, headers, max_bytes: maxBytes, follow: true, timeout: 90 }),
      signal: AbortSignal.timeout(180_000),
    })
  } catch {
    throw new LinkError('fetcher_unreachable')
  }
  const buf = Buffer.from(await res.arrayBuffer())
  if (!res.ok) {
    let code = `http_${res.status}`
    try { code = JSON.parse(buf.toString()).error || code } catch { /* not JSON */ }
    throw new LinkError(code)
  }
  const n = buf.readUInt32BE(0)
  return { meta: JSON.parse(buf.subarray(4, 4 + n).toString('utf8')), body: buf.subarray(4 + n) }
}

const isHtml = (meta, body) => /text\/html/i.test(meta.headers?.['content-type'] || '') || /^\s*<(!doctype html|html|head)/i.test(body.subarray(0, 300).toString('latin1'))
const titleOf = (body) => (body.toString('utf8').match(/<title[^>]*>([^<]{1,140})/i)?.[1] || '').trim()

/** Turns share-page links of the usual file hosts into direct downloads. */
export function directLink(raw) {
  let u
  try { u = new URL(String(raw || '').trim()) } catch { throw new LinkError('bad_url') }
  if (!/^https?:$/.test(u.protocol)) throw new LinkError('bad_url')
  const h = u.hostname.toLowerCase().replace(/^www\./, '')
  if (/(^|\.)mega(\.co)?\.nz$/.test(h)) throw new LinkError('unsupported_host', 'MEGA')
  if (/(^|\.)gofile\.io$/.test(h)) throw new LinkError('unsupported_host', 'Gofile')
  if (h === 'github.com') {
    const m = u.pathname.match(/^\/([^/]+)\/([^/]+)\/blob\/(.+)$/)
    if (m) return { url: `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}`, host: 'github' }
    return { url: u.href, host: 'github' }
  }
  if (h === 'dropbox.com' || h.endsWith('.dropbox.com')) {
    u.searchParams.set('dl', '1')
    return { url: u.href, host: 'dropbox' }
  }
  if (h === 'drive.google.com' || h === 'docs.google.com') {
    const id = u.pathname.match(/\/d\/([A-Za-z0-9_-]{10,})/)?.[1] || u.searchParams.get('id')
    if (!id) throw new LinkError('bad_url')
    return { url: `https://drive.usercontent.google.com/download?id=${id}&export=download&confirm=t`, host: 'gdrive' }
  }
  if (h === 'pixeldrain.com') {
    const id = u.pathname.match(/^\/u\/([A-Za-z0-9]+)/)?.[1]
    if (id) return { url: `https://pixeldrain.com/api/file/${id}?download`, host: 'pixeldrain' }
  }
  if (h === 'mediafire.com') return { url: u.href, host: 'mediafire', page: true }
  if (/(^|\.)(discordapp\.(com|net)|discord\.com)$/.test(h)) return { url: u.href, host: 'discord' }
  return { url: u.href, host: 'direct' }
}

function fileNameOf(meta, url) {
  const cd = meta.headers?.['content-disposition'] || ''
  let n = cd.match(/filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/)?.[1]
  if (n) { try { n = decodeURIComponent(n) } catch { /* keep */ } }
  n ||= cd.match(/filename\s*=\s*"([^"]+)"/)?.[1] || cd.match(/filename\s*=\s*([^;]+)/)?.[1]
  if (!n) {
    try { n = decodeURIComponent(new URL(meta.url || url).pathname.split('/').filter(Boolean).pop() || '') } catch { n = '' }
  }
  return String(n || 'indirilen_dosya').replace(/[\\/\0-\x1f"]/g, '_').trim().slice(0, 200) || 'indirilen_dosya'
}

/** Downloads the file behind a link (following MediaFire / Google Drive pages). Returns { buf, name, source }. */
export async function fetchLink(raw) {
  const d = directLink(raw)
  let { meta, body } = await fetchVia(d.url, { maxBytes: d.page ? 3 * 1024 * 1024 : undefined })
  if (d.host === 'mediafire' && isHtml(meta, body)) {
    const html = body.toString('utf8')
    let next = html.match(/href="(https:\/\/download\d*\.mediafire\.com\/[^"]+)"/)?.[1]
    const scrambled = html.match(/data-scrambled-url="([^"]+)"/)?.[1]
    if (!next && scrambled) { try { next = Buffer.from(scrambled, 'base64').toString('utf8') } catch { /* no link */ } }
    if (!next) throw new LinkError('not_a_file', titleOf(body))
    ;({ meta, body } = await fetchVia(next))
  }
  if (d.host === 'gdrive' && isHtml(meta, body)) {
    const html = body.toString('utf8')
    const action = html.match(/<form[^>]+action="([^"]+)"/)?.[1]
    if (!action) throw new LinkError('not_a_file', titleOf(body) || 'Google Drive: dosya paylaşıma açık değil')
    const q = new URLSearchParams()
    for (const m of html.matchAll(/<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"/g)) q.set(m[1], m[2])
    ;({ meta, body } = await fetchVia(`${action.replace(/&amp;/g, '&')}?${q}`))
  }
  if (meta.status >= 400) throw new LinkError('http_error', String(meta.status))
  if (meta.truncated) throw new LinkError('file_too_large')
  if (!body.length) throw new LinkError('empty_file')
  if (isHtml(meta, body)) throw new LinkError('not_a_file', titleOf(body))
  return {
    buf: body,
    name: fileNameOf(meta, d.url),
    source: {
      url: String(raw).trim().slice(0, 1000), fetched: d.url.slice(0, 1000), final_url: String(meta.url || '').slice(0, 1000), host_kind: d.host,
      redirects: (meta.redirects || []).slice(0, 10), ip: meta.ip || null, content_type: meta.headers?.['content-type'] || null,
      server: meta.headers?.server || null, tls_verified: meta.tls_verified ?? null, at: Date.now(),
    },
  }
}

/* ======================================================================== hash lookups */

export function hashKind(h) {
  const s = String(h || '').trim().toLowerCase()
  if (/^[0-9a-f]{64}$/.test(s)) return ['sha256', s]
  if (/^[0-9a-f]{40}$/.test(s)) return ['sha1', s]
  if (/^[0-9a-f]{32}$/.test(s)) return ['md5', s]
  return [null, s]
}

/** All three hashes, a name and the size of a file known to MalwareBazaar or VirusTotal, or null. */
export async function resolveHash(hash) {
  if (process.env.ABUSECH_AUTH_KEY) {
    try {
      const r = await http('https://mb-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': process.env.ABUSECH_AUTH_KEY }, body: urlForm({ query: 'get_info', hash }), timeout: 30_000 })
      const d = r?.data?.[0]
      if (r?.query_status === 'ok' && d) return { sha256: d.sha256_hash, sha1: d.sha1_hash, md5: d.md5_hash, size: d.file_size || 0, name: d.file_name || null, from: 'malwarebazaar' }
    } catch { /* try VirusTotal */ }
  }
  if (process.env.VT_API_KEY) {
    try {
      const r = await http(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': process.env.VT_API_KEY }, timeout: 30_000 })
      const a = r?.data?.attributes
      if (a?.sha256) return { sha256: a.sha256, sha1: a.sha1, md5: a.md5, size: a.size || 0, name: a.meaningful_name || a.names?.[0] || null, from: 'virustotal' }
    } catch { /* unknown */ }
  }
  return null
}

// MalwareBazaar hands samples out as a ZipCrypto zip with the password "infected" (one member).
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0 } return t })()
const crcByte = (c, b) => (CRC[(c ^ b) & 0xff] ^ (c >>> 8)) >>> 0
export function unzipCrypto(zip, password) {
  const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
  if (eocd < 0) return null
  const cd = zip.readUInt32LE(eocd + 16)
  if (zip.readUInt32LE(cd) !== 0x02014b50) return null
  const flags = zip.readUInt16LE(cd + 8), method = zip.readUInt16LE(cd + 10), csize = zip.readUInt32LE(cd + 20), lho = zip.readUInt32LE(cd + 42)
  const start = lho + 30 + zip.readUInt16LE(lho + 26) + zip.readUInt16LE(lho + 28)
  let data = Buffer.from(zip.subarray(start, start + csize))
  if (flags & 1 && method !== 99) {
    let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890
    const upd = (b) => {
      k0 = crcByte(k0, b)
      k1 = (Math.imul((k1 + (k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0
      k2 = crcByte(k2, k1 >>> 24)
    }
    for (const ch of Buffer.from(password)) upd(ch)
    for (let i = 0; i < data.length; i++) {
      const t = (k2 | 2) & 0xffff
      const c = data[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff)
      data[i] = c
      upd(c)
    }
    data = data.subarray(12)
  }
  let real = method
  if (method === 99) {
    // WinZip AES: extra field 0x9901 gives the key strength and the real method; PBKDF2-SHA1 keys, AES-CTR (little-endian counter).
    const xs = lho + 30 + zip.readUInt16LE(lho + 26), xe = xs + zip.readUInt16LE(lho + 28)
    let strength = 0
    for (let p = xs; p + 4 <= xe;) {
      const id = zip.readUInt16LE(p), n = zip.readUInt16LE(p + 2)
      if (id === 0x9901) { strength = zip[p + 8]; real = zip.readUInt16LE(p + 9) }
      p += 4 + n
    }
    const kl = { 1: 16, 2: 24, 3: 32 }[strength]
    if (!kl) return null
    const salt = data.subarray(0, kl / 2)
    const keys = pbkdf2Sync(password, salt, 1000, kl * 2 + 2, 'sha1')
    if (!keys.subarray(kl * 2).equals(data.subarray(salt.length, salt.length + 2))) return null
    const enc = data.subarray(salt.length + 2, data.length - 10)
    const ecb = createCipheriv(`aes-${kl * 8}-ecb`, keys.subarray(0, kl), null)
    ecb.setAutoPadding(false)
    const out = Buffer.alloc(enc.length)
    const ctr = Buffer.alloc(16)
    for (let i = 0, blk = 1; i < enc.length; i += 16, blk++) {
      ctr.fill(0)
      ctr.writeUInt32LE(blk >>> 0, 0)
      const ks = ecb.update(ctr)
      for (let j = 0; j < 16 && i + j < enc.length; j++) out[i + j] = enc[i + j] ^ ks[j]
    }
    data = out
  }
  if (real === 0) return data
  if (real === 8) { try { return inflateRawSync(data) } catch { return null } }
  return null
}

/** The sample itself (MalShare, then MalwareBazaar), so a hash scan can run every layer. */
export async function downloadByHash(sha256) {
  const check = (buf) => (buf?.length > 64 && createHash('sha256').update(buf).digest('hex') === sha256 ? buf : null)
  if (process.env.MALSHARE_API_KEY) {
    try {
      const b = check(await http(`https://malshare.com/api.php?api_key=${process.env.MALSHARE_API_KEY}&action=getfile&hash=${sha256}`, { raw: true, timeout: 120_000 }))
      if (b) return { buf: b, from: 'malshare' }
    } catch { /* not there */ }
  }
  if (process.env.ABUSECH_AUTH_KEY) {
    try {
      const zip = await http('https://mb-api.abuse.ch/api/v1/', { method: 'POST', raw: true, headers: { 'Auth-Key': process.env.ABUSECH_AUTH_KEY }, body: urlForm({ query: 'get_file', sha256_hash: sha256 }), timeout: 120_000 })
      const b = zip?.[0] === 0x50 ? check(unzipCrypto(zip, 'infected')) : null
      if (b) return { buf: b, from: 'malwarebazaar' }
    } catch { /* not there */ }
  }
  return null
}

/* ======================================================================== similar files */

// Import hashes every program of one toolchain shares (.NET stubs, Go, Delphi, PyInstaller…) say nothing.
const COMMON_IMPHASH = new Set(['f34d5f2d4577ed6d9ceec516c1f5a744', 'dae02f32a21e03ce65412f6e56942daa', '9cbefe68f395e67356e2a5d8d1b285c0'])
const simCache = new Map()

/**
 * Files close to this one (TLSH / ssdeep / imphash) among everything ClashGear has scanned. Viewers see the
 * names and links of their own and of shared reports; other people's files only as verdict + family + date.
 */
export async function similarFiles(job, { viewerKeyId, owner }) {
  const key = job.id
  let hits = simCache.get(key)
  if (!hits || Date.now() - hits.at > 10 * 60_000) {
    const cands = fuzzyCandidates(job.sha256)
    const fuzzy = await similarTo({ tlsh: job.tlsh, ssdeep: job.ssdeep }, cands.filter((c) => c.tlsh || c.ssdeep).map((c) => [c.id, c.tlsh, c.ssdeep])).catch(() => [])
    const byId = new Map(cands.map((c) => [c.id, c]))
    const out = new Map()
    for (const [id, dist, ss] of fuzzy) {
      const c = byId.get(id)
      if (!c) continue
      const sim = Math.round(Math.max(ss || 0, dist == null ? 0 : Math.max(0, 100 - dist)))
      out.set(id, { c, tlsh: dist, ssdeep: ss || 0, imphash: false, sim })
    }
    const imp = job.static?.pe?.imphash
    if (imp && !COMMON_IMPHASH.has(imp)) {
      const same = cands.filter((c) => c.imphash === imp)
      if (same.length <= 25) for (const c of same) {
        const e = out.get(c.id) || { c, tlsh: null, ssdeep: 0, imphash: false, sim: 60 }
        e.imphash = true
        e.sim = Math.max(e.sim, 60)
        out.set(c.id, e)
      }
    }
    // one entry per distinct file (the newest scan of it)
    const bySha = new Map()
    for (const e of [...out.values()].sort((a, b) => b.c.created_at - a.c.created_at)) if (!bySha.has(e.c.sha256)) bySha.set(e.c.sha256, e)
    hits = { at: Date.now(), list: [...bySha.values()].sort((a, b) => b.sim - a.sim).slice(0, 15) }
    simCache.set(key, hits)
    if (simCache.size > 500) simCache.delete(simCache.keys().next().value)
  }
  return hits.list.map(({ c, tlsh, ssdeep, imphash, sim }) => {
    const root = c.parent_id ? getJob(c.parent_id) : c
    const visible = owner || c.key_id === viewerKeyId || !!root?.public
    const fam = getJob(c.id)?.ai?.computed?.family || null
    return {
      similarity: sim, tlsh_distance: tlsh, ssdeep, imphash,
      verdict: c.verdict, score: c.score, family: fam, created_at: c.created_at,
      mine: c.key_id === viewerKeyId,
      ...(visible ? { id: c.id, file_name: c.file_name, sha256: c.sha256 } : {}),
    }
  })
}

/* ======================================================================== version diff */

const setOf = (a) => new Set((a || []).filter(Boolean))
function delta(a, b) {
  const A = setOf(a), B = setOf(b)
  return { added: [...B].filter((x) => !A.has(x)).slice(0, 80), removed: [...A].filter((x) => !B.has(x)).slice(0, 80), same: [...B].filter((x) => A.has(x)).length }
}
const resOf = (results, src) => results.find((r) => r.source === src && r.status === 'done')?.summary || null
function facts(job) {
  const results = listResults(job.id)
  const st = job.static || {}
  const pe = st.pe || {}
  const cs = resOf(results, 'cgstatic')
  const sigs = results.filter((r) => r.status === 'done' && r.layer === 8).flatMap((r) => (r.summary?.signatures || []).filter((s) => !s.noise).map((s) => s.name))
  return {
    id: job.id, file_name: job.file_name, sha256: job.sha256, size: job.size, created_at: job.created_at,
    verdict: job.verdict, score: job.score, family: job.ai?.computed?.family || null, type: st.type,
    compiled_at: pe.compiled_at || null, signed: !!pe.signed, signer: results.map((r) => r.summary?.signature).find(Boolean)?.signers || null,
    packers: [...(pe.packer_hints || []), ...((cs?.die || []).filter((d) => /packer|protector|installer|sfx/i.test(d.type)).map((d) => d.string))],
    sections: (pe.sections || []).map((s) => `${s.name} (${Number(s.entropy || 0).toFixed(1)})`),
    imports: (pe.imports || []).flatMap((i) => (i.funcs || []).map((f) => `${i.dll}!${f}`)),
    urls: [...(st.indicators?.urls || []), ...(cs?.iocs?.urls || [])], ips: st.indicators?.ips || [], domains: st.indicators?.domains || [],
    yara: (cs?.yara || []).map((y) => y.rule),
    capabilities: (cs?.capa?.capabilities || []).map((c) => c.name),
    exfil: (cs?.stealer?.exfil || []).map((e) => e.kind),
    steals: cs?.stealer?.steal_categories || [],
    behaviour: (job.ai?.computed?.behaviour || []).map((b) => b.id),
    signatures: [...new Set(sigs)].slice(0, 120),
    python_modules: cs?.pyinstaller?.notable_modules || [],
    apk_permissions: cs?.apk?.permissions || [],
  }
}

/** What changed from an older scan (a) to a newer one (b) of "the same program". */
export function diffJobs(a, b) {
  const A = facts(a), B = facts(b)
  const field = (k) => ({ before: A[k], after: B[k], changed: JSON.stringify(A[k]) !== JSON.stringify(B[k]) })
  const lists = ['imports', 'sections', 'urls', 'ips', 'domains', 'yara', 'capabilities', 'exfil', 'steals', 'behaviour', 'signatures', 'packers', 'python_modules', 'apk_permissions']
  const out = { a: { id: A.id, file_name: A.file_name, sha256: A.sha256, created_at: A.created_at }, b: { id: B.id, file_name: B.file_name, sha256: B.sha256, created_at: B.created_at } }
  for (const k of ['verdict', 'score', 'family', 'type', 'size', 'compiled_at', 'signed', 'signer']) out[k] = field(k)
  for (const k of lists) out[k] = delta(A[k], B[k])
  // The changes a user should look at first: new ways out, new targets, new behaviour, a lost signature.
  const alerts = []
  if (out.exfil.added.length) alerts.push({ code: 'new_exfil', items: out.exfil.added })
  if (out.steals.added.length) alerts.push({ code: 'new_targets', items: out.steals.added })
  if (out.behaviour.added.length) alerts.push({ code: 'new_behaviour', items: out.behaviour.added })
  if (A.signed && !B.signed) alerts.push({ code: 'signature_lost' })
  if (out.urls.added.length + out.domains.added.length + out.ips.added.length) alerts.push({ code: 'new_hosts', items: [...out.domains.added, ...out.ips.added, ...out.urls.added].slice(0, 10) })
  const rank = { clean: 0, unknown: 1, pua: 2, suspicious: 3, malicious: 4 }
  if ((rank[B.verdict] ?? 1) > (rank[A.verdict] ?? 1)) alerts.push({ code: 'verdict_worse', items: [A.verdict, B.verdict] })
  out.alerts = alerts
  return out
}

/* ======================================================================== 1 / 3 / 7-day re-checks */

// Sources that answer by hash and change their minds over time.
const VERDICT_TR = { clean: 'Temiz', malicious: 'Zararlı', suspicious: 'Şüpheli', pua: 'Hile aracı / PUA', unknown: 'Bilinmiyor' }
const WATCH_SOURCES =['virustotal', 'metadefender', 'malwarebazaar', 'threatfox', 'hybrid_lookup', 'alienvault', 'malshare', 'yaraify', 'circl', 'opentip', 'xforce', 'reversinglabs', 'inquest']
let watching = false
async function watchTick() {
  if (watching) return
  watching = true
  try {
    for (const w of dueWatches(Date.now(), 8)) {
      const job = getJob(w.job_id)
      const day = WATCH_DAYS[w.round] ?? WATCH_DAYS.at(-1)
      if (!job || job.status !== 'done') { advanceWatch(w.job_id, { at: Date.now(), day, skipped: true }, false); continue }
      const before = { score: job.score, verdict: job.verdict }
      let after = null
      try { after = await recheckJob(job.id, WATCH_SOURCES) } catch (e) { console.error('watch recheck failed', job.id, e) }
      const vt = listResults(job.id).find((r) => r.source === 'virustotal')?.summary
      const entry = { at: Date.now(), day, before, after: after ? { score: after.score, verdict: after.verdict } : null, vt: vt ? { malicious: vt.malicious ?? null, total: vt.total ?? null } : null }
      const changed = !!after && after.verdict !== before.verdict
      advanceWatch(job.id, entry, changed)
      if (changed) {
        sendAlert({
          title: 'Scan: karar değişti', tone: after.verdict === 'malicious' ? 'bad' : 'info', url: `${SITE}/scan/r/${job.id}`,
          lines: [`${job.file_name}`, `${day}. gün kontrolü: ${VERDICT_TR[before.verdict] || before.verdict} → ${VERDICT_TR[after.verdict] || after.verdict} (${before.score} → ${after.score})`],
        }).catch(() => {})
      }
    }
  } finally {
    watching = false
  }
}
export function startWatcher() {
  setTimeout(watchTick, 90_000)
  setInterval(watchTick, 10 * 60_000).unref?.()
}

/* ======================================================================== admin health */

async function ping(port, path = '/') {
  const t = Date.now()
  try {
    const r = await fetch(`http://127.0.0.1:${port}${path}`, { signal: AbortSignal.timeout(6000) })
    return { up: true, status: r.status, ms: Date.now() - t }
  } catch { return { up: false, ms: Date.now() - t } }
}

export async function scanHealth() {
  const day = Date.now() - 86400_000, week = Date.now() - 7 * 86400_000
  const stats = providerStats(day)
  const byId = new Map()
  for (const s of stats) {
    const e = byId.get(s.source) || { done: 0, not_found: 0, error: 0, disabled: 0, running: 0, queued: 0, errors: {}, avg_ms: null }
    e[s.status] = (e[s.status] || 0) + s.n
    if (s.status === 'error') e.errors[s.error || '?'] = (e.errors[s.error || '?'] || 0) + s.n
    if (s.status === 'done' && s.avg_ms) e.avg_ms = Math.round(s.avg_ms)
    byId.set(s.source, e)
  }
  const providers = PROVIDERS.map((p) => ({ id: p.id, name: p.name, layer: p.layer, enabled: enabled(p), manual: !!p.manual, last24: byId.get(p.id) || null }))
  const [cape, fetcher, statik, ghidra, files] = await Promise.all([capeQueue(), ping(18004, '/'), ping(18005, '/'), ping(18002, '/'), ping(18001, '/')])
  return {
    at: Date.now(),
    scans: { day: scanCounts(day), week: scanCounts(week) },
    providers,
    ai: { reports_usd: aiSpentToday(), chat_usd: chatSpentToday(), cap_usd: aiTotalCap() },
    tunnel: tunnelState,
    services: { cape_queue: cape, fetcher, static: statik, ghidra, files },
    counters: { cape_auto_today: counterToday('capeauto'), link_scans_today: counterToday('linkscan'), hash_scans_today: counterToday('hashscan') },
  }
}

/* ======================================================================== score regression */

const sameClass = (want, got) => want === got || (want === 'pua' && got === 'suspicious') || (want === 'clean' && got === 'unknown')

/**
 * Re-scores every labelled file (admin labels + owner overrides) from its stored results with the current
 * score.js and no override, and lists the ones whose verdict no longer matches the label.
 */
export function runRegression() {
  const rows = []
  for (const l of allLabels()) {
    const id = l.job_id || latestJobOf(l.sha256)
    const job = id ? getJob(id) : null
    if (!job) { rows.push({ sha256: l.sha256, expected: l.verdict, origin: l.origin, missing: true }); continue }
    const c = computeScore(listResults(job.id), job.static, { aiVerdict: getAiVerdict(job.sha256), children: childJobs(job.id), fileName: job.file_name })
    rows.push({ sha256: l.sha256, job_id: job.id, file_name: job.file_name, expected: l.verdict, got: c.verdict, score: c.score, origin: l.origin, note: l.note || '', pass: sameClass(l.verdict, c.verdict), reasons: c.reasons.slice(0, 4).map((r) => r.code) })
  }
  const scored = rows.filter((r) => !r.missing)
  return { at: Date.now(), total: rows.length, scored: scored.length, passed: scored.filter((r) => r.pass).length, failed: scored.filter((r) => !r.pass), missing: rows.filter((r) => r.missing).length, rows }
}
