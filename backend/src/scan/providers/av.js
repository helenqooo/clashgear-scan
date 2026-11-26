// Layer 2 (known-good) and layer 3 (multi-engine antivirus) services.

import { resolveTxt } from 'node:dns/promises'
import { http, limit, poll } from '../http.js'

const nf = async (fn) => { try { return await fn() } catch (e) { if (e.status === 404) return null; throw e } }

// --- CIRCL hashlookup: NSRL and other known-software sets, no key needed ---------------------
export const circl = {
  id: 'circl', name: 'CIRCL hashlookup (NSRL)', layer: 2, kind: 'file', env: [],
  async run(ctx) {
    const r = await nf(() => http(`https://hashlookup.circl.lu/lookup/sha256/${ctx.sha256}`))
      || await nf(() => http(`https://hashlookup.circl.lu/lookup/sha1/${ctx.sha1}`))
    if (!r) return null
    const trust = Number(r['hashlookup:trust'] ?? 50)
    return {
      known_good: trust >= 50,
      trust,
      verdict: trust >= 50 ? 'clean' : 'unknown',
      score: null,
      product: r.ProductName || r.FileName || null,
      vendor: r.MfgName || null,
      sources: r.KnownMalicious ? ['KnownMalicious'] : [],
      file_name: r.FileName || null,
    }
  },
}

// --- MetaDefender Cloud (OPSWAT) ----------------------------------------------------------------
const md = (path, opts = {}) => http(`https://api.metadefender.com/v4${path}`, { ...opts, headers: { apikey: process.env.METADEFENDER_API_KEY, ...(opts.headers || {}) } })
function mdSummary(r, sha256) {
  const s = r.scan_results || {}
  const details = Object.entries(s.scan_details || {})
  return {
    malicious: s.total_detected_avs || 0,
    total: s.total_avs || details.length,
    verdict: s.total_detected_avs >= 2 ? 'malicious' : s.total_detected_avs ? 'suspicious' : details.length ? 'clean' : 'unknown',
    score: s.total_avs ? Math.min(100, Math.round(((s.total_detected_avs || 0) / s.total_avs) * 220)) : null,
    detections: details.filter(([, d]) => d.threat_found).map(([engine, d]) => ({ engine, result: d.threat_found })),
    engines: details.map(([engine, d]) => ({ engine, category: d.threat_found ? 'malicious' : 'undetected', result: d.threat_found || null })),
    result: s.scan_all_result_a,
    family: r.threat_name || null,
    link: `https://metadefender.com/results/file/${sha256}/hash/overview`,
  }
}
export const metadefender = {
  id: 'metadefender', name: 'MetaDefender Cloud', layer: 3, kind: 'file', env: ['METADEFENDER_API_KEY'],
  async run(ctx) {
    await limit('metadefender', 20)
    let r = await nf(() => md(`/hash/${ctx.sha256}`))
    if (!r || !r.scan_results) {
      if (ctx.size > 140 * 1024 * 1024) return null
      let id = ctx.ref
      if (!id) {
        const up = await md('/file', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', filename: encodeURIComponent(ctx.name) }, body: ctx.file(), timeout: 300_000 })
        id = up.data_id
        ctx.saveRef(id)
      }
      r = await poll(async () => {
        const x = await md(`/file/${id}`)
        return x.scan_results?.progress_percentage === 100 ? x : null
      }, { every: 15_000, timeout: 15 * 60_000 })
    }
    return mdSummary(r, ctx.sha256)
  },
}

// --- Kaspersky OpenTIP ----------------------------------------------------------------------------
const tip = (what, value) => http(`https://opentip.kaspersky.com/api/v1/search/${what}?request=${encodeURIComponent(value)}`, { headers: { 'x-api-key': process.env.OPENTIP_API_KEY } })
const ZONE = { Red: ['malicious', 85], Orange: ['suspicious', 60], Yellow: ['suspicious', 50], Green: ['clean', null], Grey: ['unknown', null] }
export const opentip = {
  id: 'opentip', name: 'Kaspersky OpenTIP', layer: 3, kind: 'file', env: ['OPENTIP_API_KEY'],
  async run(ctx) {
    await limit('opentip', 10)
    const r = await nf(() => tip('hash', ctx.sha256))
    if (!r) return null
    const [verdict, score] = ZONE[r.Zone] || ZONE.Grey
    return {
      zone: r.Zone,
      verdict,
      score,
      status: r.FileGeneralInfo?.FileStatus,
      detections: (r.DetectionsInfo || []).map((d) => ({ engine: 'Kaspersky', result: d.DetectionName })),
      family: r.DetectionsInfo?.[0]?.DetectionName || null,
      link: `https://opentip.kaspersky.com/${ctx.sha256}/`,
    }
  },
}
export const opentipIoc = {
  id: 'opentip_ioc', name: 'Kaspersky OpenTIP IOC', layer: 9, kind: 'ioc', env: ['OPENTIP_API_KEY'],
  async run({ iocs }) {
    const items = []
    for (const [type, list] of [['ip', iocs.ips], ['domain', iocs.domains]]) {
      for (const v of list.slice(0, 4)) {
        await limit('opentip', 10)
        const r = await nf(() => tip(type, v))
        if (r) items.push({ ioc: v, type, zone: r.Zone, malicious: r.Zone === 'Red' ? 1 : 0 })
      }
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}

// --- Sophos Intelix (OAuth client credentials) --------------------------------------------------
let sophosToken = null
async function sophosAuth() {
  if (sophosToken && sophosToken.exp > Date.now()) return sophosToken.v
  const basic = Buffer.from(`${process.env.SOPHOS_CLIENT_ID}:${process.env.SOPHOS_CLIENT_SECRET}`).toString('base64')
  const r = await http('https://api.labs.sophos.com/oauth2/token', { method: 'POST', headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' })
  sophosToken = { v: r.access_token, exp: Date.now() + (r.expires_in - 60) * 1000 }
  return sophosToken.v
}
export const sophos = {
  id: 'sophos', name: 'Sophos Intelix', layer: 3, kind: 'file', env: ['SOPHOS_CLIENT_ID', 'SOPHOS_CLIENT_SECRET'],
  async run(ctx) {
    const region = process.env.SOPHOS_REGION || 'de'
    const r = await nf(async () => http(`https://${region}.api.labs.sophos.com/lookup/files/v1/${ctx.sha256}`, { headers: { Authorization: await sophosAuth() } }))
    if (!r || r.reputationScore == null) return null
    // Sophos: 0-19 malware, 20-29 PUA, 30-69 unknown, 70-100 known good.
    const s = r.reputationScore
    return {
      reputation: s,
      verdict: s < 20 ? 'malicious' : s < 30 ? 'suspicious' : s >= 70 ? 'clean' : 'unknown',
      score: s < 20 ? 85 : s < 30 ? 55 : null,
      known_good: s >= 70 || undefined,
      family: r.detectionName || null,
      detections: r.detectionName ? [{ engine: 'Sophos', result: r.detectionName }] : [],
    }
  },
}

// --- Team Cymru Malware Hash Registry (DNS, no key) ---------------------------------------------
export const cymru = {
  id: 'cymru', name: 'Team Cymru MHR', layer: 3, kind: 'file', env: [],
  async run(ctx) {
    let txt
    try { txt = await resolveTxt(`${ctx.sha1}.malware.hash.cymru.com`) } catch (e) { if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return null; throw e }
    const [ts, pct] = (txt?.[0]?.join('') || '').split(' ')
    const rate = Number(pct) || 0
    return {
      detection_rate: rate,
      last_seen: ts ? new Date(Number(ts) * 1000).toISOString() : null,
      verdict: rate >= 10 ? 'malicious' : rate ? 'suspicious' : 'unknown',
      score: rate ? Math.min(100, rate * 2) : null,
    }
  },
}

// --- ReversingLabs TitaniumCloud (paid) ---------------------------------------------------------
export const reversinglabs = {
  id: 'reversinglabs', name: 'ReversingLabs Spectra', layer: 3, kind: 'file', env: ['RL_USER', 'RL_PASSWORD'], paid: true,
  async run(ctx) {
    const auth = Buffer.from(`${process.env.RL_USER}:${process.env.RL_PASSWORD}`).toString('base64')
    const r = await nf(() => http(`https://data.reversinglabs.com/api/databrowser/malware_presence/query/sha256/${ctx.sha256}?format=json&extended=true`, { headers: { Authorization: `Basic ${auth}` } }))
    const m = r?.rl?.malware_presence
    if (!m || m.status === 'UNKNOWN') return null
    return {
      status: m.status,
      verdict: m.status === 'MALICIOUS' ? 'malicious' : m.status === 'SUSPICIOUS' ? 'suspicious' : m.status === 'KNOWN' ? 'clean' : 'unknown',
      score: m.status === 'MALICIOUS' ? 90 : m.status === 'SUSPICIOUS' ? 60 : null,
      known_good: m.status === 'KNOWN' || undefined,
      family: m.threat_name || null,
      malicious: m.scanner_match, total: m.scanner_count,
    }
  },
}

// --- IBM X-Force Exchange ---------------------------------------------------------------------------
const xf = (path) => http(`https://api.xforce.ibmcloud.com/api${path}`, {
  headers: { Authorization: `Basic ${Buffer.from(`${process.env.XFORCE_KEY}:${process.env.XFORCE_PASSWORD}`).toString('base64')}`, Accept: 'application/json' },
})
export const xforce = {
  id: 'xforce', name: 'IBM X-Force Exchange', layer: 4, kind: 'file', env: ['XFORCE_KEY', 'XFORCE_PASSWORD'],
  async run(ctx) {
    const r = await nf(() => xf(`/malware/${ctx.sha256}`))
    const m = r?.malware
    if (!m) return null
    const fam = m.origins?.external?.family?.[0] || m.family?.[0] || null
    return {
      risk: m.risk,
      verdict: m.risk === 'high' ? 'malicious' : m.risk === 'medium' ? 'suspicious' : 'unknown',
      score: m.risk === 'high' ? 80 : m.risk === 'medium' ? 50 : null,
      family: fam,
      malicious: m.origins?.external?.detectionCoverage || null,
      link: `https://exchange.xforce.ibmcloud.com/malware/${ctx.sha256}`,
    }
  },
}
export const xforceIoc = {
  id: 'xforce_ioc', name: 'IBM X-Force IOC', layer: 9, kind: 'ioc', env: ['XFORCE_KEY', 'XFORCE_PASSWORD'],
  async run({ iocs }) {
    const items = []
    for (const ip of iocs.ips.slice(0, 5)) {
      const r = await nf(() => xf(`/ipr/${ip}`))
      if (r) items.push({ ioc: ip, type: 'ip', risk: r.score, malicious: r.score >= 6 ? 1 : 0, country: r.geo?.country })
    }
    for (const u of iocs.domains.slice(0, 5)) {
      const r = await nf(() => xf(`/url/${encodeURIComponent(u)}`))
      if (r?.result) items.push({ ioc: u, type: 'domain', risk: r.result.score, malicious: r.result.score >= 6 ? 1 : 0, categories: Object.keys(r.result.cats || {}) })
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}
