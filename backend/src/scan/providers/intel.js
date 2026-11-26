// Layer 4 threat-intel lookups and layer 9 network reputation services.

import { http, limit } from '../http.js'

const nf = async (fn) => { try { return await fn() } catch (e) { if (e.status === 404) return null; throw e } }

// --- AlienVault OTX -------------------------------------------------------------------------------
const otx = (path) => http(`https://otx.alienvault.com/api/v1/indicators${path}`, { headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY } })
export const alienvault = {
  id: 'otx', name: 'AlienVault OTX', layer: 4, kind: 'file', env: ['OTX_API_KEY'],
  async run(ctx) {
    const r = await nf(() => otx(`/file/${ctx.sha256}/general`))
    const n = r?.pulse_info?.count || 0
    if (!n) return null
    const pulses = r.pulse_info.pulses.slice(0, 10)
    // Pulses list whatever a campaign touched: attackers' tools (PuTTY, AnyDesk, 7-Zip…) show up next to the malware.
    // So OTX is a hint, never decisive on its own: a named family tops out at 65, a bare mention at 55.
    const fam = pulses.flatMap((p) => p.malware_families || []).map((f) => f.display_name || f)[0] || null
    return {
      pulses: n,
      verdict: fam && n >= 3 ? 'malicious' : 'suspicious',
      score: fam && n >= 3 ? 65 : Math.min(55, 35 + n * 3),
      family: fam,
      tags: [...new Set(pulses.flatMap((p) => p.tags || []))].slice(0, 20),
      reports: pulses.map((p) => ({ name: p.name, author: p.author_name, created: p.created })),
      attack: [...new Map(pulses.flatMap((p) => p.attack_ids || []).map((a) => [a.id, { id: a.id, name: a.name }])).values()].slice(0, 20),
      link: `https://otx.alienvault.com/indicator/file/${ctx.sha256}`,
    }
  },
}
export const alienvaultIoc = {
  id: 'otx_ioc', name: 'AlienVault OTX IOC', layer: 9, kind: 'ioc', env: ['OTX_API_KEY'],
  async run({ iocs }) {
    const items = []
    for (const ip of iocs.ips.slice(0, 5)) {
      const r = await nf(() => otx(`/IPv4/${ip}/general`))
      // Popular hosts sit in many pulses (attackers use them too): only several pulses on a non-whitelisted host count.
      if (r) items.push({ ioc: ip, type: 'ip', pulses: r.pulse_info?.count || 0, malicious: (r.pulse_info?.count || 0) >= 3 && !r.validation?.length ? 1 : 0, country: r.country_name })
    }
    for (const d of iocs.domains.slice(0, 5)) {
      const r = await nf(() => otx(`/domain/${d}/general`))
      if (r) items.push({ ioc: d, type: 'domain', pulses: r.pulse_info?.count || 0, malicious: (r.pulse_info?.count || 0) >= 3 && !r.validation?.length ? 1 : 0 })
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}

// --- InQuest Labs (Deep File Inspection: Office, PDF, scripts) -------------------------------------
export const inquest = {
  id: 'inquest', name: 'InQuest Labs DFI', layer: 5, kind: 'file', env: [],
  async run(ctx) {
    const headers = process.env.INQUEST_API_KEY ? { Authorization: `Basic ${process.env.INQUEST_API_KEY}` } : {}
    const r = await nf(() => http(`https://labs.inquest.net/api/dfi/details?sha256=${ctx.sha256}`, { headers }))
    const d = r?.data
    if (!d || !d.sha256) return null
    const cls = String(d.classification || '').toUpperCase()
    return {
      classification: cls,
      verdict: cls === 'MALICIOUS' ? 'malicious' : 'unknown',
      score: cls === 'MALICIOUS' ? 80 : null,
      file_type: d.file_type,
      alerts: (d.inquest_alerts || []).slice(0, 20).map((a) => ({ title: a.title, description: a.description, category: a.category })),
      link: `https://labs.inquest.net/dfi/sha256/${ctx.sha256}`,
    }
  },
}

// --- MalShare ----------------------------------------------------------------------------------------
export const malshare = {
  id: 'malshare', name: 'MalShare', layer: 4, kind: 'file', env: ['MALSHARE_API_KEY'],
  async run(ctx) {
    const r = await nf(() => http(`https://malshare.com/api.php?api_key=${process.env.MALSHARE_API_KEY}&action=details&hash=${ctx.sha256}`))
    if (!r || typeof r !== 'object' || r.ERROR || !r.SHA256) return null
    return { verdict: 'suspicious', score: 60, file_type: r.F_TYPE, sources: (r.SOURCES || []).slice(0, 10), yara: (r.YARA?.yara || []).slice(0, 20).map((rule) => ({ rule })) }
  },
}

// --- VirusShare ----------------------------------------------------------------------------------------
export const virusshare = {
  id: 'virusshare', name: 'VirusShare', layer: 4, kind: 'file', env: ['VIRUSSHARE_API_KEY'],
  async run(ctx) {
    await limit('virusshare', 4)
    const r = await nf(() => http(`https://virusshare.com/apiv2/file?apikey=${process.env.VIRUSSHARE_API_KEY}&hash=${ctx.sha256}`))
    if (!r || r.response !== 1) return null
    const vt = r.virustotal || {}
    return { verdict: 'malicious', score: 75, family: vt.result || null, detections: vt.detections || null, exif: r.exif ? Object.keys(r.exif).length : 0 }
  },
}

// --- ThreatMiner (no key) -----------------------------------------------------------------------------
export const threatminer = {
  id: 'threatminer', name: 'ThreatMiner', layer: 4, kind: 'file', env: [],
  async run(ctx) {
    await limit('threatminer', 10)
    const r = await nf(() => http(`https://api.threatminer.org/v2/sample.php?q=${ctx.sha256}&rt=6`, { timeout: 20_000 }))
    if (!r || r.status_code !== '200' || !r.results?.length) return null
    const av = r.results[0]?.av_detections || []
    return {
      verdict: av.length ? 'malicious' : 'suspicious',
      score: av.length ? 70 : 40,
      detections: av.slice(0, 30).map((a) => ({ engine: a.av, result: a.detection })),
    }
  },
}

// --- Hybrid Analysis lookup (the sandbox submit is in sandbox.js) ---------------------------------
export const haHeaders = () => ({ 'api-key': process.env.HYBRID_ANALYSIS_API_KEY, 'User-Agent': 'Falcon Sandbox', accept: 'application/json' })
export async function haSearch(sha256) {
  try {
    const r = await http(`https://hybrid-analysis.com/api/v2/search/hash?hash=${sha256}`, { headers: haHeaders() })
    return Array.isArray(r) ? r : r?.reports || []
  } catch (e) {
    if (e.status === 404) return []
    throw e
  }
}
export const hybridLookup = {
  id: 'hybrid_lookup', name: 'Hybrid Analysis', layer: 4, kind: 'file', env: ['HYBRID_ANALYSIS_API_KEY'],
  async run(ctx) {
    const reps = await haSearch(ctx.sha256)
    if (!reps.length) return null
    // The slim search rows no longer carry score/family; the sample overview does.
    const ov = await http(`https://hybrid-analysis.com/api/v2/overview/${ctx.sha256}`, { headers: haHeaders() }).catch(() => null)
    const best = ov ? { ...ov, environment_description: undefined } : reps.reduce((a, b) => ((b.threat_score || 0) > (a.threat_score || 0) ? b : a), reps[0])
    return {
      verdict: best.verdict === 'malicious' ? 'malicious' : best.verdict === 'suspicious' ? 'suspicious' : best.verdict === 'no specific threat' ? 'clean' : 'unknown',
      score: best.threat_score ?? null,
      family: best.vx_family || null,
      av_detect: best.av_detect ?? null,
      reports: reps.length,
      environments: [...new Set(reps.map((r) => r.environment_description).filter(Boolean))],
      tags: best.tags || [],
      link: `https://www.hybrid-analysis.com/sample/${ctx.sha256}`,
    }
  },
}

// --- Malpedia: family encyclopedia, runs once a family name is known ------------------------------
export async function malpediaFamily(name) {
  const headers = process.env.MALPEDIA_API_KEY ? { Authorization: `apitoken ${process.env.MALPEDIA_API_KEY}` } : {}
  const needle = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '')
  if (needle.length < 3) return null
  const found = await nf(() => http(`https://malpedia.caad.fkie.fraunhofer.de/api/find/family/${encodeURIComponent(needle)}`, { headers, timeout: 20_000 }))
  const id = Array.isArray(found) ? found[0]?.name : null
  if (!id) return null
  const fam = await nf(() => http(`https://malpedia.caad.fkie.fraunhofer.de/api/get/family/${encodeURIComponent(id)}`, { headers, timeout: 20_000 }))
  if (!fam) return null
  return {
    id,
    common_name: fam.common_name,
    alt_names: fam.alt_names || [],
    description: String(fam.description || '').slice(0, 1500),
    attribution: fam.attribution || [],
    references: (fam.urls || []).slice(0, 8),
    link: `https://malpedia.caad.fkie.fraunhofer.de/details/${id}`,
  }
}

// --- network reputation (layer 9) -----------------------------------------------------------------
export const abuseipdb = {
  id: 'abuseipdb', name: 'AbuseIPDB', layer: 9, kind: 'ioc', env: ['ABUSEIPDB_API_KEY'],
  async run({ iocs }) {
    const items = []
    for (const ip of iocs.ips.slice(0, 8)) {
      const r = await http(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' } })
      const d = r.data || {}
      items.push({ ioc: ip, type: 'ip', confidence: d.abuseConfidenceScore, reports: d.totalReports, isp: d.isp, country: d.countryCode, malicious: d.abuseConfidenceScore >= 50 ? 1 : 0 })
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}

export const greynoise = {
  id: 'greynoise', name: 'GreyNoise', layer: 9, kind: 'ioc', env: [],
  async run({ iocs }) {
    const headers = process.env.GREYNOISE_API_KEY ? { key: process.env.GREYNOISE_API_KEY } : {}
    const items = []
    for (const ip of iocs.ips.slice(0, 6)) {
      const r = await nf(() => http(`https://api.greynoise.io/v3/community/${ip}`, { headers }))
      if (r && (r.noise || r.riot)) items.push({ ioc: ip, type: 'ip', classification: r.classification, name: r.name, riot: r.riot, malicious: r.classification === 'malicious' ? 1 : 0 })
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}

export const shodan = {
  id: 'shodan', name: 'Shodan', layer: 9, kind: 'ioc', env: ['SHODAN_API_KEY'],
  async run({ iocs }) {
    const items = []
    for (const ip of iocs.ips.slice(0, 5)) {
      await limit('shodan', 50)
      const r = await nf(() => http(`https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}&minify=true`))
      if (r) items.push({ ioc: ip, type: 'ip', org: r.org, country: r.country_name, ports: (r.ports || []).slice(0, 20), vulns: (r.vulns || []).slice(0, 10), malicious: 0 })
    }
    return { items, hits: 0 }
  },
}

export const urlscan = {
  id: 'urlscan', name: 'urlscan.io', layer: 9, kind: 'ioc', env: ['URLSCAN_API_KEY'],
  async run({ iocs }) {
    const items = []
    for (const d of iocs.domains.slice(0, 5)) {
      const r = await http(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${d}`)}&size=5`, { headers: { 'API-Key': process.env.URLSCAN_API_KEY } })
      const tagged = (r.results || []).filter((x) => x.verdicts?.malicious || x.verdicts?.overall?.malicious).length
      items.push({ ioc: d, type: 'domain', scans: r.total || 0, malicious: tagged ? 1 : 0, latest: r.results?.[0]?.result || null })
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}

export const safebrowsing = {
  id: 'safebrowsing', name: 'Google Safe Browsing', layer: 9, kind: 'ioc', env: ['GOOGLE_SAFEBROWSING_KEY'],
  async run({ iocs }) {
    const urls = [...iocs.urls.slice(0, 20), ...iocs.domains.slice(0, 20).map((d) => `http://${d}/`)]
    if (!urls.length) return { items: [], hits: 0 }
    const r = await http(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFEBROWSING_KEY}`, {
      method: 'POST',
      json: {
        client: { clientId: 'clashgear-scan', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map((url) => ({ url })),
        },
      },
    })
    const items = (r.matches || []).map((m) => ({ ioc: m.threat?.url, type: 'url', threat: m.threatType, malicious: 1 }))
    return { items, hits: items.length, checked: urls.length }
  },
}

export const pulsedive = {
  id: 'pulsedive', name: 'Pulsedive', layer: 9, kind: 'ioc', env: ['PULSEDIVE_API_KEY'],
  async run({ iocs }) {
    const items = []
    for (const v of [...iocs.ips.slice(0, 4), ...iocs.domains.slice(0, 4)]) {
      const r = await nf(() => http(`https://pulsedive.com/api/info.php?indicator=${encodeURIComponent(v)}&key=${process.env.PULSEDIVE_API_KEY}`))
      if (r && !r.error) items.push({ ioc: v, type: r.type, risk: r.risk, threats: (r.threats || []).map((t) => t.name).slice(0, 5), malicious: ['high', 'critical'].includes(r.risk) ? 1 : 0 })
    }
    return { items, hits: items.filter((i) => i.malicious).length }
  },
}
