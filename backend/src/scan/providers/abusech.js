// abuse.ch: MalwareBazaar, ThreatFox, URLhaus, YARAify, Feodo Tracker. One Auth-Key for all.

import { http, formWith, urlForm, poll, limit } from '../http.js'

const H = () => ({ 'Auth-Key': process.env.ABUSECH_AUTH_KEY })
const ENV = ['ABUSECH_AUTH_KEY']

export const malwarebazaar = {
  id: 'malwarebazaar', name: 'MalwareBazaar', layer: 4, kind: 'file', env: ENV,
  async run(ctx) {
    const r = await http('https://mb-api.abuse.ch/api/v1/', { method: 'POST', headers: H(), body: urlForm({ query: 'get_info', hash: ctx.sha256 }) })
    if (r.query_status !== 'ok' || !r.data?.[0]) return null
    const d = r.data[0]
    return {
      verdict: 'malicious',
      score: 90,
      family: d.signature || null,
      tags: d.tags || [],
      first_seen: d.first_seen,
      file_type: d.file_type,
      delivery: d.delivery_method,
      yara: (d.yara_rules || []).slice(0, 20).map((y) => ({ rule: y.rule_name, author: y.author, description: y.description })),
      vendor_intel: Object.keys(d.vendor_intel || {}),
      link: `https://bazaar.abuse.ch/sample/${ctx.sha256}/`,
    }
  },
}

export const threatfox = {
  id: 'threatfox', name: 'ThreatFox', layer: 4, kind: 'file', env: ENV,
  async run(ctx) {
    const r = await http('https://threatfox-api.abuse.ch/api/v1/', { method: 'POST', headers: H(), json: { query: 'search_hash', hash: ctx.sha256 } })
    if (r.query_status !== 'ok' || !Array.isArray(r.data) || !r.data.length) return null
    const iocs = { ips: [], domains: [], urls: [] }
    for (const i of r.data) {
      if (i.ioc_type === 'ip:port') iocs.ips.push(i.ioc.split(':')[0])
      else if (i.ioc_type === 'domain') iocs.domains.push(i.ioc)
      else if (i.ioc_type === 'url') iocs.urls.push(i.ioc)
    }
    return {
      verdict: 'malicious',
      score: 90,
      family: r.data[0].malware_printable || null,
      threat_type: r.data[0].threat_type_desc,
      c2: r.data.slice(0, 30).map((i) => ({ ioc: i.ioc, type: i.ioc_type, confidence: i.confidence_level })),
      iocs,
    }
  },
}

export const urlhaus = {
  id: 'urlhaus', name: 'URLhaus', layer: 4, kind: 'file', env: ENV,
  async run(ctx) {
    const r = await http('https://urlhaus-api.abuse.ch/v1/payload/', { method: 'POST', headers: H(), body: urlForm({ sha256_hash: ctx.sha256 }) })
    if (r.query_status !== 'ok') return null
    return {
      verdict: 'malicious',
      score: 80,
      family: r.signature || null,
      first_seen: r.firstseen,
      urls: (r.urls || []).slice(0, 20).map((u) => ({ url: u.url, status: u.url_status })),
      iocs: { ips: [], domains: [], urls: (r.urls || []).map((u) => u.url).slice(0, 10) },
    }
  },
}

// YARAify scans the file against thousands of public YARA rules + ClamAV (not shared publicly).
export const yaraify = {
  id: 'yaraify', name: 'YARAify', layer: 5, kind: 'file', env: ENV,
  async run(ctx) {
    const api = 'https://yaraify-api.abuse.ch/api/v1/'
    const look = await http(api, { method: 'POST', headers: H(), json: { query: 'lookup_hash', search_term: ctx.sha256 } })
    let task = look.query_status === 'ok' ? look.data : null
    if (!task && ctx.size <= 100 * 1024 * 1024) {
      let id = ctx.ref
      if (!id) {
        await limit('yaraify', 10)
        const up = await http(api, { method: 'POST', headers: H(), body: formWith({ json_data: { clamav_scan: 1, unpack: 1, share_file: 0 } }, ctx.file(), 'file', ctx.name), timeout: 300_000 })
        id = up.data?.task_id
        if (!id) return null
        ctx.saveRef(id)
      }
      task = await poll(async () => {
        const r = await http(api, { method: 'POST', headers: H(), json: { query: 'get_results', task_id: id, malpedia_token: '' } })
        return r.query_status === 'ok' && r.data && r.data !== 'queued' ? r.data : null
      }, { every: 15_000, timeout: 10 * 60_000 })
    }
    if (!task) return null
    const tasks = Array.isArray(task.tasks) ? task.tasks : [task]
    const rules = []
    const clam = []
    for (const t of tasks) {
      for (const y of t.static_results || []) rules.push({ rule: y.rule_name, author: y.author, description: y.description })
      for (const c of t.clamav_results || []) clam.push(c)
    }
    const uniq = [...new Map(rules.map((r) => [r.rule, r])).values()]
    const mal = uniq.filter((r) => !/^(pe|dotnet|is_|has_|SUSP_|INDICATOR_)/i.test(r.rule)).length
    return {
      yara: uniq.slice(0, 50),
      clamav: [...new Set(clam)],
      verdict: clam.length || mal >= 2 ? 'suspicious' : 'unknown',
      score: clam.length ? 70 : mal >= 2 ? 45 : null,
      detections: [...new Set(clam)].map((c) => ({ engine: 'ClamAV', result: c })),
    }
  },
}

export const threatfoxIoc = {
  id: 'threatfox_ioc', name: 'ThreatFox IOC', layer: 9, kind: 'ioc', env: ENV,
  async run({ iocs }) {
    const items = []
    for (const v of [...iocs.ips.slice(0, 6), ...iocs.domains.slice(0, 6)]) {
      const r = await http('https://threatfox-api.abuse.ch/api/v1/', { method: 'POST', headers: H(), json: { query: 'search_ioc', search_term: v, exact_match: true } })
      if (r.query_status === 'ok' && r.data?.length) items.push({ ioc: v, type: r.data[0].ioc_type, malicious: 1, family: r.data[0].malware_printable, threat: r.data[0].threat_type_desc })
    }
    return { items, hits: items.length }
  },
}

export const urlhausIoc = {
  id: 'urlhaus_ioc', name: 'URLhaus IOC', layer: 9, kind: 'ioc', env: ENV,
  async run({ iocs }) {
    const items = []
    for (const host of [...iocs.ips.slice(0, 5), ...iocs.domains.slice(0, 5)]) {
      const r = await http('https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers: H(), body: urlForm({ host }) })
      if (r.query_status === 'ok' && Number(r.url_count) > 0) items.push({ ioc: host, type: 'host', malicious: 1, urls: Number(r.url_count), blacklists: r.blacklists })
    }
    for (const url of iocs.urls.slice(0, 5)) {
      const r = await http('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers: H(), body: urlForm({ url }) })
      if (r.query_status === 'ok') items.push({ ioc: url, type: 'url', malicious: 1, threat: r.threat, status: r.url_status })
    }
    return { items, hits: items.length }
  },
}

// Feodo Tracker botnet C2 list (public download, cached for an hour).
let feodo = { at: 0, set: new Map() }
export const feodoTracker = {
  id: 'feodo', name: 'Feodo Tracker', layer: 9, kind: 'ioc', env: [],
  async run({ iocs }) {
    if (Date.now() - feodo.at > 3600_000) {
      const list = await http('https://feodotracker.abuse.ch/downloads/ipblocklist.json')
      feodo = { at: Date.now(), set: new Map((Array.isArray(list) ? list : []).map((e) => [e.ip_address, e])) }
    }
    const items = iocs.ips.filter((ip) => feodo.set.has(ip)).map((ip) => ({ ioc: ip, type: 'ip', malicious: 1, family: feodo.set.get(ip).malware, status: feodo.set.get(ip).status }))
    return { items, hits: items.length, checked: iocs.ips.length }
  },
}
