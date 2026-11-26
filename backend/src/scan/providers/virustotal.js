import { http, formWith, limit, poll } from '../http.js'

const BASE = 'https://www.virustotal.com/api/v3'
const key = () => process.env.VT_API_KEY
const rpm = () => Number(process.env.VT_RPM || 4)
const vt = async (path, opts = {}) => {
  await limit('virustotal', rpm())
  return http(`${BASE}${path}`, { ...opts, headers: { 'x-apikey': key(), ...(opts.headers || {}) } })
}
const get = async (path) => {
  try { return await vt(path) } catch (e) { if (e.status === 404) return null; throw e }
}

function fileSummary(a, sha256) {
  const st = a.last_analysis_stats || {}
  const total = (st.malicious || 0) + (st.suspicious || 0) + (st.undetected || 0) + (st.harmless || 0)
  const detections = Object.entries(a.last_analysis_results || {})
    .filter(([, r]) => r.category === 'malicious' || r.category === 'suspicious')
    .map(([engine, r]) => ({ engine, result: r.result }))
  const mal = st.malicious || 0
  return {
    malicious: mal,
    suspicious: st.suspicious || 0,
    total,
    detections,
    engines: Object.entries(a.last_analysis_results || {}).map(([engine, r]) => ({ engine, category: r.category, result: r.result })),
    verdict: mal >= 3 ? 'malicious' : mal || st.suspicious ? 'suspicious' : total ? 'clean' : 'unknown',
    score: total ? Math.min(100, Math.round((mal / total) * 220)) : null,
    family: a.popular_threat_classification?.suggested_threat_label || null,
    tags: a.tags || [],
    known_good: a.trusted_verdict?.verdict === 'goodware' || undefined,
    names: (a.names || []).slice(0, 8),
    type: a.type_description,
    signature: a.signature_info ? { signers: a.signature_info.signers, verified: a.signature_info.verified, product: a.signature_info.product } : null,
    yara: (a.crowdsourced_yara_results || []).slice(0, 20).map((y) => ({ rule: y.rule_name, source: y.ruleset_name, description: y.description })),
    sigma: a.sigma_analysis_stats || null,
    sandbox_verdicts: Object.entries(a.sandbox_verdicts || {}).map(([s, v]) => ({ sandbox: s, category: v.category, family: v.malware_names?.[0] })),
    first_seen: a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString() : null,
    link: `https://www.virustotal.com/gui/file/${sha256}`,
  }
}

export const virustotal = {
  id: 'virustotal', name: 'VirusTotal', layer: 3, kind: 'file', env: ['VT_API_KEY'],
  async run(ctx) {
    let rep = await get(`/files/${ctx.sha256}`)
    if (!rep) {
      if (ctx.size > 650 * 1024 * 1024) return null
      let analysisId = ctx.ref
      if (!analysisId) {
        const url = ctx.size > 32 * 1024 * 1024 ? (await vt('/files/upload_url')).data : `${BASE}/files`
        await limit('virustotal', rpm())
        const up = await http(url, { method: 'POST', headers: { 'x-apikey': key() }, body: formWith({}, ctx.file(), 'file', ctx.name), timeout: 300_000 })
        analysisId = up.data.id
        ctx.saveRef(analysisId)
      }
      await poll(async () => ((await vt(`/analyses/${analysisId}`)).data.attributes.status === 'completed' ? true : null), { every: 30_000, timeout: 20 * 60_000 })
      rep = await get(`/files/${ctx.sha256}`)
      if (!rep) return null
    }
    return fileSummary(rep.data.attributes, ctx.sha256)
  },
}

// Behaviour reports from VirusTotal's own sandboxes (Zenbox, CAPE, Microsoft Sysinternals, ...).
export const vtSandbox = {
  id: 'vt_sandbox', name: 'VirusTotal Sandboxes', layer: 8, kind: 'file', env: ['VT_API_KEY'], after: ['virustotal'],
  async run(ctx) {
    const s = await get(`/files/${ctx.sha256}/behaviour_summary`)
    if (!s?.data || !Object.keys(s.data).length) return null
    const d = s.data
    const list = await get(`/files/${ctx.sha256}/behaviours?limit=20`)
    const sandboxes = [...new Set((list?.data || []).map((b) => b.attributes?.sandbox_name).filter(Boolean))]
    const ips = (d.ip_traffic || []).map((x) => x.destination_ip).filter(Boolean)
    const domains = (d.dns_lookups || []).map((x) => x.hostname).filter(Boolean)
    const urls = (d.http_conversations || []).map((x) => x.url).filter(Boolean)
    const attack = (d.mitre_attack_techniques || []).map((t) => ({ id: t.id, name: t.signature_description, severity: t.severity }))
    const high = (d.signature_matches || []).filter((m) => /high/i.test(m.severity || '')).length
    return {
      sandboxes,
      verdict: d.verdicts?.includes('MALWARE') ? 'malicious' : attack.length ? 'suspicious' : 'unknown',
      score: d.verdicts?.includes('MALWARE') ? 85 : high ? 60 : null,
      processes: (d.processes_tree || []).slice(0, 30),
      processes_created: (d.processes_created || []).slice(0, 40),
      command_executions: (d.command_executions || []).slice(0, 40),
      files_dropped: (d.files_dropped || []).slice(0, 40).map((f) => ({ path: f.path, sha256: f.sha256 })),
      registry_set: (d.registry_keys_set || []).slice(0, 40),
      mutexes: (d.mutexes_created || []).slice(0, 30),
      attack,
      signatures: (d.signature_matches || []).slice(0, 40).map((m) => ({ name: m.name || m.description, severity: m.severity })),
      iocs: { ips, domains, urls },
      link: `https://www.virustotal.com/gui/file/${ctx.sha256}/behavior`,
    }
  },
}

export const vtIoc = {
  id: 'vt_ioc', name: 'VirusTotal IOC', layer: 9, kind: 'ioc', env: ['VT_API_KEY'],
  async run({ iocs }) {
    const out = []
    for (const ip of iocs.ips.slice(0, 4)) {
      const r = await get(`/ip_addresses/${ip}`)
      const st = r?.data?.attributes?.last_analysis_stats
      if (st) out.push({ ioc: ip, type: 'ip', malicious: st.malicious || 0, owner: r.data.attributes.as_owner, country: r.data.attributes.country })
    }
    for (const d of iocs.domains.slice(0, 4)) {
      const r = await get(`/domains/${d}`)
      const st = r?.data?.attributes?.last_analysis_stats
      if (st) out.push({ ioc: d, type: 'domain', malicious: st.malicious || 0, categories: Object.values(r.data.attributes.categories || {}).slice(0, 3) })
    }
    return { items: out, hits: out.filter((x) => x.malicious > 0).length }
  },
}

// --- Link reputation (link scans only): the download URL itself on VirusTotal and urlscan.io ----------------
// VirusTotal: the URL's last analysis, or a fresh one when VT has never seen it. urlscan.io: an unlisted scan
// (not on its public feed) with the page's final address, IP, verdict and a screenshot.
const urlId = (u) => Buffer.from(u).toString('base64url')
async function vtUrl(u) {
  let r = await get(`/urls/${urlId(u)}`)
  let a = r?.data?.attributes
  if (!a?.last_analysis_stats || !Object.keys(a.last_analysis_results || {}).length) {
    const sub = await vt('/urls', { method: 'POST', body: new URLSearchParams({ url: u }) })
    const aid = sub?.data?.id
    if (aid) {
      await poll(async () => { const x = await vt(`/analyses/${aid}`); return x?.data?.attributes?.status === 'completed' ? true : null }, { every: 15_000, timeout: 4 * 60_000 }).catch(() => {})
      r = await get(`/urls/${urlId(u)}`)
      a = r?.data?.attributes
    }
  }
  if (!a) return null
  const st = a.last_analysis_stats || {}
  const total = (st.malicious || 0) + (st.suspicious || 0) + (st.undetected || 0) + (st.harmless || 0)
  return {
    ioc: u, type: 'url', source_name: 'VirusTotal', malicious: st.malicious || 0, suspicious: st.suspicious || 0, total,
    engines: Object.entries(a.last_analysis_results || {}).filter(([, x]) => ['malicious', 'suspicious'].includes(x.category)).map(([engine, x]) => ({ engine, result: x.result })).slice(0, 20),
    categories: Object.values(a.categories || {}).slice(0, 4), title: a.title || null, final_url: a.last_final_url || null,
    link: `https://www.virustotal.com/gui/url/${urlId(u)}`,
  }
}
async function urlscanUrl(u) {
  if (!process.env.URLSCAN_API_KEY) return null
  const h = { 'API-Key': process.env.URLSCAN_API_KEY }
  const sub = await http('https://urlscan.io/api/v1/scan/', { method: 'POST', headers: h, json: { url: u, visibility: 'unlisted', tags: ['clashgear'] } })
  const id = sub?.uuid
  if (!id) return null
  const res = await poll(async () => {
    try { return await http(`https://urlscan.io/api/v1/result/${id}/`, { headers: h }) } catch (e) { if (e.status === 404) return null; throw e }
  }, { every: 10_000, timeout: 3 * 60_000 }).catch(() => null)
  if (!res) return { ioc: u, type: 'url', source_name: 'urlscan.io', malicious: 0, pending: true, link: `https://urlscan.io/result/${id}/` }
  const v = res.verdicts?.overall || {}
  return {
    ioc: u, type: 'url', source_name: 'urlscan.io', malicious: v.malicious ? 1 : 0, score: v.score ?? null, categories: v.categories || [], brands: (v.brands || []).map((b) => b.name || b).slice(0, 5),
    final_url: res.page?.url || null, ip: res.page?.ip || null, country: res.page?.country || null, server: res.page?.server || null, domain_age_days: res.page?.apexDomainAgeDays ?? null,
    // direct file links render no page, so urlscan has no screenshot for them
    screenshot: /html/i.test(res.page?.mimeType || '') ? `https://urlscan.io/screenshots/${id}.png` : null, link: `https://urlscan.io/result/${id}/`,
  }
}
export const linkReputation = {
  id: 'link_rep', name: 'Link itibarı (VirusTotal · urlscan.io)', layer: 9, kind: 'file', env: ['VT_API_KEY'], needsSource: true,
  async run(ctx) {
    const src = ctx.source
    if (!src?.url) return null
    const urls = [...new Set([src.url, src.final_url].filter(Boolean))].slice(0, 2)
    const [vtItems, us] = await Promise.all([
      Promise.all(urls.map((u) => vtUrl(u).catch(() => null))),
      urlscanUrl(src.url).catch(() => null),
    ])
    const items = [...vtItems.filter(Boolean), ...(us ? [us] : [])]
    const vtBad = vtItems.filter(Boolean).reduce((m, x) => Math.max(m, x.malicious), 0)
    // One or two VT engines flag plenty of clean download sites: a URL counts as a network hit from three on.
    const hits = items.filter((x) => (x.source_name === 'VirusTotal' ? x.malicious >= 3 : x.malicious > 0)).length
    return {
      items, hits,
      verdict: vtBad >= 3 || us?.malicious ? 'malicious' : vtBad ? 'suspicious' : items.length ? 'clean' : 'unknown',
      score: vtBad >= 3 ? 70 : vtBad || us?.malicious ? 55 : null,
      screenshot: us?.screenshot || null,
    }
  },
}
