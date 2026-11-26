// Layers 6, 7 and 10: unpacking, script emulation / deobfuscation, code-genetics.

import { http, formWith, poll, limit } from '../http.js'
import { getJob } from '../db.js'

const uniq = (a) => [...new Set(a.filter(Boolean))]

// --- UnpacMe: unpacks the sample; every unpacked child is scanned again as its own job ------------
const UNPAC = 'https://api.unpac.me/api/v1'
const up = (path, opts = {}) => http(`${UNPAC}${path}`, { ...opts, headers: { Authorization: `Key ${process.env.UNPACME_API_KEY}`, ...(opts.headers || {}) } })
export const unpacme = {
  id: 'unpacme', name: 'UnpacMe', layer: 6, kind: 'file', env: ['UNPACME_API_KEY'], rootOnly: true,
  async run(ctx) {
    // Only executables are worth unpacking; scripts and documents go to the emulators instead.
    if (!['pe', 'elf'].includes(ctx.type)) return { skipped: 'not_executable', children: [] }
    let id = ctx.ref
    if (!id) {
      // The free plan has ~100 public submissions a month: only files that look packed are worth one.
      const pe = getJob(ctx.jobId)?.static?.pe
      const packed = !!(pe?.packer_hints?.length || (pe?.sections || []).some((s) => s.entropy > 7.2 && s.exec !== false) || (pe?.sections || []).some((s) => /^(UPX\d|\.vmp\d|\.themida|\.enigma\d|\.aspack|\.petite|\.mpress\d)/i.test(s.name || '')))
      if (ctx.type === 'pe' && !packed) return { skipped: 'not_packed', children: [] }
      const acc = await up('/private/user/access').catch(() => null)
      const privateLeft = (acc?.month_limit_private || 0) - (acc?.month_submissions_private || 0)
      const left = (acc?.month_limit || 0) - (acc?.month_submissions || 0)
      if (!acc || (privateLeft <= 0 && left <= Number(process.env.UNPACME_RESERVE || 5))) return { skipped: 'quota', children: [] }
      await limit('unpacme', 5)
      // Private when the plan allows it; otherwise public (the upload page says files may be shared with researchers).
      const privacy = privateLeft > 0 ? 'private' : 'public'
      const r = await up('/private/upload', { method: 'POST', body: formWith({ privacy }, ctx.file(), 'file', ctx.name), timeout: 300_000 })
      id = r.id
      ctx.saveRef(id)
    }
    // Private submissions are read back through the private status/results endpoints (as in unpacme-go).
    await poll(async () => {
      const s = await up(`/private/status/${id}`)
      if (s.status === 'fail') throw new Error('unpack_failed')
      return s.status === 'complete' ? true : null
    }, { every: 20_000, timeout: 20 * 60_000 })
    const res = await up(`/private/results/${id}`)
    const results = res.results || []
    // 50 downloads a month on the free plan: the first three unpacked layers are enough
    const children = results.filter((x) => x.hashes?.sha256 && x.hashes.sha256 !== ctx.sha256).slice(0, 3)
    for (const c of children) {
      try {
        let buf = await up(`/private/download/${c.hashes.sha256}`, { raw: true, timeout: 120_000 })
        // free plans get downloads as a zip with the password "infected"
        if (buf[0] === 0x50 && buf[1] === 0x4b) buf = (await import('../extras.js')).unzipCrypto(buf, 'infected') || buf
        await ctx.addChild(buf, `${ctx.name}.unpacked.${c.hashes.sha256.slice(0, 8)}`)
      } catch { /* listed below even when the download is refused */ }
    }
    const fam = uniq(results.flatMap((x) => (x.malware_id || []).map((m) => m.name)))
    return {
      unpacked: children.length,
      children: children.map((c) => ({ sha256: c.hashes.sha256, malware: (c.malware_id || []).map((m) => m.name), type: c.file_type || null })),
      family: fam[0] || null,
      verdict: fam.length ? 'malicious' : children.length ? 'suspicious' : 'unknown',
      score: fam.length ? 85 : null,
      packers: uniq(results.flatMap((x) => (x.packer_id || x.classification || []).map?.((p) => p.name || p) || [])),
      link: `https://www.unpac.me/results/${id}`,
    }
  },
}

// --- Filescan.io: emulation-based analysis that unwraps obfuscated scripts and pulls IOCs --------
const FS = 'https://www.filescan.io/api'
const fsh = () => ({ 'X-Api-Key': process.env.FILESCAN_API_KEY })
const FS_VERDICT = { MALICIOUS: ['malicious', 90], LIKELY_MALICIOUS: ['malicious', 75], SUSPICIOUS: ['suspicious', 55], BENIGN: ['clean', null], NO_THREAT: ['clean', null], INFORMATIONAL: ['clean', null] }
export const filescan = {
  id: 'filescan', name: 'Filescan.io (emülasyon)', layer: 7, kind: 'file', env: ['FILESCAN_API_KEY'],
  async run(ctx) {
    let flow = ctx.ref
    if (!flow) {
      if (ctx.size > 100 * 1024 * 1024) return null
      const r = await http(`${FS}/scan/file`, { method: 'POST', headers: fsh(), body: formWith({ is_private: 'true' }, ctx.file(), 'file', ctx.name), timeout: 300_000 })
      flow = r.flow_id
      ctx.saveRef(flow)
    }
    const filters = ['general', 'finalVerdict', 'allTags', 'overallState', 'iocs', 'allSignalGroups', 'extractedFiles', 'emulationData', 'resources']
    const q = filters.map((f) => `filter=${f}`).join('&')
    const rep = await poll(async () => {
      const r = await http(`${FS}/scan/${flow}/report?${q}`, { headers: fsh() })
      return r.allFinished ? r : null
    }, { every: 15_000, timeout: 20 * 60_000 })
    const reports = Object.values(rep.reports || {})
    const main = reports[0] || {}
    const [verdict, score] = FS_VERDICT[main.finalVerdict?.verdict] || ['unknown', null]
    const iocs = reports.flatMap((r) => r.iocs || [])
    const byType = (t) => uniq(iocs.filter((i) => String(i.type).toLowerCase().includes(t)).map((i) => i.value)).slice(0, 30)
    // Deobfuscated script layers the emulator recovered, when the report carries them.
    const scripts = []
    for (const r of reports) {
      for (const e of r.emulationData || []) {
        const text = e.data?.content || e.content || e.script || e.deobfuscated
        if (typeof text === 'string' && text.trim()) scripts.push({ name: e.name || e.type || 'emulation', text: text.slice(0, 20000) })
      }
      for (const x of r.extractedFiles || []) {
        if (typeof x.content === 'string' && x.content.trim()) scripts.push({ name: x.name || 'extracted', text: x.content.slice(0, 20000) })
      }
    }
    return {
      verdict,
      score,
      threat_level: main.finalVerdict?.threatLevel ?? null,
      tags: uniq(reports.flatMap((r) => (r.allTags || []).map((t) => t.tag?.name || t.name))).slice(0, 30),
      signals: reports.flatMap((r) => r.allSignalGroups || []).filter((s) => s.verdict?.verdict && s.verdict.verdict !== 'INFORMATIONAL' && s.verdict.verdict !== 'BENIGN')
        .slice(0, 40).map((s) => ({ name: s.description, severity: s.verdict.verdict })),
      extracted_files: reports.flatMap((r) => r.extractedFiles || []).length,
      scripts,
      iocs: { ips: byType('ip'), domains: byType('domain'), urls: byType('url') },
      link: `https://www.filescan.io/uploads/${flow}/reports/${Object.keys(rep.reports || {})[0] || ''}/overview`,
    }
  },
}

// --- Intezer Analyze: genetic code reuse -> family -----------------------------------------------
const IZ = 'https://analyze.intezer.com/api/v2-0'
let izToken = null
async function iz(path, opts = {}) {
  if (!izToken || izToken.exp < Date.now()) {
    const t = await http(`${IZ}/get-access-token`, { method: 'POST', json: { api_key: process.env.INTEZER_API_KEY } })
    izToken = { v: t.result, exp: Date.now() + 9 * 60_000 }
  }
  return http(`${IZ}${path}`, { ...opts, headers: { Authorization: `Bearer ${izToken.v}`, ...(opts.headers || {}) } })
}
export const intezer = {
  id: 'intezer', name: 'Intezer Analyze', layer: 10, kind: 'file', env: ['INTEZER_API_KEY'],
  async run(ctx) {
    let url = ctx.ref
    if (!url) {
      try {
        url = (await iz('/analyze-by-hash', { method: 'POST', json: { hash: ctx.sha256 } })).result_url
      } catch (e) {
        if (e.status !== 404) throw e
        if (ctx.size > 100 * 1024 * 1024) return null
        url = (await iz('/analyze', { method: 'POST', body: formWith({}, ctx.file(), 'file', ctx.name), timeout: 300_000 })).result_url
      }
      ctx.saveRef(url)
    }
    const r = await poll(async () => {
      const x = await iz(url)
      if (x.status === 'failed') throw new Error('intezer_failed')
      return x.status === 'succeeded' ? x.result : null
    }, { every: 15_000, timeout: 20 * 60_000 })
    const v = r.verdict
    return {
      verdict: v === 'malicious' ? 'malicious' : v === 'suspicious' ? 'suspicious' : v === 'trusted' ? 'clean' : 'unknown',
      score: v === 'malicious' ? 90 : v === 'suspicious' ? 55 : null,
      known_good: v === 'trusted' || undefined,
      family: r.family_name || null,
      sub_verdict: r.sub_verdict,
      link: r.analysis_url || null,
    }
  },
}
