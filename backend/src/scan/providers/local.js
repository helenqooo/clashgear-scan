// Layer 5: our own static engines on the CAPE box (cg-static, reached through the SSH tunnel). YARA-Forge rules,
// capa capabilities with ATT&CK ids, FLOSS-decoded strings, Detect It Easy, ssdeep/TLSH, the stealer config
// extractor (PyInstaller/Nuitka/zlib streams, .NET and decoded strings), Office macros and Android packages.
// Nothing here is rate limited by an outside service, so it runs for every file, children included.

import { http, poll } from '../http.js'
import { TUNNEL_STATIC_PORT } from '../tunnel.js'
import { setJobFuzzy } from '../db.js'

const BASE = `http://127.0.0.1:${TUNNEL_STATIC_PORT}`
const auth = () => ({ Authorization: `Token ${process.env.CG_STATIC_TOKEN}` })

// Stealer families the extractor recognises, and YARA rules that name malware rather than a technique or a tool.
const OBFUSCATOR = /obfuscator/i
const YARA_FAMILY = /^(?:[A-Z]+_)*(?:MAL|MALWARE|CRIME|APT|RANSOM|STEALER|RAT|BACKDOOR|TROJAN)_/i
const YARA_NOT_FAMILY = /HKTL|HackTool|PUA|SUSP|Generic|Packer|Packed|Obfusc|Crypter|Loader_Generic|Anomaly|INDICATOR|CAPE_|Heuristic|Cheat/i

function familyFromYara(rule) {
  const r = String(rule.rule || '')
  if (!YARA_FAMILY.test(r) || YARA_NOT_FAMILY.test(r)) return null
  const score = Number(rule.meta?.score ?? 70)
  if (score < 70) return null
  const fam = rule.meta?.malware_family || rule.meta?.family || r.replace(YARA_FAMILY, '').replace(/_(Win|Win32|Win64|Linux|Android|MSIL)$/i, '').replace(/^(Win|Win32|Win64|MSIL)_/i, '').replace(/_/g, ' ')
  return { family: fam.trim(), rule: r, score }
}

/** Partially hides a webhook / bot token for viewers who are not the owner (the full one can delete or spam it). */
export function maskSecret(kind, v) {
  const s = String(v || '')
  if (kind === 'discord_webhook') return s.replace(/(webhooks\/\d+\/)([A-Za-z0-9_-]{6})[A-Za-z0-9_-]+/, '$1$2…')
  if (kind === 'telegram_bot') return s.replace(/^(\d+:)(.{4}).+$/, '$1$2…')
  if (kind === 'telegram_api') return s.replace(/(\/bot\d+:)(.{4})[^/]*/, '$1$2…')
  if (kind === 'discord_bot_token') return s.slice(0, 10) + '…'
  if (kind === 'ftp_creds') return s.replace(/\/\/([^:]+):[^@]+@/, '//$1:…@')
  return s
}

export const cgStatic = {
  id: 'cgstatic', name: 'ClashGear statik motorlar (YARA · capa · FLOSS · DIE)', layer: 5, kind: 'file', env: ['CG_STATIC_TOKEN', 'CAPE_TUNNEL'],
  async run(ctx) {
    if (ctx.size > 150 * 1024 * 1024) return { skipped: 'too_large' }
    const r0 = await http(`${BASE}/analyze/${ctx.sha256}`, {
      method: 'POST', headers: { ...auth(), 'X-Name': Buffer.from(ctx.name || '').toString('base64'), 'Content-Type': 'application/octet-stream' },
      body: ctx.file(), timeout: 180_000,
    })
    if (r0?.error) throw new Error(r0.error)
    const r = await poll(async () => {
      const x = await http(`${BASE}/result/${ctx.sha256}`, { headers: auth(), timeout: 30_000 }).catch((e) => (e.status === 404 ? { status: 'missing' } : Promise.reject(e)))
      if (x.status === 'running') return null
      if (x.status === 'error' || x.status === 'missing') throw new Error(x.error || 'static_failed')
      return x
    }, { every: 4000, timeout: 12 * 60_000 })

    setJobFuzzy(ctx.jobId, { tlsh: r.tlsh, ssdeep: r.ssdeep })

    const yaraFam = (r.yara || []).map(familyFromYara).filter(Boolean)
    const st = r.stealer || {}
    const stealerFam = (st.families || []).filter((f) => !OBFUSCATOR.test(f))
    const family = stealerFam[0] || yaraFam[0]?.family || null
    // Static evidence only: a recognised family is "genetics" (it needs another kind of evidence to call the file
    // malicious), a stealer config with an exfil channel and several target kinds is a strong hint.
    let verdict = 'unknown', score = null
    if (family || st.level === 'stealer') { verdict = 'malicious'; score = 75 }
    else if (st.level === 'likely') { verdict = 'suspicious'; score = 55 }
    const apk = r.apk && !r.apk.error ? r.apk : null
    if (apk && !family) {
      const bad = ['BIND_ACCESSIBILITY_SERVICE', 'BIND_DEVICE_ADMIN', 'SEND_SMS', 'READ_SMS', 'RECEIVE_SMS'].filter((p) => apk.dangerous?.includes(p))
      if (bad.length >= 2 && !score) { verdict = 'suspicious'; score = 45 }
    }
    const caps = r.capa?.capabilities || []
    return {
      verdict, score, family,
      kind: r.kind,
      seconds: r.seconds,
      fuzzy: { ssdeep: r.ssdeep || null, tlsh: r.tlsh || null },
      // Authenticode checked offline on the CAPE box (digest + chain to a trusted root); score.js reads summary.signature.
      signature: r.signature?.verified === 'Signed' ? { verified: 'Signed', signers: r.signature.signers, product: r.signature.product } : null,
      signature_check: r.signature || null,
      yara: (r.yara || []).filter((y) => y.rule !== '_timeout').map((y) => ({ rule: y.rule, score: y.meta?.score ?? null, description: y.meta?.description || '', author: y.meta?.author || '', family: familyFromYara(y)?.family || null })),
      die: r.die || [],
      capa: r.capa ? { status: r.capa.status, reason: r.capa.reason || null, count: caps.length, capabilities: caps, attack: r.capa.attack || {} } : null,
      floss: r.floss ? { status: r.floss.status, decoded: (r.floss.decoded || []).slice(0, 80), stack: (r.floss.stack || []).slice(0, 80), tight: (r.floss.tight || []).slice(0, 40) } : null,
      pyinstaller: r.pyinstaller || null,
      office: r.office || null,
      apk,
      stealer: { level: st.level || 'none', families: st.families || [], steal_categories: st.steal_categories || [], targets: st.targets || {}, exfil: st.exfil || [] },
      iocs: {
        urls: [...new Set([...(apk?.urls || []), ...(st.exfil || []).filter((e) => /^https?:/.test(e.value) && !/webhooks|\/bot\d/.test(e.value)).map((e) => e.value)])].slice(0, 20),
      },
      signatures: [
        ...yaraFam.map((y) => ({ name: `YARA: ${y.rule}`, severity: 3 })),
        ...(st.level === 'stealer' || st.level === 'likely' ? [{ name: `steals ${st.steal_categories.join(', ')} data`, severity: 3 }] : []),
      ],
    }
  },
}

/** TLSH/ssdeep neighbours of a job among every other stored file (comparison runs on cg-static). */
export async function similarTo({ tlsh, ssdeep }, items) {
  if (!process.env.CG_STATIC_TOKEN || (!tlsh && !ssdeep) || !items.length) return []
  const r = await http(`${BASE}/similar`, { method: 'POST', headers: auth(), json: { tlsh, ssdeep, items }, timeout: 60_000 })
  return r.hits || []
}

/** Rune's view into an APK: jadx output kept on cg-static for 2 h after the scan. */
export async function apkSearch(sha256, q) {
  return http(`${BASE}/apk/${sha256}/search?q=${encodeURIComponent(q)}`, { headers: auth(), timeout: 60_000 })
}
export async function apkSource(sha256, path) {
  return http(`${BASE}/apk/${sha256}/source?path=${encodeURIComponent(path)}`, { headers: auth(), timeout: 60_000 })
}
