// The verdict shown on the report is computed here, from numbers the services returned. The AI
// writes commentary next to it but can never change it.
//
// False-flag rules (2026-11-05): sources are grouped by the kind of evidence they give, and a file is
// only called malicious when two independent groups agree or one source brings hard proof (a known
// sample, a recognised family, an extracted config, a strong named AV consensus). Generic machine-
// learning detections weigh less than named ones, and hack tools / PUA get their own verdict.

// Behaviour first (owner, 2026-11-05): packing, encryption and obfuscation say how a file is wrapped,
// not what it does. Cheats and licensed software are VMProtect/Themida'd as a rule, so those hints are
// shown on the report but carry no weight; the verdict comes from what the file was seen doing, from
// recognised families, and from what it dropped or downloaded.
function staticScore(st) {
  const pe = st?.pe
  if (!pe) return 0
  let s = Math.min(15, (pe.suspicious_apis?.length || 0) * 1.5)
  if (st.indicators?.keywords?.length > 3) s += 5
  return Math.min(20, Math.round(s))
}

// Behaviour seen in a sandbox, by what it means. "high" ones are what malware is for.
const BEHAVIOUR = [
  { id: 'credential_theft', high: true, re: /\bsteal(s|ing)?\b|\bcredentials?\b|saved password|browser (data|cookies|history|password)|login data|crypto(currency)? wallet|wallet file|discord token|telegram (session|data)|keylog|clipboard (monitor|hijack|swap)|harvest/i },
  { id: 'ransomware', high: true, re: /ransom|encrypt(s|ing)? (user |multiple |many )?files|shadow cop|vssadmin|wbadmin|bcdedit|ransom note/i },
  { id: 'injection', high: true, re: /inject|process hollow|hollowing|remote thread|memory of (another|a remote|other) process|queueuserapc|apc injection|setwindowshookex/i },
  { id: 'persistence', re: /persist|autorun|run key|startup folder|scheduled task|schtasks|creates? (a )?(new )?service|installs? (itself|a service)|winlogon|image file execution|wmi (event|subscription)/i },
  { id: 'defense_evasion', re: /disables? (windows defender|defender|anti-?virus|firewall|uac|security center|tamper)|defender exclusion|adds? .*exclusion|stops? (security|anti-?virus) (service|product)|kills? (security|anti-?virus)/i },
  { id: 'c2', re: /\bc2\b|command.and.control|beacon|known (malicious|bad) (ip|domain|host)|\birc\b|\btor\b|\.onion|dynamic dns|suspicious (dns|tls|domain)/i },
  { id: 'download_execute', re: /downloads? (and )?(execut|runs?)|drops? (and execut|a binary|an executable)|execut(es|ed) (a )?dropped|loads? (a |an )?(encrypted |remote )?payload|fileless|reflective(ly)? load/i },
]
// Analysis-environment checks, hedged guesses ("API typically used for keylogging" is every cheat's
// hotkey handler) and allocation details: interesting, never evidence on their own.
const BEHAVIOUR_IGNORE = /anti-?debug|anti-?vm|anti-?sandbox|virtual(i[sz]ation| machine)|sandbox|debugger|timing|sleep|packer|packed|entropy|obfuscat|dead ip|locale|language|computer name|user name|typically|likely|possibl|may be|might|potential|can be used|could be|legitimate|\brwx\b|_rwx|suspended (mode|state)|stealth/i
// Signature words that say nothing about a target ("tries to steal putty sessions" only counts when
// the file is not PuTTY itself).
const STOP = new Set(['tries', 'steal', 'sessions', 'session', 'from', 'registry', 'files', 'file', 'data', 'with', 'that', 'this', 'into', 'process', 'windows', 'browser', 'information', 'private', 'local', 'internet', 'creates', 'installs', 'itself', 'drops', 'binary', 'executes', 'queries', 'reads', 'writes'])
const selfRef = (sig, fileName) => {
  const own = String(fileName || '').toLowerCase()
  return String(sig).toLowerCase().split(/[^a-z0-9]+/).some((w) => w.length >= 4 && !STOP.has(w) && own.includes(w))
}
// Only sandboxes that ran the file themselves and describe what they saw. VirusTotal's sandbox list is a
// terse aggregate of many vendors (it tags calc.exe "infostealer_cookies"), so it scores but never proves.
const BEHAVIOUR_SOURCES = new Set(['cape', 'hybrid_sandbox', 'triage', 'threatzone', 'joe', 'anyrun', 'vmray'])
function behaviourOf(results, fileName) {
  const hit = new Map()
  for (const r of results) {
    if (!BEHAVIOUR_SOURCES.has(r.source)) continue
    for (const sig of r.summary.signatures || []) {
      const name = String(sig.name || sig.description || '')
      if (!name || sig.noise || BEHAVIOUR_IGNORE.test(name) || selfRef(name, fileName)) continue
      const b = BEHAVIOUR.find((x) => x.re.test(name))
      if (!b) continue
      const h = hit.get(b.id) || { id: b.id, high: !!b.high, sources: new Set(), examples: [] }
      h.sources.add(r.source)
      if (h.examples.length < 2) h.examples.push(name.slice(0, 120))
      hit.set(b.id, h)
    }
  }
  // Our CAPE's per-process activity (API calls + Sysmon): concrete persistence and injection.
  const note = (id, high, source, example) => {
    const h = hit.get(id) || { id, high, sources: new Set(), examples: [] }
    h.sources.add(source)
    if (h.examples.length < 2) h.examples.push(example.slice(0, 120))
    hit.set(id, h)
  }
  for (const r of results) {
    for (const p of r.summary?.activity?.processes || []) {
      if (ACTIVITY_SKIP.test(p.name || '')) continue
      for (const w of p.registry?.written || []) if (AUTORUN_KEY.test(w.key)) note('persistence', false, r.source, `${p.name}: ${w.key}`)
      for (const f of p.files?.written || []) if (/\\Start Menu\\Programs\\Startup\\/i.test(f)) note('persistence', false, r.source, `${p.name}: ${f}`)
      if ((p.flags || []).some((f) => f === 'remote_thread' || f === 'wrote_other_process' || f === 'tampering')) note('injection', true, r.source, `${p.name}: başka bir sürece kod/thread`)
    }
  }
  return [...hit.values()].map((h) => ({ ...h, sources: [...h.sources] }))
}
const AUTORUN_KEY = /\\CurrentVersion\\(Run|RunOnce|RunServices|Policies\\Explorer\\Run)\\|\\Winlogon\\(Shell|Userinit)|\\Services\\[^\\]+\\(ImagePath|Start)$|\\Image File Execution Options\\[^\\]+\\Debugger/i
// The desktop shell in a live session (that's the user clicking) and Windows' own background services.
const ACTIVITY_SKIP = /^(explorer|svchost|dllhost|wmiprvse|wmiadap|tiworker|trustedinstaller|slui|sppsvc|searchindexer|searchprotocolhost|wuauclt|taskhostw|runtimebroker|msmpeng|consent|werfault|services|lsass|csrss|winlogon)\.exe$/i

const cleanFamily = (f) => String(f || '').trim()
const famKey = (f) => cleanFamily(f).toLowerCase().replace(/^(trojan|win32|win64|msil|backdoor|malware)[/:.]/g, '').replace(/[^a-z0-9]+/g, '')

// Sources that only say "this hash was seen at a bad URL", not "this file is bad". Attackers often
// host legitimate binaries (calc.exe as a test payload), so on their own they become a warning.
const SIGHTING_ONLY = new Set(['urlhaus'])

// Detection names. PUA: tools people install on purpose (cheats, cracks, hack tools). GENERIC: verdicts
// from ML/heuristics/reputation that name no family. MALWARE: names of real malware behaviour, which
// keep a file out of the PUA bucket.
const PUA_RE = /hack ?tool|hktl|riskware|risk ?tool|\bpua\b|\bpup\b|potentially|unwanted|unwnt|not-a-virus|game ?hack|\bcheat|\bcrack|keygen|patcher|grayware|greyware|adware|remoteadmin|\btool\b|program:|applicunwnt|\bhacktool/i
const GENERIC_RE = /generic|heur|\bml\b|ml\.|static ai|malicious \(|confidence|\bunsafe\b|w32\.malware\.|^malicious$|^suspicious|suspicious\.|behaveslike|real ?protect|save\.a|artemis|wacatac|\bscore\b|\bai\b|cloud|susgen|reputation|\bgen\b|gen:|\.gen\b|attribute|highconfidence|probably|lowfi|\bsuspect\b|variant|abapplication|\bagent\b|^trojan\.?$/i
const MALWARE_RE = /stealer|\brat\b|backdoor|ransom|coinminer|\bminer\b|spyware|banker|keylog|downloader|dropper|botnet|\bworm\b|rootkit|redline|lumma|vidar|raccoon|asyncrat|njrat|remcos|agenttesla|formbook|xworm|quasar|dcrat|amadey|smokeloader|stealc|risepro|meduza/i
// PACKER: names that only describe the wrapping (Packed.VMProtect, Obfuscator, Krypt…).
const PACKER_RE = /pack(ed|er)\b|packed\.|vmprotect|\bvmp\b|themida|winlicense|obfusc|confuser|enigma|\bupx\b|protector|smartassembly|dotfuscator|eazfuscator|\bkrypt|crypted|\bcryptor/i
const kindOf = (name) => (MALWARE_RE.test(name) ? 'malware' : PACKER_RE.test(name) ? 'packer' : PUA_RE.test(name) ? 'pua' : GENERIC_RE.test(name) ? 'generic' : 'named')

// Publishers whose valid signature makes weak signals moot (a stolen cert still needs other proof).
const TRUSTED_SIGNER = /microsoft|google|valve|riot games|epic games|discord|mozilla|adobe|nvidia|intel corporation|advanced micro devices|logitech|razer|oracle|jetbrains|apple inc|spotify|zoom video|electronic arts|ubisoft|blizzard|activision|steelseries|corsair|cloudflare|github|obs project/i

const groupOf = (r) => {
  if (r.source === 'hybrid_lookup') return 'dynamic' // Hybrid Analysis's verdict comes from its own sandbox runs
  // Our static engines: a recognised family (YARA family rule / stealer markers) is code genetics, the rest is static.
  if (r.source === 'cgstatic') return r.summary?.family ? 'genetics' : 'static'
  if (r.layer === 3) return 'av'
  if (r.layer === 4) return 'intel'
  if (r.layer === 5) return 'static'
  if (r.layer >= 6 && r.layer <= 8) return 'dynamic'
  if (r.layer === 9) return 'network'
  if (r.layer === 10) return 'genetics'
  return 'other'
}
// Groups whose agreement counts toward "two independent kinds of evidence". Static hints never do.
const EVIDENCE = new Set(['av', 'intel', 'dynamic', 'genetics', 'network'])

/** AV score: generic detections count 40 %, PUA names 50 %, packer-only names nothing. */
function avScore(s) {
  const dets = s.detections || []
  if (!dets.length || !s.total) return { score: s.score, named: 0, generic: 0, pua: 0, malware: 0, packer: 0 }
  const n = { named: 0, generic: 0, pua: 0, malware: 0, packer: 0 }
  for (const d of dets) n[kindOf(String(d.result || ''))]++
  const weighted = n.named + n.malware + 0.4 * n.generic + 0.5 * n.pua
  return { score: Math.min(100, Math.round((weighted / s.total) * 220)), ...n }
}

/**
 * @param results scan_results rows of one job
 * @param st      the job's static facts
 * @param opts    { override } — an owner-confirmed verdict for this sha256 ({ verdict, note });
 *                { aiVerdict } — Nyx + Rune's verdict for it ({ verdict, score, reason })
 */
export function computeScore(results, st, opts = {}) {
  const done = results.filter((r) => r.status === 'done' && r.summary)
  const files = done.filter((r) => r.layer !== 9)
  const reasons = []

  // AV consensus clean: many engines looked and (almost) none flagged it.
  const av = files.filter((r) => typeof r.summary.total === 'number' && r.summary.total > 0)
  const engines = av.reduce((n, r) => n + r.summary.total, 0)
  const detected = av.reduce((n, r) => n + (r.summary.malicious || 0), 0)
  const avClean = engines >= 20 && detected <= 1
  const signer = files.map((r) => r.summary.signature).find((s) => s?.verified === 'Signed')
  const trusted = files.some((r) => r.summary.known_good || (r.summary.tags || []).includes('known-distributor')) || !!signer
  const trustedSigner = !!signer && TRUSTED_SIGNER.test(String(signer.signers || signer.product || ''))
  const demote = (r) => SIGHTING_ONLY.has(r.source) && (avClean || trusted)
  const warnings = files.filter((r) => demote(r) && r.summary.verdict === 'malicious')
    .map((r) => ({ kind: 'seen_on_malicious_host', source: r.source, urls: (r.summary.urls || []).slice(0, 5).map((u) => u.url || u) }))

  // Detection-name mix across the AV engines.
  const mix = { named: 0, generic: 0, pua: 0, malware: 0, packer: 0 }
  const signals = []
  for (const r of files) {
    if (typeof r.summary.score !== 'number' || demote(r)) continue
    let score = r.summary.score
    if (groupOf(r) === 'av' && r.summary.detections) {
      const a = avScore(r.summary)
      for (const k of Object.keys(mix)) mix[k] += a[k]
      score = a.score ?? score
    }
    signals.push({ source: r.source, group: groupOf(r), score })
  }
  // Layer 9: contacted hosts on blocklists form the network group.
  const iocHits = done.filter((r) => r.layer === 9).reduce((n, r) => n + (r.summary.hits || 0), 0)
  if (iocHits) signals.push({ source: 'network', group: 'network', score: Math.min(75, 50 + iocHits * 5) })
  // What the sandboxes saw it do, by meaning (credential theft, injection, persistence…).
  // A program touching its own data is not theft, also when the program is a child this file fetched.
  const behaviour = behaviourOf(files, [opts.fileName, ...(opts.children || []).map((c) => c.file_name)].join(' '))
  // With a clean AV consensus one sandbox's word is weaker: it needs a second sandbox to agree.
  const behaviourSources = new Set(behaviour.flatMap((b) => b.sources))
  const corroborated = !avClean || behaviourSources.size >= 2
  if (behaviour.length) signals.push({ source: 'behaviour', group: 'dynamic', score: (behaviour.length >= 2 ? 75 : 50) - (corroborated ? 0 : 20) })

  const groups = {}
  for (const s of signals) {
    const g = (groups[s.group] ||= { group: s.group, score: 0, sources: [] })
    g.score = Math.max(g.score, s.score)
    g.sources.push({ source: s.source, score: s.score })
  }
  const strongest = signals.reduce((m, s) => Math.max(m, s.score), 0)
  const agreeing = Object.values(groups).filter((g) => EVIDENCE.has(g.group) && g.score >= 60)

  // Hard proof: one source is enough.
  const proofs = []
  for (const r of files) {
    const s = r.summary
    if (demote(r)) continue
    if (['malwarebazaar', 'threatfox'].includes(r.source) && (s.score ?? 0) >= 80) proofs.push({ source: r.source, detail: s.family || s.signature_name || 'known sample' })
    else if (['unpacme', 'intezer'].includes(r.source) && (s.score ?? 0) >= 85 && s.family) proofs.push({ source: r.source, detail: s.family })
    else if (groupOf(r) === 'dynamic' && s.configs?.length) proofs.push({ source: r.source, detail: `config: ${s.configs[0].family || ''}`.trim() })
  }
  if ((groups.av?.score ?? 0) >= 85 && mix.named + mix.malware >= 8) proofs.push({ source: 'av', detail: `${mix.named + mix.malware} named detections` })
  // Doing what malware is for (stealing, injecting, encrypting) plus one more malicious behaviour.
  if (corroborated && behaviour.some((b) => b.high) && behaviour.length >= 2) proofs.push({ source: behaviour.find((b) => b.high).sources[0], detail: behaviour.map((b) => b.id).join(', ') })
  // A loader is what it loads: a malicious file it dropped, downloaded or unpacked makes it malicious.
  const badKid = (opts.children || []).find((c) => c.verdict === 'malicious')
  if (badKid) proofs.push({ source: 'child', detail: badKid.file_name })
  // Token Tuzağı: the file took our fake accounts (zipped them, sent them, swapped the clipboard, opened three kinds,
  // or someone later tried the stolen trap login). That is what a stealer does, so it is proof on its own.
  const honey = files.find((r) => r.source === 'honey')?.summary?.honey
  if (honey?.proof) proofs.unshift({ source: 'honey', detail: honey.headline || '' })
  const proof = proofs.length > 0

  let score
  if (proof) {
    score = Math.max(strongest, 85)
    const p = proofs[0]
    reasons.push(p.source === 'child' ? { code: 'child_malicious', tone: 'bad', detail: p.detail } : { code: 'proof', tone: 'bad', source: p.source, detail: p.detail })
  } else if (agreeing.length >= 2) {
    score = strongest + (agreeing.length >= 3 ? 5 : 0)
    // The file ran in a sandbox and did nothing malicious there: scores alone stay "suspicious".
    if (groups.dynamic && !behaviour.length && !honey?.reads?.length) score = Math.min(score, 69)
    reasons.push({ code: 'groups_agree', tone: score >= 70 ? 'bad' : 'warn', groups: agreeing.map((g) => g.group) })
  } else {
    score = Math.min(strongest, 60)
    if (strongest > 60) reasons.push({ code: 'single_group', tone: 'warn', groups: agreeing.map((g) => g.group), source: signals.find((s) => s.score === strongest)?.source })
  }
  if (mix.generic && mix.generic >= mix.named + mix.malware) reasons.push({ code: 'generic_av', tone: 'info', generic: mix.generic, named: mix.named + mix.malware })
  if (behaviour.length) reasons.push({ code: 'behaviour', tone: proof ? 'bad' : 'warn', items: behaviour.map((b) => b.id), detail: behaviour.flatMap((b) => b.examples).slice(0, 3).join(' · ') })
  else if (groups.dynamic?.sources.some((x) => x.source !== 'honey')) reasons.push({ code: 'no_behaviour', tone: 'info' })
  if (mix.packer) reasons.push({ code: 'packer_only', tone: 'info', n: mix.packer })
  if (honey?.used?.length) reasons.push({ code: 'honey_used', tone: 'bad', n: honey.used.length })
  if (honey && !honey.proof) reasons.push(honey.reads?.length ? { code: 'honey_read', tone: 'warn', detail: honey.headline || '' } : { code: 'honey_clean', tone: 'info' })
  const puaKid = !badKid && (opts.children || []).find((c) => c.verdict === 'pua')
  if (puaKid) reasons.push({ code: 'child_pua', tone: 'warn', detail: puaKid.file_name })

  const st0 = staticScore(st)
  if (st0 > score) { score = st0; if (st0 >= 35) reasons.push({ code: 'static_only', tone: 'warn' }) }

  const knownGood = files.some((r) => r.summary.known_good)
  if (knownGood && !proof && strongest < 70) { score = Math.min(score, 5); reasons.push({ code: 'known_good', tone: 'good' }) }
  // A clean AV consensus on a file from a known publisher keeps weak static hints from tipping it.
  if (avClean && trusted && !proof && strongest < 70) score = Math.min(score, 15)
  if (trustedSigner && !proof) { score = Math.min(score, 15); reasons.push({ code: 'trusted_signer', tone: 'good', signer: String(signer.signers || signer.product || '').split(';')[0].trim() }) }
  score = Math.max(0, Math.min(100, Math.round(score)))

  // Hack tools, cheats, cracks: most named detections say so and none name real malware.
  const named = mix.named + mix.generic + mix.pua + mix.malware
  const pua = !proof && mix.pua >= 2 && mix.pua >= 0.4 * named && mix.malware < 2

  const anyClean = files.some((r) => r.summary.verdict === 'clean')
  let verdict = score >= 70 ? 'malicious' : score >= 35 ? 'suspicious' : knownGood || anyClean ? 'clean' : 'unknown'
  if (pua && score >= 35) { verdict = 'pua'; reasons.unshift({ code: 'pua', tone: 'warn', n: mix.pua }) }

  // Nyx + Rune's verdict after reading the code. It may raise the score freely; lowering it to pua/clean is
  // refused when a source brought hard proof. An owner override below still wins.
  const ai = opts.aiVerdict
  if (ai?.verdict && !(proof && ai.verdict !== 'malicious')) {
    const band = { malicious: [70, 100], pua: [35, 69], clean: [0, 20] }[ai.verdict]
    if (band) {
      const before = score
      score = Math.max(band[0], Math.min(band[1], Math.round(Number(ai.score) || band[0])))
      verdict = ai.verdict
      reasons.unshift({ code: 'ai_verdict', tone: ai.verdict === 'malicious' ? 'bad' : ai.verdict === 'pua' ? 'warn' : 'good', verdict, before, note: ai.reason || '' })
    }
  } else if (ai?.verdict) reasons.push({ code: 'ai_verdict_refused', tone: 'info', verdict: ai.verdict })

  // Owner-confirmed false positive (or reclassification) for this exact file.
  if (opts.override?.verdict) {
    verdict = opts.override.verdict
    if (verdict === 'clean') score = Math.min(score, 5)
    reasons.unshift({ code: 'override', tone: 'good', verdict, note: opts.override.note || '' })
  }

  // Family: the name most sources agree on, among those that call it bad.
  const votes = new Map()
  for (const r of files) {
    const f = r.summary.family
    if (!f || r.summary.verdict === 'clean' || demote(r) || PACKER_RE.test(f)) continue
    const k = famKey(f)
    if (k.length < 3) continue
    const v = votes.get(k) || { name: cleanFamily(f), n: 0 }
    v.n++
    votes.set(k, v)
  }
  const family = verdict === 'clean' ? null : [...votes.values()].sort((a, b) => b.n - a.n)[0]?.name || null

  return {
    score, verdict, family, known_good: knownGood, agreeing: agreeing.length, signals, ioc_hits: iocHits, engines, detected, warnings,
    groups: Object.values(groups).sort((a, b) => b.score - a.score), detection_mix: mix, proofs, reasons, behaviour,
  }
}
