// Layer 8: the file runs in someone else's VMs (never on this server). Each provider first looks for
// an existing report of the same hash, and only submits when there is none.

import { http, formWith, urlForm, poll, limit } from '../http.js'
import { haHeaders, haSearch } from './intel.js'
import { TUNNEL_FILES_PORT } from '../tunnel.js'

const nf = async (fn) => { try { return await fn() } catch (e) { if (e.status === 404) return null; throw e } }
const uniq = (a) => [...new Set(a.filter(Boolean))]
const MAX_SUBMIT = 100 * 1024 * 1024

// --- Recorded Future Triage (tria.ge) ---------------------------------------------------------------
const TRIAGE = () => (process.env.TRIAGE_URL || 'https://tria.ge/api/v0').replace(/\/+$/, '')
const tg = (path, opts = {}) => http(`${TRIAGE()}${path}`, { ...opts, headers: { Authorization: `Bearer ${process.env.TRIAGE_API_KEY}`, ...(opts.headers || {}) } })

export const triage = {
  id: 'triage', name: 'Triage (Recorded Future)', layer: 8, kind: 'file', env: ['TRIAGE_API_KEY'],
  async run(ctx) {
    let id = ctx.ref
    if (!id) {
      const found = await tg(`/search?query=${encodeURIComponent(`sha256:${ctx.sha256}`)}`)
      id = (found.data || []).find((s) => s.status === 'reported')?.id
      if (!id) {
        if (ctx.size > MAX_SUBMIT) return null
        const up = await tg('/samples', { method: 'POST', body: formWith({ _json: { kind: 'file', interactive: false } }, ctx.file(), 'file', ctx.name), timeout: 300_000 })
        id = up.id
      }
      ctx.saveRef(id)
    }
    await poll(async () => {
      const s = await tg(`/samples/${id}`)
      if (s.status === 'failed') throw new Error('triage_failed')
      return s.status === 'reported' ? true : null
    }, { every: 30_000, timeout: 30 * 60_000 })
    const o = await tg(`/samples/${id}/overview.json`)
    const t = o.targets?.[0] || {}
    const score = o.analysis?.score ?? o.sample?.score ?? t.score ?? 0
    const configs = (o.extracted || []).filter((e) => e.config).map((e) => ({ source: 'Triage', ...e.config }))
    const dumped = (o.extracted || []).filter((e) => e.dumped_file || e.dropper).length
    return {
      score: score * 10,
      verdict: score >= 8 ? 'malicious' : score >= 5 ? 'suspicious' : score >= 1 ? 'clean' : 'unknown',
      family: o.analysis?.family?.[0] || t.family?.[0] || null,
      tags: uniq([...(o.analysis?.tags || []), ...(t.tags || [])]).slice(0, 30),
      signatures: (o.signatures || t.signatures || []).slice(0, 40).map((s) => ({ name: s.name || s.label, score: s.score, ttp: s.ttp })),
      attack: uniq((o.signatures || []).flatMap((s) => s.ttp || [])).map((id) => ({ id })),
      environments: uniq((o.tasks || []).map((x) => x.os || x.name)),
      configs,
      dumped_files: dumped,
      iocs: { ips: uniq(t.iocs?.ips || []), domains: uniq(t.iocs?.domains || []), urls: uniq(t.iocs?.urls || []) },
      link: `https://tria.ge/${id}`,
    }
  },
}

// --- Hybrid Analysis / CrowdStrike Falcon Sandbox ------------------------------------------------------
// The www host now 301s to the bare domain, which turns a POST into a GET; call the bare host directly.
const HA = 'https://hybrid-analysis.com/api/v2'

// The sandbox OS has to match the file (a Windows VM rejects ELF, Mach-O or an extensionless text file),
// and Falcon picks the runner from the file extension, so a missing one is added. HYBRID_ANALYSIS_ENV
// still overrides the Windows choice. Types come from static.js detectType.
const HA_WIN = () => process.env.HYBRID_ANALYSIS_ENV || '160' // Windows 10 64 bit
const HA_TARGET = {
  pe: { env: HA_WIN, ext: ['exe', 'dll', 'scr', 'sys', 'cpl', 'ocx', 'com'], add: 'exe' },
  pdf: { env: HA_WIN, ext: ['pdf'], add: 'pdf' },
  ole: { env: HA_WIN, ext: ['doc', 'xls', 'ppt', 'msi', 'msg'], add: 'doc' },
  docx: { env: HA_WIN, ext: ['docx', 'docm', 'dotm'], add: 'docx' },
  xlsx: { env: HA_WIN, ext: ['xlsx', 'xlsm', 'xlsb'], add: 'xlsx' },
  pptx: { env: HA_WIN, ext: ['pptx', 'pptm'], add: 'pptx' },
  rtf: { env: HA_WIN, ext: ['rtf'], add: 'rtf' },
  lnk: { env: HA_WIN, ext: ['lnk'], add: 'lnk' },
  zip: { env: HA_WIN, ext: ['zip'], add: 'zip' },
  rar: { env: HA_WIN, ext: ['rar'], add: 'rar' },
  '7z': { env: HA_WIN, ext: ['7z'], add: '7z' },
  jar: { env: HA_WIN, ext: ['jar'], add: 'jar' },
  powershell: { env: HA_WIN, ext: ['ps1', 'psm1'], add: 'ps1' },
  javascript: { env: HA_WIN, ext: ['js', 'jse'], add: 'js' },
  vbscript: { env: HA_WIN, ext: ['vbs', 'vbe'], add: 'vbs' },
  batch: { env: HA_WIN, ext: ['bat', 'cmd'], add: 'bat' },
  hta: { env: HA_WIN, ext: ['hta'], add: 'hta' },
  wsf: { env: HA_WIN, ext: ['wsf'], add: 'wsf' },
  elf: { env: () => '330', ext: [], add: null }, // Linux (Ubuntu 24.04, 64 bit)
  shell: { env: () => '330', ext: ['sh'], add: 'sh' },
  python: { env: () => '330', ext: ['py'], add: 'py' },
  macho: { env: () => '430', ext: [], add: null }, // macOS (ARM64)
  'macho-fat': { env: () => '430', ext: [], add: null },
  apk: { env: () => '200', ext: ['apk'], add: 'apk' }, // Android static analysis
  dex: { env: () => '200', ext: ['dex'], add: 'dex' },
}
/** { environment_id, submit_name } for the file, or null when no sandbox OS can run it (plain text, unknown). */
function haTarget(type, name) {
  const t = HA_TARGET[type]
  if (!t) return null
  const ext = (/\.([a-z0-9]{1,5})$/i.exec(name)?.[1] || '').toLowerCase()
  const submit = t.add && !t.ext.includes(ext) ? `${name}.${t.add}` : name
  return { environment_id: t.env(), submit_name: submit }
}

export const hybridSandbox = {
  id: 'hybrid_sandbox', name: 'CrowdStrike Falcon Sandbox (Hybrid Analysis)', layer: 8, kind: 'file', env: ['HYBRID_ANALYSIS_API_KEY'],
  async run(ctx) {
    let job = ctx.ref
    if (!job) {
      // search/hash now returns { sha256s, reports: [{ id, state, ... }] }; older answers used job_id.
      const existing = (await haSearch(ctx.sha256)).find((r) => (r.id || r.job_id) && r.state !== 'ERROR')
      job = existing?.id || existing?.job_id
      if (!job) {
        if (ctx.size > MAX_SUBMIT) return null
        const target = haTarget(ctx.type, ctx.name)
        if (!target) return { skipped: 'not_runnable', verdict: 'unknown', score: null, note: `no sandbox OS runs "${ctx.type}" files` }
        const up = await http(`${HA}/submit/file`, { method: 'POST', headers: haHeaders(), body: formWith(target, ctx.file(), 'file', target.submit_name), timeout: 300_000 })
        job = up.job_id || up.id
      }
      ctx.saveRef(job)
    }
    await poll(async () => {
      const s = await http(`${HA}/report/${job}/state`, { headers: haHeaders() })
      if (s.state === 'ERROR') throw new Error(s.error || 'ha_failed')
      return s.state === 'SUCCESS' ? true : null
    }, { every: 30_000, timeout: 30 * 60_000 })
    const r = await http(`${HA}/report/${job}/summary`, { headers: haHeaders() })
    return {
      score: r.threat_score ?? null,
      verdict: r.verdict === 'malicious' ? 'malicious' : r.verdict === 'suspicious' ? 'suspicious' : r.verdict === 'no specific threat' ? 'clean' : 'unknown',
      family: r.vx_family || null,
      environment: r.environment_description,
      tags: uniq([...(r.tags || []), ...(r.classification_tags || [])]),
      signatures: (r.signatures || []).filter((s) => s.threat_level >= 1).slice(0, 40).map((s) => ({ name: s.name, severity: s.threat_level_human, category: s.category })),
      attack: (r.mitre_attcks || []).map((m) => ({ id: m.attck_id, name: m.technique, tactic: m.tactic })),
      processes: (r.processes || []).slice(0, 30).map((p) => ({ name: p.name, command_line: p.command_line, pid: p.pid })),
      extracted_files: (r.extracted_files || []).slice(0, 20).map((f) => ({ name: f.name, sha256: f.sha256, threat_level: f.threat_level_readable })),
      iocs: { ips: uniq(r.hosts || []), domains: uniq(r.domains || []), urls: [] },
      link: `https://www.hybrid-analysis.com/sample/${ctx.sha256}`,
    }
  },
}

// --- CAPE Sandbox (our own instance when CAPE_URL is set, else the public one; also extracts payloads
// and malware configs). Our instance sits behind a firewall, so its web links are never handed out.
const CAPE = () => (process.env.CAPE_URL || 'https://capesandbox.com/apiv2').replace(/\/+$/, '')
const OWN_CAPE = () => !!process.env.CAPE_URL
export const CAPE_RUN_OPTIONS = 'curdir=%USERPROFILE%\\Desktop'
// Signatures nearly every Windows program trips; shown on the report but never scored.
const CAPE_NOISE = /dead IP|computer locale|system language|SetUnhandledExceptionFilter|adapter addresses|date expiration check|process token information|computer name|user name|reads data out of its own binary|enumerates running processes|Windows utilities for basic|installed applications|terminates? (itself|due to)|stack pivot|creates RWX memory|checks? (for )?(the )?(presence|amount) of (memory|physical)|Possible date/i
const cape = (path, opts = {}) => http(`${CAPE()}${path}`, { ...opts, headers: { Authorization: `Token ${process.env.CAPE_API_KEY}`, ...(opts.headers || {}) } })
/** Tasks waiting in our CAPE queue (null when CAPE cannot be asked). */
export async function capeQueue() {
  try {
    const r = await cape('/cuckoo/status/', { timeout: 15_000 })
    const t = r?.data?.tasks || r?.tasks || {}
    return { pending: Number(t.pending || 0), running: Number(t.running || 0) }
  } catch { return null }
}

export const capeSandbox = {
  // rootOnly: the files it hands back as children were already seen running inside this detonation,
  // and our one VM should not spend its queue re-running each of them.
  // manual: our own VM is not used for every upload, only when the user starts a live session
  // (jobs.js attachLiveRun feeds that session's report in here through ctx.ref).
  id: 'cape', layer: 8, kind: 'file', env: ['CAPE_API_KEY'], rootOnly: true, get manual() { return OWN_CAPE() },
  get name() { return OWN_CAPE() ? 'ClashGear Sandbox (CAPE)' : 'CAPE Sandbox' },
  async run(ctx) {
    let id = ctx.ref
    if (!id) {
      const found = await nf(() => cape(`/tasks/search/sha256/${ctx.sha256}/`))
      id = (found?.data || []).find((t) => t.status === 'reported')?.id
      if (!id) {
        if (ctx.size > MAX_SUBMIT) return null
        await limit('cape', 5)
        // On our VMs the sample lands on the desktop under its own name and runs from there, like a user would.
        const up = await cape('/tasks/create/file/', { method: 'POST', body: formWith(OWN_CAPE() ? { options: CAPE_RUN_OPTIONS } : {}, ctx.file(), 'file', ctx.name), timeout: 300_000 })
        id = up.data?.task_ids?.[0]
        if (!id) throw new Error(up.error_value || 'cape_submit_failed')
      }
      ctx.saveRef(String(id))
    }
    await poll(async () => {
      const s = await cape(`/tasks/status/${id}/`)
      if (/failed/.test(String(s.data))) throw new Error('cape_failed')
      return s.data === 'reported' ? true : null
    }, { every: OWN_CAPE() ? 10_000 : 45_000, timeout: 45 * 60_000 })
    const r = await cape(`/tasks/get/report/${id}/`, { timeout: 180_000 })
    const net = r.network || {}
    const configs = (r.CAPE?.configs || []).flatMap((c) => Object.entries(c).map(([family, cfg]) => ({ source: 'CAPE', family, ...cfg })))
    const mal = Number(r.malscore ?? 0)
    // CAPE's malscore piles up on generic behaviour (locale checks, curl, a dead IP): a harmless batch
    // file scored 8.8. On our own instance the score is rebuilt from the signatures minus that noise
    // (the dead IPs are mostly our own egress guard dropping traffic). Only a recognised family or an
    // extracted config lets CAPE speak at full weight; behaviour alone tops out at "suspicious".
    const sigs = (r.signatures || []).map((s) => ({ name: s.description || s.name, severity: Number(s.severity) || 1 }))
    // Suricata (ET Open) on the run's traffic: only malware / C2 / exploit rules become signatures, POLICY and INFO stay listed.
    const alerts = (r.suricata?.alerts || []).map((a) => ({ signature: String(a.signature || ''), category: a.category || '', severity: Number(a.severity) || 3, dst: a.dstip || '', port: a.dstport || null, proto: a.protocol || '' }))
    const seenAlert = new Set()
    const suricata = alerts.filter((a) => a.signature && !seenAlert.has(a.signature) && seenAlert.add(a.signature)).slice(0, 40)
    for (const a of suricata) if (/^ET (MALWARE|TROJAN|CNC|EXPLOIT|PHISHING|MOBILE_MALWARE|ATTACK_RESPONSE)|^ETPRO (MALWARE|TROJAN)/i.test(a.signature)) sigs.push({ name: `Suricata: ${a.signature}${/cnc|c2|command and control/i.test(a.signature) ? ' (command and control)' : ''}`, severity: 3 })
    // YARA (CAPE + YARA-Forge core) on the process memory dumps: what the unpacked code in memory looks like.
    const memoryYara = uniq((r.procmemory || []).flatMap((p) => (p.yara || p.cape_yara || []).map((y) => y.name || y.rule))).slice(0, 30)
    const real = sigs.filter((s) => !CAPE_NOISE.test(s.name))
    const behaviour = OWN_CAPE() ? Math.min(100, real.reduce((n, s) => n + (s.severity >= 3 ? 15 : s.severity === 2 ? 7 : 2), 0)) : Math.round(mal * 10)
    const proof = !!(r.malfamily || r.detections?.length || configs.length)
    const score = proof ? Math.max(Math.round(mal * 10), 85) : Math.min(45, Math.round(behaviour / 2))
    // What the sample wrote or downloaded (and payloads CAPE carved out of memory) goes through the whole
    // pipeline as child scans, so a loader is judged by what it actually fetched and ran.
    const captured = OWN_CAPE() && ctx.isRoot ? await scanCaptured(ctx, id, r) : []
    return {
      score,
      verdict: proof && mal >= 7 ? 'malicious' : score >= 35 ? 'suspicious' : 'unknown',
      family: r.malfamily || r.detections?.[0]?.family || null,
      signatures: sigs.slice(0, 40).map((s) => ({ ...s, noise: CAPE_NOISE.test(s.name) || undefined })),
      attack: capeTtps(r.ttps),
      processes: (r.behavior?.processtree || []).slice(0, 20).map(function walk(p) { return { name: p.name, pid: p.pid, command_line: p.environ?.CommandLine, children: (p.children || []).slice(0, 10).map(walk) } }),
      configs,
      payloads: (r.CAPE?.payloads || []).length,
      captured,
      activity: OWN_CAPE() ? capeActivity(r) : undefined,
      suricata,
      memory_yara: memoryYara,
      iocs: { ips: uniq((net.hosts || []).map((h) => h.ip || h)), domains: uniq((net.domains || []).map((d) => d.domain)), urls: uniq((net.http || []).map((h) => h.uri)) },
      link: OWN_CAPE() ? undefined : `${CAPE().replace(/\/apiv2$/, '')}/analysis/${id}/`,
    }
  },
}

// --- Token Tuzağı: a CAPE run in a profile full of fake accounts (../honey.js). Started by hand from the
// report (or by Nyx/Rune); honey.js writes its result, this entry only names the source and keeps it off by default.
export const honeyTrap = {
  id: 'honey', name: 'Token Tuzağı', layer: 8, kind: 'file', env: ['CAPE_URL', 'CAPE_API_KEY', 'CAPE_FILES_TOKEN'], manual: true,
  async run() { return null },
}

// --- CAPE activity: what each process did, rebuilt from its API calls -----------------------------
// Readable "this process started X, read these files, changed these registry values, talked to
// these hosts" for the report, without the hundreds of thousands of raw calls.
const argOf = (c, ...names) => { for (const n of names) { const a = (c.arguments || []).find((x) => x.name === n); if (a && a.value != null && a.value !== '') return String(a.value) } return '' }
const prettyOf = (c, name) => String((c.arguments || []).find((x) => x.name === name)?.pretty_value || '')
// System chatter every process produces (DLL loads, fonts, locale/theme lookups, pipes and devices).
const FILE_NOISE = /^\\(Device|\?\?\\pipe)|\\pipe\\|^\\\\\.\\|\\Windows\\(System32|SysWOW64|WinSxS|Fonts|Globalization|Registration|assembly|Microsoft\.NET)\\|\.(mui|nls|ttf|ttc|fon)$|desktop\.ini$|\\AppData\\Local\\Microsoft\\Windows\\Caches\\/i
const REG_NOISE = /\\(Shell\\Bags|BagMRU|UserAssist|MuiCache|Shell Extensions\\Cached|ActivityDataModel|SessionInfo|Explorer\\(Modules|ComDlg32|RecentDocs|FeatureUsage|TypedPaths|StreamMRU|Advanced|CabinetState|ShellState|Streams)|Notifications\\Settings|CloudStore|Security and Maintenance|FileExts\\|OpenWithProgids|ApplicationAssociationToasts|Explorer\\(Taskband|StartPage|HideDesktopIcons|VirtualDesktops|RunMRU|Search)|Policies\\Microsoft\\Windows\\(System|Explorer)|Control Panel\\(International|Desktop|Mouse|Keyboard)|Themes\\Personalize|Nls\\|MUI\\|SafeBoot|Session Manager\\(Environment|AppCertDlls)?|Terminal Server|LanguageConfiguration|CTF\\|Rpc\\|FileSystem\\|Image File Execution Options\\DllNXOptions|Command Processor\\(DisableUNCCheck|EnableExtensions|DelayedExpansion|DefaultColor|CompletionChar|PathCompletionChar|AutoRun))/i
const DIR_LIKE = /\\(Users\\[^\\.]+|AppData|Local|Roaming|LocalLow|Microsoft|Windows|Explorer|Temp|Desktop|Documents|Downloads|Programs|Start Menu)\\?$/i
const OWN_NET = /^(192\.168\.1\.(1|255)\b|127\.|0\.0\.0\.0|224\.|239\.|255\.)/
const add = (set, v, max) => { if (v && set.size < max) set.add(v) }
export function capeActivity(r) {
  const tree = new Map()
  for (const p of r.behavior?.processes || []) {
    const files = { read: new Set(), written: new Set(), deleted: new Set() }
    const reg = { read: new Set(), written: new Map(), deleted: new Set() }
    const net = { dns: new Set(), connections: new Set(), urls: new Set() }
    const started = new Set()
    const flags = new Set()
    for (const c of p.calls || []) {
      const api = c.api || ''
      if (/^(NtCreateFile|NtOpenFile)$/.test(api)) {
        const f = argOf(c, 'FileName'); if (!f || FILE_NOISE.test(f)) continue
        // folders being opened, not files
        if (/DIRECTORY_FILE/.test(prettyOf(c, 'CreateOptions')) || DIR_LIKE.test(f)) continue
        const acc = prettyOf(c, 'DesiredAccess') + ' ' + prettyOf(c, 'CreateDisposition')
        if (/WRITE|APPEND|CREATE|OVERWRITE|SUPERSEDE/i.test(acc) && !/FILE_OPEN\b/.test(acc.replace(/FILE_OPEN_IF/g, ''))) add(files.written, f, 60)
        else add(files.read, f, 60)
      } else if (/^(NtWriteFile|WriteFile)$/.test(api)) {
        const f = argOf(c, 'HandleName', 'FileName'); if (f && !FILE_NOISE.test(f)) add(files.written, f, 60)
      } else if (/^(NtReadFile|ReadFile)$/.test(api)) {
        const f = argOf(c, 'HandleName', 'FileName'); if (f && !FILE_NOISE.test(f)) add(files.read, f, 60)
      } else if (/^(NtDeleteFile|DeleteFileA|DeleteFileW)$/.test(api)) {
        add(files.deleted, argOf(c, 'FileName'), 40)
      } else if (/^(CopyFile|MoveFile)/.test(api)) {
        const to = argOf(c, 'NewFileName', 'NewFilePath'); if (to) add(files.written, to, 60)
        // the source of a copy was read (stealers copy Login Data / leveldb before opening it)
        if (/^CopyFile/.test(api)) { const from = argOf(c, 'ExistingFileName'); if (from && !FILE_NOISE.test(from)) add(files.read, from, 60) }
        if (/^MoveFile/.test(api)) add(files.deleted, argOf(c, 'ExistingFileName', 'OldFilePath'), 40)
      } else if (/^(NtSetValueKey|RegSetValueEx[AW]|RegSetKeyValue[AW])$/.test(api)) {
        const k = argOf(c, 'FullName', 'ObjectAttributes')
        if (k && !REG_NOISE.test(k) && reg.written.size < 60) {
          const d = argOf(c, 'Buffer', 'Data')
          // binary blobs come escaped (\x00…); show their size instead of noise
          reg.written.set(k, /\\x[0-9a-f]{2}/i.test(d) ? `(ikili veri, ~${Math.round(d.replace(/\\x[0-9a-f]{2}/gi, '.').length)} bayt)` : d.slice(0, 160))
        }
      } else if (/^(NtCreateKey|RegCreateKeyEx[AW])$/.test(api)) {
        const k = argOf(c, 'FullName', 'ObjectAttributes'); if (k && !REG_NOISE.test(k) && /CREATED_NEW|REG_CREATED_NEW_KEY/.test(prettyOf(c, 'Disposition'))) { if (reg.written.size < 60 && !reg.written.has(k)) reg.written.set(k, '(yeni anahtar)') }
      } else if (/^(NtDeleteKey|NtDeleteValueKey|RegDelete(Key|Value|Tree)(Ex)?[AW]?)$/.test(api)) {
        add(reg.deleted, argOf(c, 'FullName', 'ObjectAttributes', 'SubKey', 'ValueName'), 40)
      } else if (/^(NtQueryValueKey|RegQueryValueEx[AW]|RegGetValue[AW])$/.test(api)) {
        const k = argOf(c, 'FullName'); if (k && !REG_NOISE.test(k)) add(reg.read, k, 60)
      } else if (/^(getaddrinfo|GetAddrInfoW|GetAddrInfoExW|gethostbyname|DnsQuery_[AW]|DnsQueryEx)$/.test(api)) {
        add(net.dns, argOf(c, 'NodeName', 'Name', 'pNodeName', 'QueryName'), 40)
      } else if (/^(connect|WSAConnect|ConnectEx)$/.test(api)) {
        const ip = argOf(c, 'ip'); if (ip && !OWN_NET.test(ip)) add(net.connections, `${ip}:${argOf(c, 'port')}`, 40)
      } else if (/^(InternetOpenUrl[AW]|URLDownloadToFile[AW]|InternetConnect[AW]|WinHttpConnect|HttpOpenRequest[AW]|WinHttpOpenRequest)$/.test(api)) {
        const u = argOf(c, 'URL', 'Url', 'ServerName', 'Path', 'ObjectName'); if (u) add(net.urls, u, 40)
      } else if (/^(CreateProcessInternalW|NtCreateUserProcess|ShellExecuteExW|WinExec|CreateProcessWithTokenW)$/.test(api)) {
        add(started, (argOf(c, 'CommandLine', 'FilePath', 'ApplicationName', 'ImagePathName') + ' ' + argOf(c, 'Parameters')).trim(), 30)
      } else if (/^(CreateRemoteThread(Ex)?|NtCreateThreadEx|RtlCreateUserThread|NtQueueApcThread(Ex)?)$/.test(api)) {
        // threads in its own process (pseudo-handle -1 or its own pid) are normal; only another process counts
        const h = argOf(c, 'ProcessHandle').toLowerCase(), pid = argOf(c, 'ProcessId', 'ProcessIdentifier')
        if ((h && !/^0xf+$/.test(h)) || (pid && pid !== String(p.process_id))) flags.add('remote_thread')
      } else if (/^(NtWriteVirtualMemory|WriteProcessMemory)$/.test(api) && argOf(c, 'ProcessIdentifier', 'ProcessId') && argOf(c, 'ProcessIdentifier', 'ProcessId') !== String(p.process_id)) {
        flags.add('wrote_other_process')
      } else if (/^SetWindowsHookEx/.test(api)) {
        flags.add('hook')
      }
    }
    tree.set(p.process_id, {
      pid: p.process_id, ppid: p.parent_id, name: p.process_name, path: p.module_path || '', first_seen: p.first_seen,
      command_line: String(p.environ?.CommandLine || '').trim().slice(0, 500),
      started: [...started],
      files: { written: [...files.written], deleted: [...files.deleted], read: [...files.read].filter((f) => !files.written.has(f)) },
      registry: { written: [...reg.written].map(([key, data]) => ({ key, data })), deleted: [...reg.deleted], read: [...reg.read] },
      network: { dns: [...net.dns], connections: [...net.connections], urls: [...net.urls] },
      flags: [...flags],
    })
  }
  // Started by the analyzer but never reported back: the monitor did not get in (packers such as
  // VMProtect/Themida detect and neutralise it). Sysmon may still fill in what it did.
  const unmonitored = []
  for (const m of String(r.debug?.log || '').matchAll(/Successfully executed process from path "([^"]+)".*? with pid (\d+)/g)) {
    if (!tree.has(Number(m[2]))) unmonitored.push({ path: m[1], pid: Number(m[2]) })
  }
  mergeSysmon(tree, r.sysmon)
  for (const u of unmonitored) u.kernel = tree.has(u.pid)
  const n = r.network || {}
  return {
    unmonitored: unmonitored.slice(0, 5),
    processes: [...tree.values()].sort((a, b) => String(a.first_seen).localeCompare(String(b.first_seen))),
    commands: (r.behavior?.summary?.executed_commands || []).slice(0, 30),
    mutexes: (r.behavior?.summary?.mutexes || []).slice(0, 30),
    services: [...(r.behavior?.summary?.created_services || []), ...(r.behavior?.summary?.started_services || [])].slice(0, 20),
    dns: (n.dns || []).slice(0, 40).map((d) => ({ name: d.request, type: d.type, answers: (d.answers || []).map((a) => a.data).slice(0, 6) })),
    http: [...(n.http || []), ...(n.http_ex || []), ...(n.https_ex || [])].slice(0, 40).map((h) => ({ method: h.method || '', url: h.uri || `${h.protocol || 'http'}://${h.host || ''}${h.uri || h.path || ''}`, host: h.host || h.dst || '', ua: h['user-agent'] || '', status: h.status || '' })),
    connections: [...new Set([...(n.tcp || []), ...(n.udp || [])].filter((c) => c.src === '192.168.1.101' && !OWN_NET.test(c.dst)).map((c) => `${c.dst}:${c.dport}${(n.udp || []).includes(c) ? '/udp' : ''}`))].slice(0, 40),
  }
}

// Sysmon (kernel-side, renamed PerfHostSvc in the guest) sees processes CAPE's in-process monitor could
// not enter. Its events are merged into the same per-process view; processes only Sysmon saw get
// source "sysmon". The analyzer's own tooling (Python, wevtutil) is filtered out.
// (the analyzer unpacks to a random C:\xxxxxxxx\ folder whose bin\ loader injects the monitor)
const SYSMON_SELF = /\\Python312\\|\\wevtutil\.exe$|\\PerfHostSvc\.exe$|^C:\\[a-z0-9]{6,12}\\(bin|dll)\\/i
function mergeSysmon(tree, events) {
  if (!Array.isArray(events)) return
  const data = (ev) => Object.fromEntries([].concat(ev?.EventData?.Data || []).map((d) => [d?.['@Name'], d?.['#text'] ?? '']))
  const proc = (pid, image) => {
    const id = Number(pid)
    if (!id) return null
    if (!tree.has(id)) {
      if (!image || SYSMON_SELF.test(image)) return null
      tree.set(id, {
        pid: id, ppid: 0, name: String(image).split('\\').pop(), path: image, first_seen: '', command_line: '', started: [], flags: [], source: 'sysmon',
        files: { written: [], deleted: [], read: [] }, registry: { written: [], deleted: [], read: [] }, network: { dns: [], connections: [], urls: [] },
      })
    }
    return tree.get(id)
  }
  const push = (arr, v, max = 60) => { if (v && arr.length < max && !arr.includes(v)) arr.push(v) }
  for (const ev of events) {
    const id = String(ev?.System?.EventID ?? '')
    const d = data(ev)
    if (SYSMON_SELF.test(d.Image || '') || SYSMON_SELF.test(d.SourceImage || '')) continue
    if (id === '1') {
      const p = proc(d.ProcessId, d.Image)
      if (!p) continue
      if (!p.command_line) p.command_line = String(d.CommandLine || '').slice(0, 500)
      if (!p.ppid) p.ppid = Number(d.ParentProcessId) || 0
      if (!p.first_seen) p.first_seen = d.UtcTime || ''
      const parent = tree.get(Number(d.ParentProcessId))
      if (parent) push(parent.started, String(d.CommandLine || d.Image).slice(0, 300), 30)
    } else if (id === '3') {
      const p = proc(d.ProcessId, d.Image); if (!p || OWN_NET.test(d.DestinationIp || '')) continue
      push(p.network.connections, `${d.DestinationIp}:${d.DestinationPort}${d.DestinationHostname ? ` (${d.DestinationHostname})` : ''}`, 40)
    } else if (id === '11') {
      const p = proc(d.ProcessId, d.Image); if (p && !FILE_NOISE.test(d.TargetFilename || '')) push(p.files.written, d.TargetFilename)
    } else if (id === '23' || id === '26') {
      const p = proc(d.ProcessId, d.Image); if (p) push(p.files.deleted, d.TargetFilename, 40)
    } else if (id === '13') {
      const p = proc(d.ProcessId, d.Image); if (!p || REG_NOISE.test(d.TargetObject || '')) continue
      if (p.registry.written.length < 60 && !p.registry.written.some((x) => x.key === d.TargetObject)) p.registry.written.push({ key: d.TargetObject, data: String(d.Details || '').slice(0, 160) })
    } else if (id === '12') {
      const p = proc(d.ProcessId, d.Image); if (!p || REG_NOISE.test(d.TargetObject || '')) continue
      if (/delete/i.test(d.EventType || '')) push(p.registry.deleted, d.TargetObject, 40)
      else if (p.registry.written.length < 60 && !p.registry.written.some((x) => x.key === d.TargetObject)) p.registry.written.push({ key: d.TargetObject, data: '(yeni anahtar)' })
    } else if (id === '22') {
      const p = proc(d.ProcessId, d.Image); if (p) push(p.network.dns, d.QueryName, 40)
    } else if (id === '8') {
      const p = proc(d.SourceProcessId, d.SourceImage); if (p && d.SourceProcessId !== d.TargetProcessId && !p.flags.includes('remote_thread')) p.flags.push('remote_thread')
    } else if (id === '25') {
      const p = proc(d.ProcessId, d.Image); if (p && !p.flags.includes('tampering')) p.flags.push('tampering')
    }
  }
}

// CAPE lists ATT&CK either as {ttp, signature} or, in newer builds, {signature, ttps: [...], mbcs: [...]}.
export function capeTtps(list) {
  return (list || []).flatMap((t) => {
    if (typeof t === 'string') return [{ id: t, name: '' }]
    const ids = Array.isArray(t?.ttps) ? t.ttps : [t?.ttp]
    return ids.filter((x) => typeof x === 'string').map((id) => ({ id, name: String(t.signature || '') }))
  })
}

// Files worth a full scan of their own: programs, libraries, installers and scripts.
const RUNNABLE = /PE32|MS-DOS executable|DOS batch|PowerShell|Visual Basic|VBScript|JavaScript source|HTML Application|MSI Installer|Windows Installer|Java archive|Microsoft Cabinet|MS Windows shortcut|Composite Document File/i
const MAX_CAPTURED = 6
async function scanCaptured(ctx, task, r) {
  const want = [
    ...(r.dropped || []).filter((d) => RUNNABLE.test(d.type || '')).map((d) => ({ kind: 'dropped', d, name: String(d.guest_paths?.[0] || d.name?.[0] || d.sha256).split(/[\\/]/).pop() })),
    ...(r.CAPE?.payloads || []).map((d) => ({ kind: 'payload', d, name: `${d.cape_type || 'payload'}-${String(d.sha256).slice(0, 8)}.bin` })),
  ].filter((x) => /^[0-9a-f]{64}$/.test(x.d.sha256 || '') && x.d.sha256 !== ctx.sha256 && x.d.size > 64 && x.d.size <= MAX_SUBMIT)
  const seen = new Set()
  const out = []
  for (const x of want) {
    if (seen.has(x.d.sha256) || out.length >= MAX_CAPTURED) continue
    seen.add(x.d.sha256)
    const item = { kind: x.kind, name: x.name, path: x.d.guest_paths?.[0] || null, type: String(x.d.type || x.d.cape_type || '').slice(0, 80), sha256: x.d.sha256, size: x.d.size }
    try {
      const buf = await http(`http://127.0.0.1:${TUNNEL_FILES_PORT}/${x.kind}/${task}/${x.d.sha256}`, { raw: true, headers: { Authorization: `Token ${process.env.CAPE_FILES_TOKEN}` }, timeout: 120_000 })
      item.job_id = await ctx.addChild(buf, `${x.kind === 'payload' ? 'bellekten çıkarılan' : 'bıraktığı/indirdiği'}: ${x.name}`)
    } catch (e) { item.error = String(e.message || e).slice(0, 80) }
    out.push(item)
  }
  return out
}

// --- Threat.Zone ----------------------------------------------------------------------------------------
const TZ = 'https://app.threat.zone/public-api'
const tz = (path, opts = {}) => http(`${TZ}${path}`, { ...opts, headers: { Authorization: `Bearer ${process.env.THREATZONE_API_KEY}`, ...(opts.headers || {}) } })
export const threatzone = {
  id: 'threatzone', name: 'Threat.Zone', layer: 8, kind: 'file', env: ['THREATZONE_API_KEY'],
  async run(ctx) {
    let id = ctx.ref
    if (!id) {
      if (ctx.size > MAX_SUBMIT) return null
      const cfg = [{ metafieldId: 'environment', value: 'w10_x64' }, { metafieldId: 'private', value: true }, { metafieldId: 'timeout', value: 180 }, { metafieldId: 'internet_connection', value: true }]
      const up = await tz('/scan/sandbox', { method: 'POST', body: formWith({ analyzeConfig: cfg }, ctx.file(), 'file', ctx.name), timeout: 300_000 })
      id = up.uuid
      ctx.saveRef(id)
    }
    const s = await poll(async () => {
      const r = await tz(`/get/submission/${id}`)
      return r.reports?.dynamic?.status === 'completed' || r.status === 'completed' || r.reports?.dynamic?.status === 'error' ? r : null
    }, { every: 30_000, timeout: 30 * 60_000 })
    const LEVEL = { 3: ['malicious', 85], 2: ['suspicious', 55], 1: ['clean', null], 0: ['unknown', null] }
    const [verdict, score] = LEVEL[s.level] || LEVEL[0]
    return { verdict, score, tags: s.tags || [], link: `https://app.threat.zone/submission/${id}` }
  },
}

// --- paid sandboxes: ANY.RUN, Joe Sandbox, VMRay ------------------------------------------------------
export const anyrun = {
  id: 'anyrun', name: 'ANY.RUN', layer: 8, kind: 'file', env: ['ANYRUN_API_KEY'], paid: true,
  async run(ctx) {
    const H = { Authorization: `API-Key ${process.env.ANYRUN_API_KEY}` }
    let id = ctx.ref
    if (!id) {
      if (ctx.size > MAX_SUBMIT) return null
      const up = await http('https://api.any.run/v1/analysis', { method: 'POST', headers: H, body: formWith({ obj_type: 'file', env_os: 'windows', env_version: '10', env_bitness: '64', opt_privacy_type: 'bylink' }, ctx.file(), 'file', ctx.name), timeout: 300_000 })
      id = up.data?.taskid
      ctx.saveRef(id)
    }
    const r = await poll(async () => {
      const x = await http(`https://api.any.run/v1/analysis/${id}`, { headers: H })
      return x.data?.status === 'done' ? x.data : null
    }, { every: 30_000, timeout: 30 * 60_000 })
    const sc = r.analysis?.scores?.verdict?.score ?? null
    return {
      score: sc,
      verdict: sc >= 70 ? 'malicious' : sc >= 30 ? 'suspicious' : sc != null ? 'clean' : 'unknown',
      family: r.analysis?.tags?.[0]?.tag || null,
      tags: (r.analysis?.tags || []).map((t) => t.tag),
      attack: (r.mitre || []).map((m) => ({ id: m.id, name: m.name })),
      link: `https://app.any.run/tasks/${id}`,
    }
  },
}

export const joe = {
  id: 'joe', name: 'Joe Sandbox', layer: 8, kind: 'file', env: ['JOE_API_KEY'], paid: true,
  async run(ctx) {
    const J = 'https://jbxcloud.joesecurity.org/api/v2'
    const apikey = process.env.JOE_API_KEY
    let sub = ctx.ref
    if (!sub) {
      if (ctx.size > MAX_SUBMIT) return null
      const up = await http(`${J}/submission/new`, { method: 'POST', body: formWith({ apikey, 'accept-tac': '1' }, ctx.file(), 'sample', ctx.name), timeout: 300_000 })
      sub = up.data?.submission_id
      ctx.saveRef(sub)
    }
    const info = await poll(async () => {
      const x = await http(`${J}/submission/info`, { method: 'POST', body: urlForm({ apikey, submission_id: sub }) })
      return x.data?.status === 'finished' ? x.data : null
    }, { every: 45_000, timeout: 45 * 60_000 })
    const a = info.most_relevant_analysis || {}
    return {
      score: a.score != null ? a.score : null,
      verdict: a.detection === 'malicious' ? 'malicious' : a.detection === 'suspicious' ? 'suspicious' : a.detection === 'clean' ? 'clean' : 'unknown',
      link: a.webid ? `https://www.joesandbox.com/analysis/${a.webid}` : null,
    }
  },
}

export const vmray = {
  id: 'vmray', name: 'VMRay', layer: 8, kind: 'file', env: ['VMRAY_URL', 'VMRAY_API_KEY'], paid: true,
  async run(ctx) {
    const B = process.env.VMRAY_URL.replace(/\/+$/, '')
    const H = { Authorization: `api_key ${process.env.VMRAY_API_KEY}` }
    let sub = ctx.ref
    if (!sub) {
      if (ctx.size > MAX_SUBMIT) return null
      const up = await http(`${B}/rest/sample/submit`, { method: 'POST', headers: H, body: formWith({}, ctx.file(), 'sample_file', ctx.name), timeout: 300_000 })
      sub = String(up.data?.submissions?.[0]?.submission_id)
      ctx.saveRef(sub)
    }
    await poll(async () => ((await http(`${B}/rest/submission/${sub}`, { headers: H })).data?.submission_finished ? true : null), { every: 45_000, timeout: 45 * 60_000 })
    const an = (await http(`${B}/rest/analysis/submission/${sub}`, { headers: H })).data || []
    const sev = an.map((x) => x.analysis_verdict || x.analysis_severity).find(Boolean)
    return {
      verdict: /malicious/.test(sev) ? 'malicious' : /suspicious/.test(sev) ? 'suspicious' : /clean|not_suspicious/.test(sev) ? 'clean' : 'unknown',
      score: /malicious/.test(sev) ? 90 : /suspicious/.test(sev) ? 55 : null,
    }
  },
}
