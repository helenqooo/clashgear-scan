// Layer 1: identity and fingerprint, pure JS over the in-memory bytes. Never executes anything;
// every field read from the file is bounds-checked because the file may be built to break parsers.

import { createHash } from 'node:crypto'

function entropy(buf, start = 0, end = buf.length) {
  const n = end - start
  if (n <= 0) return 0
  const f = new Uint32Array(256)
  for (let i = start; i < end; i++) f[buf[i]]++
  let e = 0
  for (const c of f) if (c) { const p = c / n; e -= p * Math.log2(p) }
  return Math.round(e * 1000) / 1000
}

const MAGIC = [
  [[0x4d, 0x5a], 'pe'],
  [[0x7f, 0x45, 0x4c, 0x46], 'elf'],
  [[0xcf, 0xfa, 0xed, 0xfe], 'macho'],
  [[0xca, 0xfe, 0xba, 0xbe], 'macho-fat'],
  [[0x25, 0x50, 0x44, 0x46], 'pdf'],
  [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 'ole'],
  [[0x50, 0x4b, 0x03, 0x04], 'zip'],
  [[0x52, 0x61, 0x72, 0x21], 'rar'],
  [[0x37, 0x7a, 0xbc, 0xaf], '7z'],
  [[0x1f, 0x8b], 'gzip'],
  [[0x7b, 0x5c, 0x72, 0x74, 0x66], 'rtf'],
  [[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], 'lnk'],
  [[0x64, 0x65, 0x78, 0x0a], 'dex'],
]

function detectType(buf, name) {
  for (const [sig, t] of MAGIC) if (sig.every((b, i) => buf[i] === b)) {
    if (t !== 'zip') return t
    const head = buf.subarray(0, Math.min(buf.length, 4096)).toString('latin1')
    if (head.includes('AndroidManifest.xml') || /\.apk$/i.test(name)) return 'apk'
    if (head.includes('META-INF/') || /\.jar$/i.test(name)) return 'jar'
    if (head.includes('word/')) return 'docx'
    if (head.includes('xl/')) return 'xlsx'
    if (head.includes('ppt/')) return 'pptx'
    return 'zip'
  }
  const ext = (/\.([a-z0-9]{1,5})$/i.exec(name)?.[1] || '').toLowerCase()
  const SCRIPTS = { ps1: 'powershell', psm1: 'powershell', js: 'javascript', jse: 'javascript', vbs: 'vbscript', vbe: 'vbscript', bat: 'batch', cmd: 'batch', hta: 'hta', py: 'python', sh: 'shell', wsf: 'wsf' }
  if (SCRIPTS[ext]) return SCRIPTS[ext]
  // Mostly printable bytes = text of some kind.
  const sample = buf.subarray(0, Math.min(buf.length, 8192))
  let printable = 0
  for (const b of sample) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 0xc0) printable++
  return sample.length && printable / sample.length > 0.95 ? 'text' : 'unknown'
}

// Win32 APIs that matter most for triage (injection, persistence, evasion, crypto, network).
const SUSPICIOUS_API = new Set([
  'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 'ReadProcessMemory',
  'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC', 'NtQueueApcThread',
  'SetThreadContext', 'GetThreadContext', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'NtWriteVirtualMemory',
  'OpenProcess', 'SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState', 'RegisterHotKey',
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA',
  'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA', 'CryptAcquireContextW', 'BCryptEncrypt', 'BCryptDecrypt',
  'URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
  'HttpSendRequestA', 'HttpSendRequestW', 'WinHttpOpen', 'WinHttpSendRequest', 'WSAStartup', 'connect', 'send', 'recv',
  'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExW', 'WinExec', 'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserW',
  'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW', 'CreateServiceA', 'CreateServiceW',
  'AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'MiniDumpWriteDump',
  'CryptUnprotectData', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'LdrLoadDll', 'NtSetInformationThread',
])

const PACKER_SECTIONS = {
  UPX0: 'UPX', UPX1: 'UPX', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect', '.themida': 'Themida',
  '.winlice': 'WinLicense', '.enigma1': 'Enigma', '.enigma2': 'Enigma', '.aspack': 'ASPack', '.adata': 'ASPack',
  MPRESS1: 'MPRESS', MPRESS2: 'MPRESS', '.petite': 'Petite', '.nsp0': 'NsPack', '.MPRESS1': 'MPRESS', '.boom': 'The Boomerang',
  '.ccg': 'CCG', '.packed': 'packed', '.perplex': 'Perplex', '.spack': 'Simple Pack', '.taz': 'PESpin', '.y0da': 'yoda',
}

function parsePE(buf) {
  const u16 = (o) => (o + 2 <= buf.length ? buf.readUInt16LE(o) : 0)
  const u32 = (o) => (o + 4 <= buf.length ? buf.readUInt32LE(o) : 0)
  const peOff = u32(0x3c)
  if (peOff <= 0 || peOff + 24 > buf.length || u32(peOff) !== 0x00004550) return null
  const coff = peOff + 4
  const machine = u16(coff)
  const nSections = Math.min(u16(coff + 2), 96)
  const timestamp = u32(coff + 4)
  const optSize = u16(coff + 16)
  const characteristics = u16(coff + 18)
  const opt = coff + 20
  const magic = u16(opt)
  const is64 = magic === 0x20b
  const entry = u32(opt + 16)
  const imageBase = is64 ? Number(buf.readBigUInt64LE(Math.min(opt + 24, buf.length - 8))) : u32(opt + 28)
  const subsystem = u16(opt + 68)
  const ddOff = opt + (is64 ? 112 : 96)
  const nDirs = Math.min(u32(opt + (is64 ? 108 : 92)), 16)
  const dir = (i) => (i < nDirs ? { rva: u32(ddOff + i * 8), size: u32(ddOff + i * 8 + 4) } : { rva: 0, size: 0 })

  const secTable = opt + optSize
  const sections = []
  for (let i = 0; i < nSections; i++) {
    const s = secTable + i * 40
    if (s + 40 > buf.length) break
    const name = buf.subarray(s, s + 8).toString('latin1').replace(/\0.*$/s, '')
    const vsize = u32(s + 8), va = u32(s + 12), rawSize = u32(s + 16), rawPtr = u32(s + 20), ch = u32(s + 36)
    const end = Math.min(buf.length, rawPtr + rawSize)
    sections.push({
      name, va, vsize, rawPtr, rawSize, entropy: rawPtr < buf.length ? entropy(buf, rawPtr, end) : 0,
      exec: !!(ch & 0x20000000), write: !!(ch & 0x80000000),
    })
  }
  const rvaToOff = (rva) => {
    for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return rva - s.va + s.rawPtr
    return rva < buf.length ? rva : -1
  }
  const cstr = (off, max = 256) => {
    if (off < 0 || off >= buf.length) return ''
    let e = off
    while (e < buf.length && e - off < max && buf[e]) e++
    return buf.subarray(off, e).toString('latin1')
  }

  // Imports (name table walk, capped).
  const imports = []
  const imp = dir(1)
  if (imp.rva) {
    let d = rvaToOff(imp.rva)
    for (let n = 0; d > 0 && d + 20 <= buf.length && n < 256; n++, d += 20) {
      const oft = u32(d), nameRva = u32(d + 12), ft = u32(d + 16)
      if (!nameRva) break
      const dll = cstr(rvaToOff(nameRva)).toLowerCase()
      const funcs = []
      let t = rvaToOff(oft || ft)
      for (let k = 0; t > 0 && k < 2048; k++) {
        const thunk = is64 ? buf.readBigUInt64LE(Math.min(t, buf.length - 8)) : BigInt(u32(t))
        if (!thunk) break
        const byOrd = is64 ? thunk & 0x8000000000000000n : thunk & 0x80000000n
        if (byOrd) funcs.push(`ord${Number(thunk & 0xffffn)}`)
        else funcs.push(cstr(rvaToOff(Number(thunk & 0x7fffffffn)) + 2))
        t += is64 ? 8 : 4
        if (t + 8 > buf.length) break
      }
      imports.push({ dll, funcs })
    }
  }
  // imphash: md5 over "dll.func" pairs, extension stripped, lower-cased (pefile convention).
  const pairs = []
  for (const { dll, funcs } of imports) {
    const base = dll.replace(/\.(dll|ocx|sys)$/, '')
    for (const f of funcs) pairs.push(`${base}.${f.toLowerCase()}`)
  }
  const imphash = pairs.length ? createHash('md5').update(pairs.join(',')).digest('hex') : null

  const lastEnd = sections.reduce((m, s) => Math.max(m, s.rawPtr + s.rawSize), 0)
  const security = dir(4)
  const overlay = Math.max(0, buf.length - lastEnd - (security.rva >= lastEnd ? security.size : 0))
  const entrySection = sections.find((s) => entry >= s.va && entry < s.va + Math.max(s.vsize, s.rawSize))?.name || null
  const packers = [...new Set(sections.map((s) => PACKER_SECTIONS[s.name]).filter(Boolean))]
  const suspicious = [...new Set(imports.flatMap((i) => i.funcs).filter((f) => SUSPICIOUS_API.has(f)))]
  const ARCH = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64', 0x1c4: 'ARM' }
  const SUB = { 1: 'native', 2: 'GUI', 3: 'console', 9: 'WinCE', 10: 'EFI app', 16: 'boot' }

  return {
    arch: ARCH[machine] || `0x${machine.toString(16)}`,
    bits: is64 ? 64 : 32,
    dll: !!(characteristics & 0x2000),
    subsystem: SUB[subsystem] || String(subsystem),
    compiled_at: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    entry_point: `0x${entry.toString(16)}`,
    entry_section: entrySection,
    image_base: `0x${imageBase.toString(16)}`,
    dotnet: dir(14).rva !== 0,
    signed: security.rva !== 0 && security.size > 0,
    tls_callbacks: dir(9).rva !== 0,
    overlay_bytes: overlay,
    sections: sections.map(({ rawPtr, ...s }) => s),
    imports: imports.slice(0, 64).map((i) => ({ dll: i.dll, count: i.funcs.length, funcs: i.funcs.slice(0, 40) })),
    import_count: pairs.length,
    imphash,
    suspicious_apis: suspicious,
    packer_hints: packers,
    high_entropy_sections: sections.filter((s) => s.entropy > 7.2).map((s) => s.name),
  }
}

// Printable ASCII and UTF-16LE runs, then the indicator-shaped ones pulled out.
function strings(buf, min = 6, cap = 40000) {
  const out = []
  let cur = ''
  for (let i = 0; i < buf.length && out.length < cap; i++) {
    const b = buf[i]
    if (b >= 32 && b < 127) cur += String.fromCharCode(b)
    else { if (cur.length >= min) out.push(cur); cur = '' }
  }
  if (cur.length >= min) out.push(cur)
  cur = ''
  for (let i = 0; i + 1 < buf.length && out.length < cap * 2; i += 2) {
    const b = buf[i]
    if (buf[i + 1] === 0 && b >= 32 && b < 127) cur += String.fromCharCode(b)
    else { if (cur.length >= min) out.push(cur); cur = '' }
  }
  return out
}

const RE = {
  url: /\bhttps?:\/\/[^\s"'<>\\]{4,200}/gi,
  ip: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  registry: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s"']{3,160}/gi,
  path: /\b[A-Z]:\\[^\s"'<>|*?]{3,160}/gi,
  email: /\b[\w.+-]{2,40}@[\w-]{2,40}\.[a-z]{2,10}\b/gi,
  domain: /\b(?:[a-z0-9-]{2,63}\.)+(?:com|net|org|ru|cn|xyz|top|info|io|me|cc|su|tk|ml|ga|onion|biz|online|site|club|pw|ws|in|co|tr)\b/gi,
}
const PRIVATE_IP = /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|2(?:2[4-9]|[3-5]\d)\.)/
const KEYWORDS = /(powershell|cmd\.exe|-enc(odedcommand)?|frombase64string|invoke-expression|\biex\b|downloadstring|bitsadmin|certutil|regsvr32|rundll32|mshta|schtasks|wscript|cscript|vssadmin|bcdedit|wevtutil|mimikatz|\bbitcoin\b|ransom|\.onion|discord(app)?\.com\/api\/webhooks|api\.telegram\.org|pastebin\.com|keylog|webhook|password|cookies|login data|wallet)/i

function indicators(list) {
  const pick = (re, filter = () => true) => [...new Set(list.flatMap((s) => s.match(re) || []))].filter(filter).slice(0, 60)
  return {
    urls: pick(RE.url),
    ips: pick(RE.ip, (ip) => !PRIVATE_IP.test(ip) && !/^\d+\.\d+\.\d+\.0$/.test(ip) && ip !== '255.255.255.255'),
    domains: pick(RE.domain, (d) => !/\.(dll|exe|sys|pdb)$/i.test(d)),
    registry: pick(RE.registry),
    paths: pick(RE.path),
    emails: pick(RE.email),
    keywords: [...new Set(list.filter((s) => KEYWORDS.test(s)).map((s) => s.slice(0, 160)))].slice(0, 60),
  }
}

/** Static facts for the report. `hashes` comes from storage.js so it is computed once. */
export function analyzeStatic(buf, name, hashes) {
  const type = detectType(buf, name)
  const pe = type === 'pe' ? parsePE(buf) : null
  const strs = strings(buf)
  return {
    file_name: name,
    size: buf.length,
    type,
    ...hashes,
    entropy: entropy(buf),
    pe,
    strings_total: strs.length,
    indicators: indicators(strs),
    script_head: ['powershell', 'javascript', 'vbscript', 'batch', 'hta', 'python', 'shell', 'wsf', 'text'].includes(type)
      ? buf.subarray(0, 4000).toString('utf8') : null,
  }
}
