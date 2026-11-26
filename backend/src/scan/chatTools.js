// Tools the analyst chat model can call. Every tool works on the decrypted sample in memory only
// (nothing is written to disk and nothing is executed): byte reads, strings, PE layout and an
// x86/x64 disassembler (iced-x86, WebAssembly) whose output is annotated with imports and strings.

import { Decoder, DecoderOptions, Formatter, FormatterSyntax, Register } from 'iced-x86'
import { getJob, listJobs, listResults, childJobs } from './db.js'
import { loadSample, hashes } from './storage.js'
import { startScan } from './jobs.js'
import { vmpUnpack } from './vmpunpack.js'
import { startHoney, latestRun, honeyToday, honeyForTools, honeyEnabled, HONEY_SECONDS } from './honey.js'
import { TUNNEL_GHIDRA_PORT, TUNNEL_STATIC_PORT } from './tunnel.js'
import { apkSearch, apkSource } from './providers/local.js'
import { http } from './http.js'

const MAX_READ = 4096
const MAX_INSNS = 400
// Free keys get smaller tool outputs (each one is paid for again as input on every later step).
const FREE = { insns: 120, read: 1024, strings: 80, hits: 30 }
const cache = new Map() // sha256 -> { buf, pe, at }, a few samples kept briefly while a chat works on them

function sample(job) {
  const hit = cache.get(job.sha256)
  if (hit) { hit.at = Date.now(); return hit }
  const buf = loadSample(job.sha256)
  if (!buf) throw new Error('sample_not_stored (deleted after 30 days, or never stored)')
  const entry = { buf, pe: parsePE(buf), at: Date.now() }
  cache.set(job.sha256, entry)
  for (const [k, v] of cache) if (cache.size > 4 && v !== entry) cache.delete(k)
  return entry
}
setInterval(() => { for (const [k, v] of cache) if (Date.now() - v.at > 15 * 60_000) cache.delete(k) }, 60_000).unref()

/* Ghidra (cg-ghidra on the CAPE box, through the tunnel): the sample is sent once, Ghidra analyses and
 * decompiles it there (1-3 min) and the export is read back. Rune drops it when its run ends. */
const GHIDRA = `http://127.0.0.1:${TUNNEL_GHIDRA_PORT}`
const ghidraCache = new Map() // sha256 -> export, only while a Rune run works on it
const ghidraHeaders = () => ({ Authorization: `Token ${process.env.GHIDRA_TOKEN}` })
async function ghidraExport(job, waitMs, signal) {
  const hit = ghidraCache.get(job.sha256)
  if (hit) return hit
  if (!process.env.GHIDRA_TOKEN) throw new Error('decompiler_not_configured')
  const until = Date.now() + waitMs
  const timeout = (ms) => (signal ? AbortSignal.any([signal, AbortSignal.timeout(ms)]) : AbortSignal.timeout(ms))
  let posted = false
  for (;;) {
    if (signal?.aborted) throw new Error('stopped')
    const res = await fetch(`${GHIDRA}/result/${job.sha256}`, { headers: ghidraHeaders(), signal: timeout(60_000) })
    const body = await res.json().catch(() => ({}))
    if (body.status === 'done') { ghidraCache.set(job.sha256, body); return body }
    if (body.status === 'error') {
      // A failed run is kept on the CAPE box for a while; clear it so the next call can try again.
      fetch(`${GHIDRA}/result/${job.sha256}`, { method: 'DELETE', headers: ghidraHeaders(), signal: AbortSignal.timeout(15_000) }).catch(() => {})
      throw new Error(`decompiler: ${String(body.error || '').slice(-300)}. Ghidra cannot map this file: work on with pe_layout, find_strings and disassemble (follow the calls from the entry point / exports and the xrefs of interesting strings) and do not call decompile on it again.`)
    }
    if (res.status === 404 && !posted) {
      const r = await fetch(`${GHIDRA}/analyze/${job.sha256}`, { method: 'POST', headers: ghidraHeaders(), body: sample(job).buf, signal: timeout(60_000) })
      if (!r.ok) throw new Error(`decompiler refused the sample (${r.status})`)
      posted = true
    }
    if (Date.now() > until) return { status: 'running', elapsed_s: body.elapsed ?? 0 }
    await new Promise((r) => setTimeout(r, 3000))
  }
}
/* Archives (zip, rar, 7z, gz…) are opened by 7-Zip on the CAPE box too, never here and never run. Extracted
 * members become child jobs of the archive (scanned like a sandbox's dropped files), so both agents can
 * work on them with every tool. */
const ARCHIVE_CHILDREN_MAX = 15
async function archiveCall(kind, buf, password, names) {
  if (!process.env.GHIDRA_TOKEN) throw new Error('archive_tool_not_configured')
  const res = await fetch(`${GHIDRA}/archive/${kind}`, {
    method: 'POST',
    headers: { ...ghidraHeaders(), 'X-Password': Buffer.from(password || '').toString('base64'), 'X-Names': Buffer.from(JSON.stringify(names || [])).toString('base64') },
    body: buf,
    signal: AbortSignal.timeout(120_000),
  })
  if (!res.ok) throw new Error(`archive service ${res.status}`)
  return res.json()
}

/** Forgets a sample's decompiled code here and on the CAPE box. */
export async function dropDecompiled(sha256) {
  ghidraCache.delete(sha256)
  if (!process.env.GHIDRA_TOKEN) return
  await fetch(`${GHIDRA}/result/${sha256}`, { method: 'DELETE', headers: ghidraHeaders(), signal: AbortSignal.timeout(15_000) }).catch(() => {})
}
const sameAddr = (a, b) => { try { return BigInt(a) === BigInt(b) } catch { return false } }

const hex = (n) => `0x${(typeof n === 'bigint' ? n : BigInt(n)).toString(16)}`
const num = (v) => {
  if (typeof v === 'number') return v
  const s = String(v ?? '').trim().toLowerCase()
  if (!s) return NaN
  return s.startsWith('0x') ? parseInt(s, 16) : /^[0-9]+$/.test(s) ? parseInt(s, 10) : /^[0-9a-f]+h$/.test(s) ? parseInt(s.slice(0, -1), 16) : NaN
}

/* ------------------------------------------------------------------ PE layout */

function parsePE(buf) {
  const u16 = (o) => (o + 2 <= buf.length ? buf.readUInt16LE(o) : 0)
  const u32 = (o) => (o + 4 <= buf.length ? buf.readUInt32LE(o) : 0)
  const peOff = u32(0x3c)
  if (u16(0) !== 0x5a4d || peOff <= 0 || peOff + 24 > buf.length || u32(peOff) !== 0x00004550) return null
  const coff = peOff + 4
  const nSections = Math.min(u16(coff + 2), 96)
  const opt = coff + 20
  const is64 = u16(opt) === 0x20b
  const entry = u32(opt + 16)
  const imageBase = is64 ? buf.readBigUInt64LE(Math.min(opt + 24, buf.length - 8)) : BigInt(u32(opt + 28))
  const ddOff = opt + (is64 ? 112 : 96)
  const nDirs = Math.min(u32(opt + (is64 ? 108 : 92)), 16)
  const dir = (i) => (i < nDirs ? { rva: u32(ddOff + i * 8), size: u32(ddOff + i * 8 + 4) } : { rva: 0, size: 0 })
  const sections = []
  for (let i = 0; i < nSections; i++) {
    const s = opt + u16(coff + 16) + i * 40
    if (s + 40 > buf.length) break
    const ch = u32(s + 36)
    sections.push({
      name: buf.subarray(s, s + 8).toString('latin1').replace(/\0.*$/s, ''),
      vsize: u32(s + 8), va: u32(s + 12), rawSize: u32(s + 16), rawPtr: u32(s + 20),
      flags: `${ch & 0x40000000 ? 'r' : '-'}${ch & 0x80000000 ? 'w' : '-'}${ch & 0x20000000 ? 'x' : '-'}`,
    })
  }
  const rvaToOff = (rva) => {
    for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return rva - s.va < s.rawSize ? rva - s.va + s.rawPtr : -1
    return rva < (sections[0]?.rawPtr || 0x400) && rva < buf.length ? rva : -1
  }
  const offToRva = (off) => {
    for (const s of sections) if (off >= s.rawPtr && off < s.rawPtr + s.rawSize) return off - s.rawPtr + s.va
    return off < (sections[0]?.rawPtr || 0x400) ? off : -1
  }
  const cstr = (off, max = 256) => {
    if (off < 0 || off >= buf.length) return ''
    let e = off
    while (e < buf.length && e - off < max && buf[e]) e++
    return buf.subarray(off, e).toString('latin1')
  }

  // Imports with the IAT slot of every function, so disassembly can name `call [iat]`.
  const imports = []
  const iat = new Map() // rva of IAT slot -> "dll!func"
  const imp = dir(1)
  if (imp.rva) {
    let d = rvaToOff(imp.rva)
    for (let n = 0; d > 0 && d + 20 <= buf.length && n < 256; n++, d += 20) {
      const oft = u32(d), nameRva = u32(d + 12), ft = u32(d + 16)
      if (!nameRva) break
      const dll = cstr(rvaToOff(nameRva)).toLowerCase()
      const funcs = []
      let t = rvaToOff(oft || ft)
      for (let k = 0; t > 0 && k < 4096 && t + 8 <= buf.length; k++, t += is64 ? 8 : 4) {
        const thunk = is64 ? buf.readBigUInt64LE(t) : BigInt(u32(t))
        if (!thunk) break
        const byOrd = is64 ? thunk & 0x8000000000000000n : thunk & 0x80000000n
        const fn = byOrd ? `ord${Number(thunk & 0xffffn)}` : cstr(rvaToOff(Number(thunk & 0x7fffffffn)) + 2)
        const slot = ft + k * (is64 ? 8 : 4)
        funcs.push({ name: fn, iat_va: hex(imageBase + BigInt(slot)) })
        iat.set(slot, `${dll}!${fn}`)
      }
      imports.push({ dll, funcs })
    }
  }

  // Exports by name.
  const exports = []
  const ex = dir(0)
  if (ex.rva) {
    const e = rvaToOff(ex.rva)
    if (e > 0) {
      const nNames = Math.min(u32(e + 24), 4096), funcs = rvaToOff(u32(e + 28)), names = rvaToOff(u32(e + 32)), ords = rvaToOff(u32(e + 36))
      for (let i = 0; i < nNames && names > 0 && ords > 0 && funcs > 0; i++) {
        const rva = u32(funcs + u16(ords + i * 2) * 4)
        exports.push({ name: cstr(rvaToOff(u32(names + i * 4))), rva, va: hex(imageBase + BigInt(rva)) })
      }
    }
  }
  return { is64, bits: is64 ? 64 : 32, entry, imageBase, sections, rvaToOff, offToRva, imports, iat, exports, dotnet: dir(14).rva !== 0 }
}

/* ------------------------------------------------------------------ helpers */

function printableAt(buf, off) {
  if (off < 0 || off >= buf.length) return null
  let e = off
  while (e < buf.length && e - off < 120 && buf[e] >= 0x20 && buf[e] < 0x7f) e++
  if (e - off >= 4 && (e >= buf.length || buf[e] === 0)) return JSON.stringify(buf.subarray(off, e).toString('latin1'))
  e = off
  while (e + 1 < buf.length && e - off < 240 && buf[e + 1] === 0 && buf[e] >= 0x20 && buf[e] < 0x7f) e += 2
  if ((e - off) / 2 >= 4) return `L${JSON.stringify(buf.subarray(off, e).toString('utf16le'))}`
  return null
}

function hexdump(buf, off, len) {
  const out = []
  for (let o = off; o < Math.min(buf.length, off + len); o += 16) {
    const row = buf.subarray(o, Math.min(o + 16, buf.length))
    const h = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const a = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('')
    out.push(`${o.toString(16).padStart(8, '0')}  ${h.padEnd(47)}  ${a}`)
  }
  return out.join('\n')
}

/** Resolves "entry", an export name, "rva:0x..", "off:0x.." or a VA into a file offset and VA. */
function locate(s, where) {
  const { pe, buf } = s
  const w = String(where ?? 'entry').trim()
  if (!pe) {
    const off = num(w.replace(/^off:/i, '').replace(/^entry$/i, '0'))
    if (!(off >= 0 && off < buf.length)) throw new Error(`bad offset "${w}" (file is not PE: pass a file offset)`)
    return { off, ip: BigInt(off) }
  }
  let rva
  if (/^entry$/i.test(w)) rva = pe.entry
  else if (/^rva:/i.test(w)) rva = num(w.slice(4))
  else if (/^off:/i.test(w)) {
    const off = num(w.slice(4))
    rva = pe.offToRva(off)
    if (rva < 0) return { off, ip: BigInt(off) }
  } else {
    const exp = pe.exports.find((e) => e.name === w)
    if (exp) rva = exp.rva
    else {
      const va = num(w)
      if (!Number.isFinite(va)) throw new Error(`cannot resolve "${w}"`)
      rva = va >= Number(pe.imageBase) ? va - Number(pe.imageBase) : va
    }
  }
  const off = pe.rvaToOff(rva)
  if (off < 0) throw new Error(`rva ${hex(rva)} has no file data (uninitialised or outside sections; packed?)`)
  return { off, ip: pe.imageBase + BigInt(rva) }
}

function vaToOff(pe, va) {
  if (!pe) return Number(va)
  const rva = Number(va - pe.imageBase)
  return rva >= 0 ? pe.rvaToOff(rva) : -1
}

/* ------------------------------------------------------------------ tools */

/** A job the caller may read: the owner key reads any job, every other key only its own. */
function jobFor(id, ctx) {
  const job = getJob(String(id || ''))
  if (!job || !(ctx?.owner || job.key_id === ctx?.keyId)) throw new Error('job_not_found')
  return job
}

function trimSummary(v, depth = 0) {
  if (v == null) return v
  if (typeof v === 'string') return v.length > 1500 ? `${v.slice(0, 1500)}…` : v
  if (Array.isArray(v)) return v.slice(0, depth ? 30 : 60).map((x) => trimSummary(x, depth + 1))
  if (typeof v === 'object') {
    if (depth > 5) return '[…]'
    const out = {}
    for (const [k, x] of Object.entries(v)) if (k !== 'engines') out[k] = trimSummary(x, depth + 1)
    return out
  }
  return v
}

const IMPL = {
  list_jobs({ limit = 15 }, { keyId }) {
    return listJobs(keyId, Math.min(Math.max(Number(limit) || 15, 1), 50))
      .map((j) => ({ job_id: j.id, file_name: j.file_name, size: j.size, sha256: j.sha256, status: j.status, verdict: j.verdict, score: j.score, created_at: new Date(j.created_at).toISOString() }))
  },

  async get_report({ job_id, wait_seconds = 0 }, ctx) {
    let job = jobFor(job_id, ctx)
    // While the scan is still running, optionally wait (up to 90 s) for it to finish.
    const until = Date.now() + Math.min(Math.max(Number(wait_seconds) || 0, 0), 90) * 1000
    while (job.status === 'running' && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 3000))
      job = jobFor(job_id, ctx)
    }
    return {
      job_id: job.id, file_name: job.file_name, size: job.size, md5: job.md5, sha1: job.sha1, sha256: job.sha256,
      status: job.status, score: job.score, verdict: job.verdict,
      static: trimSummary(job.static),
      ai_report: job.ai ? { verdict: job.ai.verdict, family: job.ai.family, summary: job.ai.summary_tr, findings: job.ai.key_findings_tr } : null,
      sources: listResults(job.id).filter((r) => r.status !== 'disabled').map((r) => ({ source: r.source, layer: r.layer, status: r.status, error: r.error || undefined, summary: trimSummary(r.summary) })),
      unpacked_children: childJobs(job.id).map((c) => ({ job_id: c.id, file_name: c.file_name, size: c.size, verdict: c.verdict, score: c.score })),
    }
  },

  pe_layout({ job_id }, ctx) {
    const s = sample(jobFor(job_id, ctx))
    if (!s.pe) return { pe: false, size: s.buf.length, head_hex: hexdump(s.buf, 0, 64) }
    const { pe } = s
    return {
      pe: true, bits: pe.bits, image_base: hex(pe.imageBase), entry_va: hex(pe.imageBase + BigInt(pe.entry)), dotnet: pe.dotnet,
      sections: pe.sections.map((x) => ({ name: x.name, va: hex(pe.imageBase + BigInt(x.va)), vsize: hex(x.vsize), raw_offset: hex(x.rawPtr), raw_size: hex(x.rawSize), flags: x.flags })),
      imports: pe.imports.map((i) => ({ dll: i.dll, funcs: i.funcs.slice(0, 300) })),
      exports: pe.exports.slice(0, 300).map(({ name, va }) => ({ name, va })),
    }
  },

  read_bytes({ job_id, at = 'off:0', length = 256, as = 'hex' }, ctx) {
    const s = sample(jobFor(job_id, ctx))
    const { off } = locate(s, /^\d+$/.test(String(at)) ? `off:${at}` : at)
    const len = Math.min(Math.max(Number(length) || 256, 1), ctx.owner ? MAX_READ : FREE.read)
    if (as === 'text') return { offset: hex(off), text: s.buf.subarray(off, off + len).toString('latin1') }
    if (as === 'utf16') return { offset: hex(off), text: s.buf.subarray(off, off + len).toString('utf16le') }
    return { offset: hex(off), hexdump: hexdump(s.buf, off, len) }
  },

  find_strings({ job_id, min_length = 5, pattern, encoding = 'both', start = 0, limit = 200 }, ctx) {
    const s = sample(jobFor(job_id, ctx))
    const { buf, pe } = s
    const min = Math.min(Math.max(Number(min_length) || 5, 3), 64)
    const re = pattern ? new RegExp(String(pattern).slice(0, 200), 'i') : null
    const cap = Math.min(Math.max(Number(limit) || 200, 1), ctx.owner ? 500 : FREE.strings)
    const out = []
    let total = 0
    const push = (o, str, enc) => {
      if (re && !re.test(str)) return
      total++
      if (total <= Number(start) || out.length >= cap) return
      const rva = pe ? pe.offToRva(o) : -1
      out.push({ off: hex(o), va: pe && rva >= 0 ? hex(pe.imageBase + BigInt(rva)) : undefined, enc, s: str.length > 300 ? `${str.slice(0, 300)}…` : str })
    }
    if (encoding !== 'utf16') {
      let st = -1
      for (let i = 0; i <= buf.length; i++) {
        const c = buf[i]
        if (i < buf.length && c >= 0x20 && c < 0x7f) { if (st < 0) st = i } else if (st >= 0) { if (i - st >= min) push(st, buf.subarray(st, i).toString('latin1'), 'ascii'); st = -1 }
      }
    }
    if (encoding !== 'ascii') {
      for (const par of [0, 1]) {
        let st = -1
        for (let i = par; i + 1 <= buf.length; i += 2) {
          const ok = i + 1 < buf.length && buf[i + 1] === 0 && buf[i] >= 0x20 && buf[i] < 0x7f
          if (ok) { if (st < 0) st = i } else if (st >= 0) { if ((i - st) / 2 >= min) push(st, buf.subarray(st, i).toString('utf16le'), 'utf16'); st = -1 }
        }
      }
    }
    return { total_matches: total, returned: out.length, start: Number(start) || 0, strings: out }
  },

  search_bytes({ job_id, hex: hexPat, text, limit = 50 }, ctx) {
    const s = sample(jobFor(job_id, ctx))
    let needle
    if (hexPat) needle = Buffer.from(String(hexPat).replace(/[^0-9a-f]/gi, ''), 'hex')
    else if (text) needle = Buffer.from(String(text), 'latin1')
    if (!needle?.length) throw new Error('give hex or text')
    const hits = []
    for (let i = s.buf.indexOf(needle); i >= 0 && hits.length < Math.min(Number(limit) || 50, ctx.owner ? 200 : FREE.hits); i = s.buf.indexOf(needle, i + 1)) {
      const rva = s.pe ? s.pe.offToRva(i) : -1
      hits.push({ off: hex(i), va: s.pe && rva >= 0 ? hex(s.pe.imageBase + BigInt(rva)) : undefined })
    }
    return { needle_len: needle.length, hits }
  },

  disassemble({ job_id, at = 'entry', count = 80, bits }, ctx) {
    const s = sample(jobFor(job_id, ctx))
    const { buf, pe } = s
    const { off, ip } = locate(s, at)
    const bitness = [16, 32, 64].includes(Number(bits)) ? Number(bits) : pe?.bits || 32
    const n = Math.min(Math.max(Number(count) || (ctx.owner ? 80 : 60), 1), ctx.owner ? MAX_INSNS : FREE.insns)
    const data = buf.subarray(off, Math.min(buf.length, off + n * 15))
    const decoder = new Decoder(bitness, data, DecoderOptions.None)
    decoder.ip = ip
    const fmt = new Formatter(FormatterSyntax.Intel)
    fmt.hexPrefix = '0x'
    fmt.hexSuffix = ''
    fmt.uppercaseHex = false
    const lines = []
    try {
      for (let i = 0; i < n && decoder.canDecode; i++) {
        const pos = decoder.position
        const ins = decoder.decode()
        try {
          const bytes = [...data.subarray(pos, pos + ins.length)].map((b) => b.toString(16).padStart(2, '0')).join('')
          let line = `${hex(ins.ip).padEnd(bitness === 64 ? 18 : 10)} ${bytes.padEnd(20)} ${ins.isInvalid ? '(bad)' : fmt.format(ins)}`
          const notes = []
          const targets = []
          if (ins.nearBranchTarget) targets.push(ins.nearBranchTarget)
          if (ins.memoryBase === Register.RIP || ins.memoryBase === Register.EIP) targets.push(ins.ipRelMemoryAddress)
          else if (ins.memoryBase === Register.None && ins.memoryIndex === Register.None && ins.memoryDisplacement) targets.push(ins.memoryDisplacement)
          for (const t of targets) {
            if (pe) {
              const rva = Number(t - pe.imageBase)
              const api = pe.iat.get(rva)
              if (api) { notes.push(api); continue }
              const exp = pe.exports.find((e) => e.rva === rva)
              if (exp) { notes.push(`export ${exp.name}`); continue }
            }
            const str = printableAt(buf, vaToOff(pe, t))
            if (str) notes.push(str)
          }
          for (const imm of (fmt.format(ins).match(/0x[0-9a-f]{5,16}/g) || [])) {
            const str = printableAt(buf, vaToOff(pe, BigInt(imm)))
            if (str && !notes.includes(str)) notes.push(str)
          }
          if (notes.length) line += `   ; ${notes.join(' | ')}`
          lines.push(line)
        } finally { ins.free() }
      }
    } finally { decoder.free(); fmt.free() }
    return { bits: bitness, start_va: hex(ip), file_offset: hex(off), listing: lines.join('\n') }
  },

  async extract_archive({ job_id, password = '', files }, ctx) {
    const job = jobFor(job_id, ctx)
    const buf = sample(job).buf
    if (!files) {
      const r = await archiveCall('list', buf, password)
      if (r.error) return { error: r.error, hint: r.error === 'password_required' ? 'Encrypted: try common passwords (infected, 1234, 123, password, the file or site name) or ask the user.' : undefined }
      return { ...r, hint: 'Extract the runnable or suspicious members with "files" (max 5 per call).' }
    }
    const names = String(files).split('|').map((s) => s.trim()).filter(Boolean).slice(0, 5)
    const kids = childJobs(job.id)
    if (kids.length >= ARCHIVE_CHILDREN_MAX) throw new Error('this archive already has enough extracted files; work with get_report.unpacked_children')
    const r = await archiveCall('extract', buf, password, names)
    if (r.error) return { error: r.error }
    const out = []
    for (const f of r.files || []) {
      const data = Buffer.from(f.b64, 'base64')
      const name = String(f.name).split(/[\\/]/).pop()
      const sha = hashes(data).sha256
      const have = childJobs(job.id).find((c) => c.sha256 === sha)
      const id = have ? have.id : startScan({ keyId: job.key_id, buf: data, name: `arşivden: ${name}`, parentId: job.id })
      out.push({ name: f.name, size: data.length, job_id: id })
    }
    return { extracted: out, skipped: r.skipped, note: 'Each file is now a job of its own (scanning in the background): use its job_id with every tool.' }
  },

  async vmp_unpack({ job_id, mode = 'static' }, ctx) {
    return vmpUnpack(jobFor(job_id, ctx), { runtime: mode === 'runtime' })
  },

  // Token Tuzağı (honey.js): run the file among fake accounts in the VM, or read what the last run caught.
  async token_trap({ job_id, action = 'status', wait_seconds = 0 }, ctx) {
    const job = jobFor(job_id, ctx)
    if (action === 'start') {
      if (!honeyEnabled()) return { error: 'honey_unavailable' }
      const prev = latestRun(job.id)
      if (prev && ['queued', 'running'].includes(prev.status)) return { status: prev.status, note: 'Already running. Call again with action "status" and wait_seconds 90.' }
      if (prev?.status === 'done' && !ctx.owner) return { ...honeyForTools(job.id, false), note: 'It already ran on this file; this is its result.' }
      if (!ctx.owner && honeyToday(ctx.keyId) >= Number(process.env.SCAN_HONEY_DAILY ?? 2)) return { error: 'honey_quota_exceeded', note: "Today's Token Tuzağı runs for this key are used up; the user can run it tomorrow from the report's Sandbox tab." }
      const run = await startHoney(job, ctx.keyId)
      return { status: run.status, seconds: HONEY_SECONDS, note: `Running in the bait VM (${HONEY_SECONDS} s plus 1-2 min processing). Do other work, then call token_trap with action "status" and wait_seconds 90.` }
    }
    const until = Date.now() + Math.min(Math.max(Number(wait_seconds) || 0, 0), 90) * 1000
    while (['queued', 'running'].includes(latestRun(job.id)?.status) && Date.now() < until && !ctx?.signal?.aborted) await new Promise((r) => setTimeout(r, 5000))
    return honeyForTools(job.id, !!ctx?.owner) || { status: 'never_run', note: 'Token Tuzağı has not run on this file. action "start" runs it (about 4-5 minutes).' }
  },

  async decompile({ job_id, functions, filter, limit = 60 }, ctx) {
    const job = jobFor(job_id, ctx)
    // Short wait: a big file takes Ghidra minutes, and Rune keeps working (and visibly so) meanwhile.
    const ex = await ghidraExport(job, 40_000, ctx?.signal)
    if (ex.status !== 'done') return { ...ex, note: 'Ghidra is still analysing this file (large files take several minutes). Work with pe_layout / disassemble / find_strings meanwhile and call decompile again only after a few of those steps.' }
    const head = { format: ex.format, ...(ex.upx_unpacked ? { upx_unpacked: true } : {}), language: ex.language, image_base: ex.image_base, entry_points: ex.entry_points, functions_total: ex.functions_total, decompiled: ex.decompiled, truncated: ex.truncated }
    if (!functions) {
      // The map: every function with the imports it calls and the strings it references, busiest first.
      let list = ex.functions
      if (filter) {
        let re
        try { re = new RegExp(filter, 'i') } catch { throw new Error('INVALID_JSON: filter is not a valid regex') }
        list = list.filter((f) => re.test(f.name) || f.calls.some((c) => re.test(c)) || f.strings.some((s) => re.test(s)))
      }
      list = [...list].sort((a, b) => b.calls.length - a.calls.length || b.strings.length - a.strings.length)
      const n = Math.min(Math.max(Number(limit) || 60, 1), ctx?.owner ? 300 : 120)
      return { ...head, matches: list.length, functions: list.slice(0, n).map(({ c, ...f }) => ({ ...f, has_code: !!c })) }
    }
    const wanted = String(functions).split(',').map((s) => s.trim()).filter(Boolean).slice(0, 4)
    const found = wanted.map((w) => ex.functions.find((f) => f.name === w || sameAddr(f.addr, w)) || { name: w, error: 'no such function (use decompile without "functions" for the list)' })
    return { ...head, functions: found }
  },

  // Android: jadx output on cg-static (made right after the static scan, kept 2 h).
  async apk_code({ job_id, search, path }, ctx) {
    const job = jobFor(job_id, ctx)
    if (job.static?.type !== 'apk' && !/\.apk$/i.test(job.file_name)) return { error: 'not an APK; use decompile for PE/ELF files' }
    try {
      if (path) return await apkSource(job.sha256, path)
      return await apkSearch(job.sha256, search || '(onCreate|https?://|loadLibrary|DexClassLoader|getDeviceId|sendTextMessage|Accessibility)')
    } catch (e) {
      if (e.status !== 404) throw e
      const buf = loadSample(job.sha256)
      if (!buf) return { error: 'sample no longer stored' }
      await http(`http://127.0.0.1:${TUNNEL_STATIC_PORT}/analyze/${job.sha256}`, { method: 'POST', headers: { Authorization: `Token ${process.env.CG_STATIC_TOKEN}`, 'Content-Type': 'application/octet-stream' }, body: buf, timeout: 120_000 }).catch(() => {})
      return { status: 'running', note: 'jadx is decompiling this APK (1-4 minutes). Use get_report meanwhile and call apk_code again later.' }
    }
  },
}

const J = (p) => ({ type: 'object', properties: p.properties, required: p.required || [], additionalProperties: false })
const JOB = { type: 'string', description: 'Scan job id (from the conversation, list_jobs or get_report.unpacked_children).' }
const AT = { type: 'string', description: '"entry", an export name, a virtual address like "0x401000", "rva:0x1000" or a raw file offset "off:0x400".' }

export const TOOLS = [
  { name: 'list_jobs', description: 'Recent scans of this key (newest first) with job ids, names, verdicts.', input_schema: J({ properties: { limit: { type: 'integer' } } }) },
  { name: 'get_report', description: 'The full multi-layer scan report of a job: hashes, static analysis, every source result (AV engines, intel, sandboxes, unpackers, deobfuscators, network), the AI summary and unpacked child files. Status "running" means sources are still working: do static work meanwhile, then call again with wait_seconds (max 90) to wait for the scan to finish.', input_schema: J({ properties: { job_id: JOB, wait_seconds: { type: 'integer', description: 'Wait up to this many seconds (max 90) while the scan is still running.' } }, required: ['job_id'] }) },
  { name: 'pe_layout', description: 'PE headers of the sample: bitness, image base, entry point, sections with raw offsets and flags, every import with its IAT address, and exports. For non-PE files returns the first bytes.', input_schema: J({ properties: { job_id: JOB }, required: ['job_id'] }) },
  { name: 'disassemble', description: 'Disassembles x86/x64 code (Intel syntax) from the sample. Calls through the IAT are annotated with the API name, and references to strings show the string. Follow calls and jumps by disassembling their targets. Up to 400 instructions per call.', input_schema: J({ properties: { job_id: JOB, at: AT, count: { type: 'integer', description: 'Instructions, max 400.' }, bits: { type: 'integer', enum: [16, 32, 64], description: 'Only for non-PE shellcode; PE files use their own bitness.' } }, required: ['job_id'] }) },
  { name: 'read_bytes', description: 'Reads up to 4096 bytes as a hexdump (default), latin1 text or UTF-16 text. Use for headers, configs, overlays, embedded scripts.', input_schema: J({ properties: { job_id: JOB, at: AT, length: { type: 'integer' }, as: { type: 'string', enum: ['hex', 'text', 'utf16'] } }, required: ['job_id'] }) },
  { name: 'find_strings', description: 'Extracts ASCII and UTF-16 strings with their file offsets and virtual addresses. Filter with a case-insensitive regex; page with start/limit.', input_schema: J({ properties: { job_id: JOB, pattern: { type: 'string' }, min_length: { type: 'integer' }, encoding: { type: 'string', enum: ['both', 'ascii', 'utf16'] }, start: { type: 'integer' }, limit: { type: 'integer' } }, required: ['job_id'] }) },
  { name: 'search_bytes', description: 'Finds an exact byte pattern (hex, no wildcards) or a latin1 text and returns offsets and virtual addresses.', input_schema: J({ properties: { job_id: JOB, hex: { type: 'string' }, text: { type: 'string' }, limit: { type: 'integer' } }, required: ['job_id'] }) },
  { name: 'extract_archive', description: 'Opens an archive (zip, rar, 7z, gz, tar…) in an isolated box (nothing is run). Without "files": the member list (name, size, encrypted). With "files" (member names separated by |, max 5): extracts them, each becomes a child job you can analyse with every tool (job_id in the result). Password-protected archives: pass "password" (malware archives often use "infected").', input_schema: J({ properties: { job_id: JOB, password: { type: 'string' }, files: { type: 'string', description: 'Member names from the list, separated by |.' } }, required: ['job_id'] }) },
  { name: 'vmp_unpack', description: 'Unpacks a VMProtect-protected PE inside the isolated sandbox VM with VMPStatic and VMProtect-Unpacker. "static" (default) never runs the file; "runtime" starts it suspended in the VM and dumps it from memory (use when static fails). Takes 3-6 minutes. Unpacked images become child jobs (job_id in the result) to decompile. Packing is undone, virtualized functions stay virtualized. Once per file.', input_schema: J({ properties: { job_id: JOB, mode: { type: 'string', enum: ['static', 'runtime'] } }, required: ['job_id'] }) },
  { name: 'token_trap', description: 'Token Tuzağı: the file runs in our sandbox VM inside a user profile full of fake, unique-per-run accounts (Discord token, Chrome/Edge saved passwords and cookies decryptable with the VM DPAPI key, Steam ssfn, Telegram tdata, Exodus/MetaMask wallets, a Roblox cookie, a crypto address on the clipboard, a login for our own trap page). The result says, per kind, whether the file READ the bait (Windows audit log names the process), PACKED it (a zip or file made during the run holds the values) and SENT it (values seen in outbound traffic, also base64/zipped or inside HTTPS decrypted with the VM TLS keys; "connection" proof means only a connection to an upload/chat API after reading), clipboard swaps, Discord webhooks / Telegram bots seen, and "used": someone later tried the stolen trap login (date, country). proof=true is hard evidence of a stealer. action "status" (default) reads the latest run (wait_seconds up to 90 while it runs); "start" runs it (3-5 minutes, counts against the daily runs of the key).', input_schema: J({ properties: { job_id: JOB, action: { type: 'string', enum: ['status', 'start'] }, wait_seconds: { type: 'integer', description: 'With status: wait up to this many seconds (max 90) while a run is going.' } }, required: ['job_id'] }) },
  { name: 'apk_code', description: 'Android APK sources decompiled by jadx (Java). Without "path": a case-insensitive regex "search" over all sources returns file:line hits (default search looks for entry points, URLs, native/dynamic loading, SMS, accessibility). With "path" (a file from the hits): that source file, up to 60 KB. The first call may answer "running" while jadx works.', input_schema: J({ properties: { job_id: JOB, search: { type: 'string', description: 'Regex, e.g. "webhook|api\.telegram|Cipher".' }, path: { type: 'string', description: 'e.g. "com/example/app/MainActivity.java".' } }, required: ['job_id'] }) },
  { name: 'decompile', description: 'Ghidra decompiler. Without "functions": the function map (name, address, size, imported APIs it calls, strings it references; busiest first), optionally narrowed by a case-insensitive regex "filter" over names, APIs and strings. With "functions" (comma-separated names or addresses, max 4): their decompiled C. The first call on a file starts Ghidra, which takes 1-3 minutes; a "running" result means call again later and use the other tools meanwhile.', input_schema: J({ properties: { job_id: JOB, functions: { type: 'string', description: 'e.g. "FUN_140008958, 0x140001000".' }, filter: { type: 'string', description: 'Regex over function names, called APIs and referenced strings, e.g. "Internet|socket|Crypt".' }, limit: { type: 'integer', description: 'Functions in the map, default 60.' } }, required: ['job_id'] }) },
].map((t) => ({ ...t, eager_input_streaming: true }))

// Nyx reads reports and takes a first static look; the code itself is Rune's job (rune.js).
const pick = (...names) => TOOLS.filter((t) => names.includes(t.name))
export const NYX_TOOLS = pick('list_jobs', 'get_report', 'token_trap', 'extract_archive', 'pe_layout', 'find_strings')
export const RUNE_TOOLS = pick('get_report', 'token_trap', 'extract_archive', 'vmp_unpack', 'pe_layout', 'disassemble', 'decompile', 'apk_code', 'find_strings', 'read_bytes', 'search_bytes')
/** Tools whose input and output reveal the sample's code: only owner keys see them. */
export const REVERSING_TOOLS = new Set(['pe_layout', 'disassemble', 'decompile', 'apk_code', 'vmp_unpack', 'find_strings', 'read_bytes', 'search_bytes'])

// Every reversing call also says what it is for, in words: the only thing free keys see of the step (owner,
// 2026-11-07: the rail must show what is being done, not a fixed label). runTool never sees it.
const NOTE = { type: 'string', description: 'What this step does, for the user watching: a short Turkish phrase (max 8 words, present tense), no code, no addresses, no byte values. E.g. "ağ bağlantısı kuran fonksiyonu arıyor", "şifreli metinleri çözen döngüyü inceliyor".' }
export const withNote = (tools) => tools.map((t) => (REVERSING_TOOLS.has(t.name)
  ? { ...t, input_schema: { ...t.input_schema, properties: { ...t.input_schema.properties, note: NOTE }, required: [...t.input_schema.required, 'note'] } }
  : t))
/** The tool input without the step note. */
export const withoutNote = (input) => { if (!input || typeof input !== 'object') return input; const { note, ...rest } = input; return rest }

/** Validates the (possibly truncated) streamed input against the tool schema, then runs the tool. */
export function runTool(name, input, ctx) {
  const def = TOOLS.find((t) => t.name === name)
  if (!def || !IMPL[name]) throw new Error(`unknown tool ${name}`)
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('INVALID_JSON: input is not an object')
  const props = def.input_schema.properties
  for (const k of def.input_schema.required) if (input[k] == null) throw new Error(`INVALID_JSON: missing ${k}`)
  for (const [k, v] of Object.entries(input)) {
    const p = props[k]
    if (!p) throw new Error(`INVALID_JSON: unknown field ${k}`)
    if (p.type === 'string' && typeof v !== 'string') throw new Error(`INVALID_JSON: ${k} must be a string`)
    if (p.type === 'integer' && !Number.isInteger(v)) throw new Error(`INVALID_JSON: ${k} must be an integer`)
    if (p.enum && !p.enum.includes(v)) throw new Error(`INVALID_JSON: ${k} must be one of ${p.enum.join(', ')}`)
  }
  return IMPL[name](input, ctx)
}
