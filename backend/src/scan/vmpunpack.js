// Rune's VMProtect unpack (owner, 2026-11-07). A CAPE task with our own analysis package `cg_vmpunpack`
// (sandbox: /opt/CAPEv2/analyzer/windows/modules/packages/cg_vmpunpack.py) runs two open-source unpackers,
// built from reviewed source, inside the guest VM only: never on this server or on the CAPE host, and the
// guest is reverted after the task. VMPStatic never runs the sample; VMProtect-Unpacker unpacks statically,
// and in runtime mode starts the sample suspended in the guest and dumps it from memory. The unpacked
// images come back through cg-files (/package/<task>) and become child jobs of the sample.

import { http, formWith } from './http.js'
import { loadSample, hashes } from './storage.js'
import { TUNNEL_FILES_PORT } from './tunnel.js'
import { startScan } from './jobs.js'
import { childJobs } from './db.js'

const CAPE = () => (process.env.CAPE_URL || '').replace(/\/+$/, '')
const cape = (path, opts = {}) => http(`${CAPE()}${path}`, { ...opts, headers: { Authorization: `Token ${process.env.CAPE_API_KEY}`, ...(opts.headers || {}) } })
const files = (path, opts = {}) => http(`http://127.0.0.1:${TUNNEL_FILES_PORT}${path}`, { ...opts, headers: { Authorization: `Token ${process.env.CAPE_FILES_TOKEN}` }, timeout: 120_000 })
const DONE = ['completed', 'reported']
const FAILED = ['failed_analysis', 'failed_processing', 'failed_reporting']
const WAIT_MS = 12 * 60_000

export const vmpUnpackEnabled = () => !!(process.env.CAPE_URL && process.env.CAPE_API_KEY && process.env.CAPE_FILES_TOKEN)

/** Unpacks the job's sample in the guest; returns the unpacked files (as child jobs) and the tools' logs. */
export async function vmpUnpack(job, { runtime = false, signal } = {}) {
  if (!vmpUnpackEnabled()) throw new Error('vmp_unpack_not_configured')
  const up = await cape('/tasks/create/file/', {
    method: 'POST',
    body: formWith({ package: 'cg_vmpunpack', options: runtime ? 'runtime=1' : '', timeout: runtime ? '150' : '100', enforce_timeout: '1', priority: '2' }, loadSample(job.sha256), 'file', job.file_name),
    timeout: 120_000,
  })
  const task = up?.data?.task_ids?.[0]
  if (!task) throw new Error(up?.error_value || 'vmp_unpack_submit_failed')
  const until = Date.now() + WAIT_MS
  for (;;) {
    if (signal?.aborted) throw new Error('stopped')
    const t = (await cape(`/tasks/view/${task}/`).catch(() => null))?.data
    if (t && DONE.includes(t.status)) break
    if (t && FAILED.includes(t.status)) break // whatever the package uploaded is still there
    if (Date.now() > until) return { task, status: 'timeout', note: 'The sandbox did not finish in time (it may be busy with another analysis).' }
    await new Promise((r) => setTimeout(r, 8000))
  }
  const list = (await files(`/package/${task}`))?.files || []
  const outputs = []
  const logs = {}
  // Logs first: they decide whether an image is worth keeping.
  for (const f of list.filter((x) => x.name.endsWith('.log'))) {
    const text = String(await files(`/package/${task}/${encodeURIComponent(f.name)}`, { raw: true })).trim()
    logs[f.name.replace(/_unpacked\.exe\.log$|_dump\.exe\.log$/, '')] = text.slice(-800)
  }
  for (const f of list.filter((x) => !x.name.endsWith('.log'))) {
    // VMPStatic writes an image even when it found nothing to unpack: that copy is not a new file.
    if (f.name.startsWith('vmpstatic') && /signature not found/i.test(logs.vmpstatic || '') && /no LZMA blocks/i.test(logs.vmpstatic || '')) continue
    const buf = await files(`/package/${task}/${encodeURIComponent(f.name)}`, { raw: true })
    if (!buf?.length) continue
    const sha = hashes(buf).sha256
    if (sha === job.sha256) continue // the tool gave the input back unchanged
    const have = childJobs(job.id).find((c) => c.sha256 === sha)
    const id = have ? have.id : startScan({ keyId: job.key_id, buf, name: `vmp açılmış: ${f.name}`, parentId: job.id })
    outputs.push({ tool: f.name.startsWith('vmpstatic') ? 'VMPStatic' : f.name.includes('runtime') ? 'VMProtect-Unpacker (runtime dump)' : 'VMProtect-Unpacker', size: buf.length, job_id: id })
  }
  return { task, outputs, logs, note: outputs.length ? 'Each unpacked image is a job of its own: use its job_id with decompile / find_strings. Virtualized functions stay virtualized.' : 'No tool produced an unpacked image; see the logs (wrong VMProtect version, not VMProtect, or anti-VM).' }
}
