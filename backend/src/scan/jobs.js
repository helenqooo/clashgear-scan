// Runs one scan job through the layers: file sources in parallel (sandboxes take the longest), then
// network enrichment on the IOCs they found, then family lookup, score and the AI report.
// Every state change is written to the DB, so a restart picks up where it stopped.

import { PROVIDERS, enabled } from './providers/index.js'
import { malpediaFamily } from './providers/intel.js'
import { createJob, getJob, setResult, getResult, listResults, childJobs, finishJob, runningJobIds, getOverride, getAiVerdict, setJobScore, pendingRefs, watchJob, counterToday, bumpCounter, resetResult, setJobSource } from './db.js'
import { capeQueue } from './providers/sandbox.js'
import { saveSample, loadSample, hashes } from './storage.js'
import { analyzeStatic } from './static.js'
import { computeScore } from './score.js'
import { onScanDone, checkAiBudget } from './alerts.js'
import { analystReport } from './ai.js'

const active = new Map()
const hostOf = (u) => { try { return new URL(u).hostname } catch { return '' } }
const PRIVATE_IP = /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|2(?:2[4-9]|[3-5]\d)\.)/
const BENIGN_DOMAIN = /(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|msftncsi\.com|msftconnecttest\.com|digicert\.com|verisign\.com|symantec\.com|sectigo\.com|globalsign\.com|google\.com|gstatic\.com|googleapis\.com|bing\.com|live\.com|office\.com|akamai(edge|hd)?\.net|cloudflare\.com|w3\.org|xmlsoap\.org|openxmlformats\.org|apple\.com|mozilla\.org|msedge\.net|msftauth\.net|msauth\.net|microsoftonline\.com|office\.net|lencr\.org|letsencrypt\.org|usertrust\.com|entrust\.net|godaddy\.com|amazontrust\.com|pki\.goog)$/i
// Not listed on purpose: file hosts malware loves (github, discord cdn, pastebin, dropbox…) stay checked.

/** Stores a new upload and starts its scan. Returns the job id. */
export function startScan({ keyId, buf, name, parentId = null, ip = null, source = null }) {
  const h = hashes(buf)
  saveSample(h.sha256, buf)
  const st = analyzeStatic(buf, name, h)
  const id = createJob({ keyId, parentId, fileName: name, size: buf.length, md5: h.md5, sha1: h.sha1, sha256: h.sha256, staticInfo: st, ip })
  if (source) setJobSource(id, source)
  setResult(id, 'local', 1, { status: 'done', summary: { type: st.type, entropy: st.entropy, packer_hints: st.pe?.packer_hints || [] } })
  for (const p of PROVIDERS) {
    if (p.rootOnly && parentId) continue
    // manual sources (our own CAPE VM) only run when the user opens a live session
    setResult(id, p.id, p.layer, { status: enabled(p) && !p.manual && !(p.needsSource && !source?.url) ? 'queued' : 'disabled' })
  }
  setResult(id, 'claude', 10, { status: process.env.ANTHROPIC_API_KEY ? 'queued' : 'disabled' })
  runJob(id)
  return id
}

/**
 * A scan from a hash alone (nobody had the sample to hand us): every source that can look a hash up runs,
 * the ones that need the file itself are switched off with "no_sample".
 */
export function startHashScan({ keyId, md5, sha1, sha256, size = 0, name, ip = null }) {
  const st = { type: 'unknown', hash_only: true, entropy: null, indicators: {} }
  const id = createJob({ keyId, parentId: null, fileName: name || sha256, size, md5: md5 || '', sha1: sha1 || '', sha256, staticInfo: st, ip })
  setResult(id, 'local', 1, { status: 'not_found', error: 'no_sample' })
  for (const p of PROVIDERS) setResult(id, p.id, p.layer, { status: enabled(p) && !p.manual && !p.needsSource ? 'queued' : 'disabled' })
  setResult(id, 'claude', 10, { status: process.env.ANTHROPIC_API_KEY ? 'queued' : 'disabled' })
  runJob(id)
  return id
}

function errText(e) {
  if (e.status === 401 || e.status === 403) return 'auth'
  if (e.status === 429) return 'rate_limited'
  if (e.message === 'timeout' || e.name === 'TimeoutError') return 'timeout'
  return String(e.message || e).slice(0, 200)
}

async function runProvider(job, p, extra) {
  // Token Tuzağı is driven by honey.js only (it may already be running when the scan starts or resumes)
  if (p.id === 'honey') return
  const prev = getResult(job.id, p.id)
  if (!prev || ['done', 'not_found', 'error', 'disabled'].includes(prev.status)) return
  setResult(job.id, p.id, p.layer, { status: 'running' })
  let fileBuf = null
  const ctx = {
    jobId: job.id,
    sha256: job.sha256,
    sha1: job.sha1,
    md5: job.md5,
    size: job.size,
    name: job.file_name,
    type: job.static?.type,
    ref: prev.ref || null,
    saveRef: (ref) => setResult(job.id, p.id, p.layer, { status: 'running', ref: String(ref) }),
    file: () => {
      if (job.static?.hash_only) throw new Error('no_sample')
      return (fileBuf ||= loadSample(job.sha256))
    },
    isRoot: !job.parent_id,
    source: job.source || null,
    // One child per distinct file (a resumed provider must not add the same one twice).
    addChild: async (buf, name) => {
      const sha = hashes(buf).sha256
      const have = childJobs(job.id).find((c) => c.sha256 === sha)
      return have ? have.id : startScan({ keyId: job.key_id, buf, name, parentId: job.id })
    },
    ...extra,
  }
  try {
    const summary = await p.run(ctx)
    setResult(job.id, p.id, p.layer, summary ? { status: 'done', summary } : { status: 'not_found' })
  } catch (e) {
    if (e.message === 'no_sample') setResult(job.id, p.id, p.layer, { status: 'disabled', error: 'no_sample' })
    else setResult(job.id, p.id, p.layer, { status: 'error', error: errText(e) })
  } finally {
    fileBuf = null
  }
}

function collectIocs(job, results) {
  const ips = new Set(), domains = new Set(), urls = new Set()
  for (const r of results) {
    // URLhaus lists where this exact file was *hosted* (often a legit binary on a malware server),
    // not hosts the file itself contacts, so those never feed the network layer.
    if (r.source === 'urlhaus') continue
    const i = r.summary?.iocs
    if (!i) continue
    for (const x of i.ips || []) ips.add(x)
    for (const x of i.domains || []) domains.add(x)
    for (const x of i.urls || []) urls.add(x)
  }
  // Where a link scan fetched the file from: the download host is checked like any contacted host.
  for (const u of [job.source?.url, job.source?.final_url]) if (u) urls.add(u)
  // Strings from the file are weaker evidence: only used when the sandboxes found nothing.
  const si = job.static?.indicators
  if (si && !ips.size && !domains.size) {
    for (const x of si.ips || []) ips.add(x)
    for (const x of si.urls || []) urls.add(x)
  }
  const clean = (a, f) => [...a].map((x) => String(x).trim()).filter(f).slice(0, 15)
  return {
    ips: clean(ips, (ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !PRIVATE_IP.test(ip)),
    domains: clean(domains, (d) => d.includes('.') && !BENIGN_DOMAIN.test(d)),
    urls: clean(urls, (u) => /^https?:\/\//.test(u) && !!hostOf(u) && !BENIGN_DOMAIN.test(hostOf(u))),
  }
}

/** Starts (or joins) the run of a job; the promise settles when the job is finished. */
export function runJob(id) {
  if (!active.has(id)) active.set(id, doRun(id).finally(() => active.delete(id)))
  return active.get(id)
}

async function doRun(id) {
  try {
    const job = getJob(id)
    if (!job || job.status !== 'running') return

    // Layers 2-8 and 10 (file sources). A source with `after` waits for those to settle first.
    const files = PROVIDERS.filter((p) => p.kind === 'file')
    const runs = new Map()
    for (const p of files.filter((x) => !x.after)) runs.set(p.id, runProvider(job, p))
    for (const p of files.filter((x) => x.after)) {
      runs.set(p.id, Promise.all(p.after.map((a) => runs.get(a))).then(() => runProvider(job, p)))
    }
    await Promise.all(runs.values())

    // Our own CAPE VM steps in when no outside sandbox ran the file (no keys, unsupported type, quota, refusal).
    if (await autoCapeWanted(job)) {
      bumpCounter('capeauto')
      setResult(id, 'cape', 8, { status: 'queued' })
      await runProvider(job, PROVIDERS.find((x) => x.id === 'cape'))
    }

    // Layer 9: network enrichment on what the sandboxes and intel sources saw.
    const iocs = collectIocs(job, listResults(id))
    const iocProviders = PROVIDERS.filter((p) => p.kind === 'ioc')
    if (iocs.ips.length || iocs.domains.length || iocs.urls.length) {
      await Promise.all(iocProviders.map((p) => runProvider(job, p, { iocs })))
    } else {
      for (const p of iocProviders) if (getResult(id, p.id)?.status === 'queued') setResult(id, p.id, p.layer, { status: 'not_found' })
    }

    // Unpacked children finish before the parent is scored (they feed the AI report).
    const kids = childJobs(id)
    await Promise.all(kids.filter((k) => k.status === 'running').map((k) => runJob(k.id)))

    let results = listResults(id)
    const computed = computeScore(results, job.static, { override: getOverride(job.sha256), aiVerdict: getAiVerdict(job.sha256), children: childJobs(id), fileName: job.file_name })

    // Family encyclopedia once a family name is known.
    if (computed.family) {
      try {
        const fam = await malpediaFamily(computed.family)
        if (fam) setResult(id, 'malpedia', 4, { status: 'done', summary: { ...fam, family: computed.family } })
      } catch { /* optional */ }
    }

    results = listResults(id)
    let ai = null
    if (getResult(id, 'claude')?.status === 'queued') {
      setResult(id, 'claude', 10, { status: 'running' })
      try {
        ai = await analystReport({ job, results, computed, children: childJobs(id) })
        setResult(id, 'claude', 10, ai?.skipped ? { status: 'error', error: ai.skipped } : { status: 'done', summary: { verdict: ai.verdict, family: ai.family || null } })
      } catch (e) {
        setResult(id, 'claude', 10, { status: 'error', error: errText(e) })
      }
    }
    finishJob(id, { score: computed.score, verdict: computed.verdict, ai: ai && !ai.skipped ? { ...ai, computed } : { computed } })
    if (!job.parent_id && !job.static?.hash_only) watchJob(id, job.created_at)
    onScanDone(id)
    checkAiBudget()
  } catch (e) {
    console.error('scan job failed', id, e)
  }
}

/**
 * A live sandbox session ran this job's file as CAPE task `taskId`: once CAPE reports it, its behaviour,
 * network and captured files join the report (captured files as child scans) and the verdict is recomputed.
 */
export async function attachLiveRun(jobId, taskId) {
  const job = getJob(jobId)
  const p = PROVIDERS.find((x) => x.id === 'cape')
  if (!job || !p || job.parent_id) return
  setResult(jobId, p.id, p.layer, { status: 'queued', ref: String(taskId) })
  await runProvider(job, p)
  await Promise.all(childJobs(jobId).filter((k) => k.status === 'running').map((k) => runJob(k.id)))
  rescoreJob(jobId)
}

// Sandboxes that run the file on their own machines; CAPE is ours.
const OUTSIDE_SANDBOXES = ['triage', 'hybrid_sandbox', 'threatzone', 'joe', 'vmray', 'anyrun']
const RUNNABLE = /^(pe|msi|lnk|powershell|javascript|vbscript|batch|hta|wsf|ole|ooxml|rtf|jar|python)$/
async function autoCapeWanted(job) {
  if (job.parent_id || job.static?.hash_only || process.env.SCAN_CAPE_AUTO === '0') return false
  const p = PROVIDERS.find((x) => x.id === 'cape')
  if (!p || !enabled(p) || !RUNNABLE.test(job.static?.type || '')) return false
  const cur = getResult(job.id, 'cape')
  if (cur && !['disabled', 'not_found', 'error'].includes(cur.status)) return false
  if (cur?.status === 'error' && cur.error !== 'no_sample') return false
  const ran = listResults(job.id).some((r) => OUTSIDE_SANDBOXES.includes(r.source) && r.status === 'done' && ((r.summary?.signatures || []).length || r.summary?.score != null))
  if (ran) return false
  if (counterToday('capeauto') >= Number(process.env.SCAN_CAPE_AUTO_DAILY || 60)) return false
  const q = await capeQueue()
  return !!q && q.pending < Number(process.env.SCAN_CAPE_AUTO_QUEUE || 4)
}

/** Runs the given hash-lookup sources of a finished job again (the 1/3/7-day re-checks) and rescores it. */
export async function recheckJob(id, sources) {
  const job = getJob(id)
  if (!job || job.status !== 'done') return null
  const list = PROVIDERS.filter((p) => sources.includes(p.id) && enabled(p) && !p.manual)
  for (const p of list) resetResult(id, p.id, p.layer)
  await Promise.all(list.map((p) => runProvider({ ...job, static: { ...(job.static || {}), hash_only: true } }, p)))
  return rescoreJob(id)
}

/** Recomputes a finished job's verdict (after an owner override); the AI text is left as it was. */
export function rescoreJob(id) {
  const job = getJob(id)
  if (!job || job.status !== 'done') return null
  const computed = computeScore(listResults(id), job.static, { override: getOverride(job.sha256), aiVerdict: getAiVerdict(job.sha256), children: childJobs(id), fileName: job.file_name })
  setJobScore(id, { score: computed.score, verdict: computed.verdict, computed })
  return computed
}

/** After a restart: continue every job that was still running. */
export function resumeJobs() {
  for (const id of runningJobIds()) runJob(id)
  // after a short wait: the SSH tunnel to the CAPE box comes up a few seconds after boot
  setTimeout(() => {
    for (const { job_id, ref } of pendingRefs('cape')) attachLiveRun(job_id, ref).catch((e) => console.error('live attach resume failed', job_id, e))
  }, 15_000)
}
