// ClashGear Scan routes: key login, upload, reports (/api/scan/*) and key admin (/api/admin/scan/*).

import multipart from '@fastify/multipart'
import { createHash, timingSafeEqual } from 'node:crypto'
import { config } from '../config.js'
import { sessionValid } from '../store.js'
import {
  createKey, findKey, getKey, keyUsable, listKeys, updateKey, markKeyUsed, usedToday,
  createScanSession, sessionKey, destroyScanSession, sweepScanSessions,
  getJob, listJobs, listAllJobs, listResults, childJobs, existingJob, samplesOlderThan,
  createChat, getChat, saveChat, listChats, listAllChats, reusableAnalysis, deleteChat, strikesOf, lastStrike, listStrikes, pardon, NYX_BAN_AT, chatTurnsToday, recordChatTurn, ipTurnsToday, recordIpTurn,
  SELF_LABEL, createSelfKey, selfKeysByIp, selfKeysTotal, selfScansByIp, selfScansTotal, resetFreeLimits, clearAnalysisReuse, setJobPublic, closedUntil,
  createFpReport, fpReportOf, listFpReports, getFpReport, decideFpReport, setOverride, deleteOverride, listOverrides, jobsWithSha,
  liveToday, recordLive,
  setJobSource, watchOf, markWatchSeen, unseenWatchChanges, setLabel, deleteLabel, allLabels, bumpCounter,
} from './db.js'
import { fetchLink, LinkError, hashKind, resolveHash, downloadByHash, similarFiles, diffJobs, startWatcher, scanHealth, runRegression } from './extras.js'
import { maskSecret } from './providers/local.js'
import { badgeSvg, badgePng, cardPng, cardSvg, shareSnippets } from './share.js'
import { startTunnel, tunnelState } from './tunnel.js'
import { isMasked, describeMask } from './ipguard.js'
import { checkTurnstile, TURNSTILE_SITE_KEY, turnstileOn, checkSignature, sigKeyFor, sha256hex } from './turnstile.js'
import { recordDevice, checkReturn, touchDevice, SRV_COOKIE, newSrvId } from './devices.js'
import { openSealed } from './seal.js'
import { botScore, agentSignatures, BOT_BLOCK_AT } from './botcheck.js'
import { liveEnabled, startLive, getLive, liveStatus, stopLive, attachLiveSocket, LIVE_SECONDS } from './live.js'
import { startTurn, isTurnRunning, subscribeTurn, stopTurn, resumeChats, viewChat, viewEvent } from './chat.js'
import { onUpload, onLimit, onLoginBlocked, onChatMessage, onFalsePositive, onVpnBlocked, onAutomation, onMcpLog } from './alerts.js'
import { startCrowdsecWatch } from './crowdsec.js'
import { deleteSample } from './storage.js'
import { startScan, startHashScan, resumeJobs, rescoreJob, attachLiveRun } from './jobs.js'
import { honeyEnabled, startHoney, latestRun, honeyToday, trapAttempt, HONEY_SECONDS, resumeHoney } from './honey.js'
import { describeProviders, LAYERS } from './providers/index.js'

const COOKIE = 'cg_scan'
const ADMIN_COOKIE = 'cg_sess'
const MAX_BYTES = 100 * 1024 * 1024
const TTL = 1000 * 60 * 60 * 24 * 7
const RETENTION = 1000 * 60 * 60 * 24 * 30

// Self-service keys: anyone can mint one, the limits sit on the visitor's IP and on the day's total
// (VirusTotal's free tier is the bottleneck: roughly 30-40 full scans a day for everyone together).
const envInt = (name, dflt) => Math.max(0, parseInt(process.env[name] ?? '', 10) || dflt)
const SELF = {
  quota: envInt('SCAN_SELF_QUOTA', 3), // scans per key per day
  ipScans: envInt('SCAN_SELF_IP_DAILY', 5), // scans per IP per day across its self keys
  ipKeys: envInt('SCAN_SELF_KEYS_PER_IP', 1), // new keys per IP per 24 h
  dayKeys: envInt('SCAN_SELF_KEYS_DAILY', 200), // new keys per 24 h, everyone
  dayScans: envInt('SCAN_SELF_SCANS_DAILY', 30), // self-key scans per day, everyone
}

// The page's automatic first prompt (ScanChat DEFAULT_PROMPT) starts with this.
const AUTO_MARKER = 'Bu dosyayı analiz et:'

const ok = (data) => ({ ok: true, data })
const bad = (reply, status, error) => reply.code(status).send({ ok: false, error })

// Key login throttle: 5 failures per IP per 15 min.
const fails = new Map()
const blocked = (ip) => {
  const now = Date.now()
  const mine = (fails.get(ip) || []).filter((t) => now - t < 15 * 60_000)
  if (mine.length) fails.set(ip, mine)
  else fails.delete(ip)
  return mine.length >= 5
}

function publicJob(j) {
  if (!j) return null
  const { key_id, ip, ...rest } = j
  return rest
}

export async function registerScan(app) {
  await app.register(multipart, { limits: { fileSize: MAX_BYTES, files: 1, fields: 4, parts: 6 } })
  // Our CAPE box is reached through an SSH tunnel (API + guacd); the live screen rides a WebSocket.
  startTunnel()
  attachLiveSocket(app.server)

  const cookieOpts = { httpOnly: true, secure: !config.insecureCookies, sameSite: 'strict', path: '/', maxAge: Math.floor(TTL / 1000) }
  const keyOf = (req) => sessionKey(req.cookies?.[COOKIE])
  // Free-tier actions are refused through VPNs, proxies, relays and Tor (limits are per IP); owner keys are exempt.
  const masked = async (req, reply, k, action) => {
    if (k?.label === 'owner') return false
    const m = await isMasked(req.ip)
    if (!m) return false
    onVpnBlocked({ ip: req.ip, key: k, info: m, action })
    reply.code(403).send({ ok: false, error: 'vpn_blocked', vpn: describeMask(m) })
    return true
  }
  // Free Nyx messages and new keys only from the site's own page: browsers stamp a same-origin fetch with
  // Origin and Sec-Fetch-Site, plain scripts and API relays (someone fed Nyx to an IDE as an OpenAI endpoint,
  // 2026-11-05) usually don't. Spoofable, so only a first gate; owner keys are exempt.
  const fromSite = (req) => req.headers.origin === config.publicUrl && req.headers['sec-fetch-site'] === 'same-origin'
  const notFromSite = (req, reply, what) => {
    if (fromSite(req)) return false
    req.log.warn({ ip: req.ip, what, origin: req.headers.origin, sfs: req.headers['sec-fetch-site'], ua: String(req.headers['user-agent'] || '').slice(0, 120) }, 'scan: non-browser request refused')
    bad(reply, 403, 'browser_required')
    return true
  }
  // ...and the real gate: a Turnstile token (body.cf_token) minted by Cloudflare's challenge in the page.
  const noHuman = async (req, reply, action, cdata = null) => {
    const v = await checkTurnstile(req.body?.cf_token, req.ip, action, cdata)
    if (v === 'ok') return false
    req.log.warn({ ip: req.ip, action, v }, 'scan: turnstile refused')
    bad(reply, 403, 'captcha_required')
    return true
  }
  // ...the page's signature over the message (see turnstile.js)...
  const unsigned = (req, reply) => {
    const v = checkSignature(req, req.cookies?.[COOKIE])
    if (v === 'ok') return false
    req.log.warn({ ip: req.ip, v }, 'scan: unsigned Nyx request refused')
    bad(reply, 403, 'browser_required')
    return true
  }
  // ...and how it is used: people type short questions a few seconds apart, IDE relays fire long prompts
  // back to back. Free messages are capped in length and spaced out per key and per IP.
  const FREE_MSG_MAX = Number(process.env.SCAN_FREE_MSG_MAX || 3000)
  const FREE_MSG_GAP = Number(process.env.SCAN_FREE_MSG_GAP_MS || 8000)
  // Fields of the OpenAI / Anthropic chat APIs that our own page never sends to Nyx.
  const API_FIELDS = ['system', 'tools', 'tool_choice', 'functions', 'function_call', 'messages', 'role', 'model', 'prompt', 'max_tokens', 'temperature', 'stream', 'response_format']
  const lastMsgAt = new Map() // 'k:<key>' / 'i:<ip>' -> time of the last accepted free message
  setInterval(() => { const t = Date.now() - 60_000; for (const [k, v] of lastMsgAt) if (v < t) lastMsgAt.delete(k) }, 60_000).unref()
  const tooFast = (req, reply, k) => {
    const t = Date.now()
    const last = Math.max(lastMsgAt.get(`k:${k.id}`) || 0, lastMsgAt.get(`i:${req.ip}`) || 0)
    if (t - last < FREE_MSG_GAP) { bad(reply, 429, 'too_fast'); return true }
    lastMsgAt.set(`k:${k.id}`, t); lastMsgAt.set(`i:${req.ip}`, t)
    return false
  }
  // Closed hours (owner, 2026-11-06): until scan_settings.closed_until every /api/scan call except the page's
  // info/session/login/logout answers 503 scan_closed; owner keys keep working. Reopens on its own.
  const OPEN_WHEN_CLOSED = new Set(['/api/scan/info', '/api/scan/session', '/api/scan/login', '/api/scan/logout', '/api/scan/panel/login'])
  app.addHook('preHandler', async (req, reply) => {
    const path = req.url.split('?')[0]
    if (!path.startsWith('/api/scan/') || OPEN_WHEN_CLOSED.has(path)) return
    const until = closedUntil()
    if (!until || keyOf(req)?.label === 'owner') return
    return reply.code(503).send({ ok: false, error: 'scan_closed', opens_at: until })
  })
  const isAdmin = (req) => sessionValid(req.cookies?.[ADMIN_COOKIE])
  const guard = async (req, reply) => {
    const k = keyOf(req)
    if (!k) return bad(reply, 401, 'not_authenticated')
    req.scanKey = k
  }

  /* -------------------------------------------------------------- public */

  // Internal: the public 21st MCP front (cg-mcp, same machine, direct to this port) reports its calls here.
  // Anything that came through the proxy (forwarded headers) or lacks the shared secret gets exactly the
  // answer an unknown /api/x/y path gets (400 invalid_param), so the route's existence is not revealed.
  app.post('/api/internal/mcp-log', async (req, reply) => {
    const want = Buffer.from(process.env.MCP_LOG_SECRET || '')
    const got = Buffer.from(String(req.headers['x-mcp-secret'] || ''))
    if (req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip'] || !want.length || got.length !== want.length || !timingSafeEqual(got, want)) return reply.code(400).send({ ok: false, error: 'invalid_param' })
    const lines = Array.isArray(req.body?.lines) ? req.body.lines.filter((l) => typeof l === 'string').slice(0, 200) : []
    if (lines.length) onMcpLog(lines)
    return { ok: true }
  })

  // What the landing page shows: layers and how many sources are switched on.
  app.get('/api/scan/info', async () => {
    const providers = describeProviders()
    return ok({ layers: LAYERS, providers, enabled: providers.filter((p) => p.enabled).length, total: providers.length, max_bytes: MAX_BYTES, turnstile_site_key: turnstileOn() ? TURNSTILE_SITE_KEY : null, closed_until: closedUntil() || null })
  })

  app.post('/api/scan/login', async (req, reply) => {
    if (blocked(req.ip)) { onLoginBlocked(req.ip); return bad(reply, 429, 'too_many_attempts') }
    // Same clean-up as the page: stray quotes/backticks, invisible characters, a capitalised "Cgs_".
    let key = String(req.body?.key || '').replace(/[\s​-‍﻿`'"“”‘’]/g, '').replace(/^cgs_/i, 'cgs_')
    // Plain shared words ("cheatglobal") are matched case-insensitively; cgs_ keys stay exact.
    if (!key.startsWith('cgs_')) key = key.toLowerCase()
    // Only key-shaped input ever reaches the lookup (letters, digits, _ and -, 6-100 long); the rest counts as a miss.
    const row = /^[A-Za-z0-9_-]{6,100}$/.test(key) ? findKey(key) : null
    if (!keyUsable(row)) {
      fails.set(req.ip, [...(fails.get(req.ip) || []), Date.now()])
      await new Promise((r) => setTimeout(r, 500))
      return bad(reply, 401, row ? 'key_inactive' : 'invalid_key')
    }
    fails.delete(req.ip)
    if (closedUntil() && row.label !== 'owner') return reply.code(503).send({ ok: false, error: 'scan_closed', opens_at: closedUntil() })
    if (await masked(req, reply, row, 'login')) return
    markKeyUsed(row.id)
    reply.setCookie(COOKIE, createScanSession(row.id, TTL), cookieOpts)
    return ok({ authed: true })
  })

  // Self-service: mint a personal key, sign the visitor in with it and show it once.
  app.post('/api/scan/keys/new', async (req, reply) => {
    if (notFromSite(req, reply, 'key')) return
    if (await noHuman(req, reply, 'key')) return
    if (await masked(req, reply, null, 'key')) return
    const day = Date.now() - 86400_000
    if (selfKeysByIp(req.ip, day) >= SELF.ipKeys) { onLimit({ key: { label: SELF_LABEL }, ip: req.ip, kind: 'self_key_ip' }); return bad(reply, 429, 'key_limit_ip') }
    if (selfKeysTotal(day) >= SELF.dayKeys) { onLimit({ key: { label: SELF_LABEL }, ip: req.ip, kind: 'self_key_day' }); return bad(reply, 429, 'key_limit_day') }
    const { id, key } = createSelfKey({ ip: req.ip, dailyQuota: SELF.quota })
    markKeyUsed(id)
    reply.setCookie(COOKIE, createScanSession(id, TTL), cookieOpts)
    return ok({ key, quota: SELF.quota })
  })

  startCrowdsecWatch()

  // Device report from the page (lib/fp.ts) for free keys: stored, linked to other keys, and Discord is told
  // when someone Nyx flagged comes back on a new key. The server also keeps its own httpOnly device cookie,
  // which survives the page's storage being wiped.
  app.post('/api/scan/fp', { bodyLimit: 32_768 }, async (req, reply) => {
    const k = keyOf(req)
    if (!k) return bad(reply, 401, 'not_authenticated')
    if (k.label === 'owner' || !fromSite(req)) return ok({})
    let srvId = /^[0-9a-f]{32}$/.test(String(req.cookies?.[SRV_COOKIE] || '')) ? req.cookies[SRV_COOKIE] : null
    if (!srvId) {
      srvId = newSrvId()
      reply.setCookie(SRV_COOKIE, srvId, { httpOnly: true, secure: !config.insecureCookies, sameSite: 'lax', path: '/', maxAge: 2 * 365 * 86400 })
    }
    const rec = recordDevice({ keyId: k.id, ip: req.ip, srvId, fp: req.body || {} })
    checkReturn(rec, k).catch((e) => req.log.warn({ err: String(e?.message || e) }, 'scan: device check failed'))
    return ok({})
  })

  app.post('/api/scan/logout', async (req, reply) => {
    destroyScanSession(req.cookies?.[COOKIE])
    reply.clearCookie(COOKIE, { path: '/' })
    return ok({ authed: false })
  })

  app.get('/api/scan/session', async (req) => {
    const k = keyOf(req)
    if (!k) return ok({ authed: false })
    // sig_key: the page signs free Nyx messages with it (only same-origin pages get it).
    const sig_key = !isOwner(k) && req.headers['sec-fetch-site'] === 'same-origin' ? sigKeyFor(req.cookies?.[COOKIE]) : null
    return ok({ authed: true, label: k.label, shared: !!k.shared, quota: k.daily_quota, used: usedToday(k.id), expires_at: k.expires_at, sig_key, now: Date.now() })
  })

  /* ------------------------------------------------------------ key holders */

  // "Honeypot" ticked on the upload form: the Token Tuzağı run starts next to the scan (same daily limit as the button).
  const honeyOnUpload = (req, k, jobId) => {
    if (!honeyEnabled() || !tunnelState.up) return 'unavailable'
    const prev = latestRun(jobId)
    if (prev && ['queued', 'running'].includes(prev.status)) return 'running'
    if (prev?.status === 'done') return 'running'
    if (honeyToday(k.id) >= honeyLimit(k)) { onLimit({ key: k, ip: req.ip, kind: 'honey' }); return 'quota' }
    startHoney(getJob(jobId), k.id).catch((e) => req.log.error(e, 'honey on upload failed'))
    return 'started'
  }
  // Every new scan (upload, link, hash) spends the same quota.
  const scanRefused = async (req, reply, k, action) => {
    if (await masked(req, reply, k, action)) return true
    if (usedToday(k.id) >= k.daily_quota) { onLimit({ key: k, ip: req.ip, kind: 'scan_quota' }); bad(reply, 429, 'quota_exceeded'); return true }
    if (k.label === SELF_LABEL) {
      if (selfScansByIp(req.ip) >= SELF.ipScans) { onLimit({ key: k, ip: req.ip, kind: 'self_scan_ip' }); bad(reply, 429, 'quota_exceeded'); return true }
      if (selfScansTotal() >= SELF.dayScans) { onLimit({ key: k, ip: req.ip, kind: 'self_scan_day' }); bad(reply, 429, 'service_busy'); return true }
    }
    return false
  }
  app.post('/api/scan/upload', { preHandler: guard }, async (req, reply) => {
    const k = req.scanKey
    if (await scanRefused(req, reply, k, 'upload')) return
    const part = await req.file()
    if (!part) return bad(reply, 400, 'no_file')
    const buf = await part.toBuffer().catch(() => null)
    if (!buf || part.file.truncated) return bad(reply, 413, 'file_too_large')
    if (!buf.length) return bad(reply, 400, 'empty_file')
    const name = String(part.filename || 'sample').replace(/[\\/\0-\x1f]/g, '_').slice(0, 200) || 'sample'
    const rescan = part.fields?.rescan?.value === '1'

    const wantHoney = part.fields?.honey?.value === '1'

    const sha256 = createHash('sha256').update(buf).digest('hex')
    const prev = existingJob(k.id, sha256)
    if (prev && !rescan) return ok({ id: prev, cached: true, honey: wantHoney ? honeyOnUpload(req, k, prev) : null })
    markKeyUsed(k.id)
    const id = startScan({ keyId: k.id, buf, name, ip: req.ip })
    onUpload({ jobId: id, key: k, ip: req.ip })
    return ok({ id, cached: false, honey: wantHoney ? honeyOnUpload(req, k, id) : null })
  })

  // Link scan: the CAPE box downloads the file (MediaFire / Drive / Dropbox / GitHub pages are followed to the file).
  const linkBusy = new Map() // key id -> running link fetches
  app.post('/api/scan/link', { preHandler: guard }, async (req, reply) => {
    const k = req.scanKey
    const url = String(req.body?.url || '').trim().slice(0, 2000)
    if (!/^https?:\/\//i.test(url)) return bad(reply, 400, 'bad_url')
    if (await scanRefused(req, reply, k, 'link')) return
    if ((linkBusy.get(k.id) || 0) >= 2) return bad(reply, 429, 'too_fast')
    linkBusy.set(k.id, (linkBusy.get(k.id) || 0) + 1)
    let got
    try {
      got = await fetchLink(url)
    } catch (e) {
      if (e instanceof LinkError) return reply.code(422).send({ ok: false, error: e.code, detail: e.detail || null })
      req.log.error(e, 'link fetch failed')
      return bad(reply, 502, 'fetch_failed')
    } finally {
      linkBusy.set(k.id, (linkBusy.get(k.id) || 1) - 1)
    }
    const sha256 = createHash('sha256').update(got.buf).digest('hex')
    const prev = existingJob(k.id, sha256)
    if (prev && req.body?.rescan !== true) { setJobSource(prev, got.source); return ok({ id: prev, cached: true, name: got.name }) }
    markKeyUsed(k.id)
    bumpCounter('linkscan')
    const id = startScan({ keyId: k.id, buf: got.buf, name: got.name, ip: req.ip, source: got.source })
    onUpload({ jobId: id, key: k, ip: req.ip })
    return ok({ id, cached: false, name: got.name, honey: req.body?.honey === true ? honeyOnUpload(req, k, id) : null })
  })

  // Hash scan: MD5 / SHA-1 / SHA-256. With a copy from MalShare every layer runs; otherwise only hash lookups.
  app.post('/api/scan/hash', { preHandler: guard }, async (req, reply) => {
    const k = req.scanKey
    const [kind, h] = hashKind(req.body?.hash)
    if (!kind) return bad(reply, 400, 'bad_hash')
    const own = listJobs(k.id, 500).find((j) => j[kind] === h)
    if (own) return ok({ id: own.id, cached: true })
    if (await scanRefused(req, reply, k, 'hash')) return
    const info = await resolveHash(h)
    if (!info?.sha256) return reply.code(404).send({ ok: false, error: 'hash_unknown' })
    const again = existingJob(k.id, info.sha256)
    if (again) return ok({ id: again, cached: true })
    markKeyUsed(k.id)
    bumpCounter('hashscan')
    const dl = await downloadByHash(info.sha256)
    const name = info.name || info.sha256
    const id = dl ? startScan({ keyId: k.id, buf: dl.buf, name, ip: req.ip }) : startHashScan({ keyId: k.id, ...info, name, ip: req.ip })
    setJobSource(id, { hash: h, hash_kind: kind, resolved_by: info.from, sample: dl?.from || null, at: Date.now() })
    onUpload({ jobId: id, key: k, ip: req.ip })
    return ok({ id, cached: false, full: !!dl })
  })

  app.get('/api/scan/jobs', { preHandler: guard }, async (req) => {
    const changed = new Set(unseenWatchChanges(req.scanKey.id))
    return ok({ jobs: listJobs(req.scanKey.id, 50).map((j) => ({ ...publicJob(j), watch_changed: changed.has(j.id) })) })
  })

  // Owner only: everyone's scans (with key label and uploader IP) for review and abuse checks.
  app.get('/api/scan/jobs-all', { preHandler: guard }, async (req, reply) => {
    if (req.scanKey.label !== 'owner') return bad(reply, 403, 'forbidden')
    const q = String(req.query?.q || '').trim().slice(0, 100)
    return ok({ jobs: listAllJobs(Math.min(300, Number(req.query?.limit) || 150), q) })
  })

  // A report is visible to the key that made it and to the shop admin, and to anyone once it is shared
  // (a shared report's unpacked/dropped child files come with it).
  const mayEdit = (req, job) => {
    const k = keyOf(req)
    return isAdmin(req) || !!(k && (k.id === job.key_id || isOwner(k)))
  }
  const rootOf = (job) => (job.parent_id ? getJob(job.parent_id) || job : job)
  app.get('/api/scan/jobs/:id', async (req, reply) => {
    const job = getJob(req.params.id)
    if (!job) return bad(reply, 404, 'not_found')
    const root = rootOf(job)
    const mine = mayEdit(req, job)
    const shared = !!root.public
    if (!mine && !shared) return bad(reply, 404, 'not_found')
    // Webhooks and bot tokens the extractor found are shown in full to the owner only (anyone holding one can delete or spam it).
    const full = isAdmin(req) || keyOf(req)?.label === 'owner'
    const results = listResults(job.id).map(({ ref, ...r }) => {
      if (full || r.source !== 'cgstatic' || !r.summary?.stealer?.exfil?.length) return r
      return { ...r, summary: { ...r.summary, stealer: { ...r.summary.stealer, exfil: r.summary.stealer.exfil.map((e) => ({ ...e, value: maskSecret(e.kind, e.value), masked: true })) } } }
    })
    const children = childJobs(job.id).map((c) => ({ id: c.id, file_name: c.file_name, sha256: c.sha256, size: c.size, status: c.status, score: c.score, verdict: c.verdict, type: c.static?.type }))
    const watch = job.parent_id ? null : watchOf(job.id)
    if (watch && mine && !watch.seen && keyOf(req)?.id === job.key_id) markWatchSeen(job.id)
    return ok({ job: { ...publicJob(job), public: shared }, results, children, layers: LAYERS, mine, share_root: root.id, fp_report: mine ? fpReportOf(job.id) : null, watch, share: shared ? shareSnippets(root) : null })
  })

  // Files close to this one among everything scanned (others' files without name or link).
  app.get('/api/scan/jobs/:id/similar', async (req, reply) => {
    const job = getJob(req.params.id)
    if (!job) return bad(reply, 404, 'not_found')
    const root = rootOf(job)
    if (!mayEdit(req, job) && !root.public) return bad(reply, 404, 'not_found')
    const k = keyOf(req)
    return ok({ similar: await similarFiles(job, { viewerKeyId: k?.id || null, owner: isAdmin(req) || k?.label === 'owner' }) })
  })

  // urlscan.io screenshot of a link scan's page, served from here (the site's CSP only allows its own images).
  const shots = new Map()
  app.get('/api/scan/jobs/:id/screenshot', async (req, reply) => {
    const job = getJob(req.params.id)
    if (!job || (!mayEdit(req, job) && !rootOf(job).public)) return bad(reply, 404, 'not_found')
    const url = listResults(job.id).find((r) => r.source === 'link_rep')?.summary?.screenshot
    if (!url || !/^https:\/\/urlscan\.io\/screenshots\/[0-9a-f-]{36}\.png$/.test(url)) return bad(reply, 404, 'not_found')
    let buf = shots.get(url)
    if (!buf) {
      const r = await fetch(url, { headers: { 'API-Key': process.env.URLSCAN_API_KEY || '' }, signal: AbortSignal.timeout(20_000) }).catch(() => null)
      if (!r?.ok) return bad(reply, 404, 'not_found')
      buf = Buffer.from(await r.arrayBuffer())
      shots.set(url, buf)
      if (shots.size > 100) shots.delete(shots.keys().next().value)
    }
    return reply.header('Cache-Control', 'private, max-age=3600').type('image/png').send(buf)
  })

  // What changed between two scans (an older and a newer version); both must be visible to the caller.
  app.get('/api/scan/diff/:a/:b', async (req, reply) => {
    const a = getJob(req.params.a), b = getJob(req.params.b)
    if (!a || !b) return bad(reply, 404, 'not_found')
    const can = (j) => mayEdit(req, j) || !!rootOf(j).public
    if (!can(a) || !can(b)) return bad(reply, 404, 'not_found')
    const [older, newer] = a.created_at <= b.created_at ? [a, b] : [b, a]
    return ok(diffJobs(older, newer))
  })

  // Report badge for forum posts: only for shared reports. PNG for forums that refuse SVG images.
  // The id and extension come from the raw URL: the global param guard refuses dots in route params.
  // Badge (440×68) and report card (1000×520) of a shared report, for forum posts.
  const shareImage = (kind) => async (req, reply) => {
    const m = String(req.url.split('?')[0]).match(/^\/api\/scan\/(?:badge|card)\/([0-9a-f]{24})\.(svg|png)$/)
    const job = m ? getJob(m[1]) : null
    if (!job || job.parent_id || !job.public) return reply.code(404).type('text/plain').send('not found')
    reply.header('Cache-Control', 'public, max-age=300').header('Access-Control-Allow-Origin', '*').header('X-Content-Type-Options', 'nosniff')
    if (m[2] === 'svg') return reply.type('image/svg+xml; charset=utf-8').send(kind === 'card' ? cardSvg(job) : badgeSvg(job))
    return reply.type('image/png').send(kind === 'card' ? cardPng(job) : badgePng(job))
  }
  app.get('/api/scan/badge/*', shareImage('badge'))
  app.get('/api/scan/card/*', shareImage('card'))

  // The forum post / badge kit of a shared report, for its share menu.
  app.get('/api/scan/jobs/:id/share-kit', async (req, reply) => {
    const job = getJob(req.params.id)
    if (!job || job.parent_id || !mayEdit(req, job)) return bad(reply, 404, 'not_found')
    if (!job.public) return bad(reply, 409, 'not_shared')
    return ok(shareSnippets(job))
  })

  // Share switch: the key that made the report, owner keys and the admin turn the public link on or off.
  app.post('/api/scan/jobs/:id/share', async (req, reply) => {
    const job = getJob(req.params.id)
    if (!job || !mayEdit(req, job)) return bad(reply, 404, 'not_found')
    const root = rootOf(job)
    setJobPublic(root.id, req.body?.public === true)
    return ok({ id: root.id, public: req.body?.public === true })
  })

  /* ------------------------------------------------------- live sandbox */

  // Run your own file in the CAPE VM and drive the desktop. Free keys get SCAN_LIVE_DAILY sessions a day.
  const liveLimit = (k) => (isOwner(k) ? Infinity : Number(process.env.SCAN_LIVE_DAILY ?? 2))
  app.post('/api/scan/jobs/:id/live', { preHandler: guard }, async (req, reply) => {
    const k = req.scanKey
    const job = getJob(req.params.id)
    if (!job || !(job.key_id === k.id || isOwner(k))) return bad(reply, 404, 'not_found')
    if (await masked(req, reply, k, 'live')) return
    if (!liveEnabled() || !tunnelState.up) return bad(reply, 503, 'live_unavailable')
    if (liveToday(k.id) >= liveLimit(k)) { onLimit({ key: k, ip: req.ip, kind: 'live' }); return bad(reply, 429, 'live_quota_exceeded') }
    const s = await startLive({ job, keyId: k.id }).catch((e) => { req.log.error(e); return null })
    if (!s) return bad(reply, 502, 'live_submit_failed')
    recordLive(k.id)
    // When the session's CAPE task is reported, its findings join this report and the verdict updates.
    attachLiveRun(job.id, s.taskId).catch((e) => req.log.error(e, 'live result attach failed'))
    return ok({ id: s.id, seconds: LIVE_SECONDS })
  })
  const myLive = (req) => { const s = getLive(req.params.lid); return s && (s.keyId === req.scanKey.id) ? s : null }
  app.get('/api/scan/live/:lid', { preHandler: guard }, async (req, reply) => {
    const s = myLive(req)
    return s ? ok(await liveStatus(s)) : bad(reply, 404, 'not_found')
  })
  app.post('/api/scan/live/:lid/stop', { preHandler: guard }, async (req, reply) => {
    const s = myLive(req)
    if (!s) return bad(reply, 404, 'not_found')
    await stopLive(s)
    return ok({ status: 'ended' })
  })
  app.get('/api/scan/live-info', { preHandler: guard }, async (req) => ({ ok: true, data: {
    available: liveEnabled() && tunnelState.up, seconds: LIVE_SECONDS,
    left: Number.isFinite(liveLimit(req.scanKey)) ? Math.max(0, liveLimit(req.scanKey) - liveToday(req.scanKey.id)) : null,
  } }))

  /* ------------------------------------------------------- Token Tuzağı */

  // Run the file in our CAPE VM inside a profile full of fake accounts (honey.js). Free keys get SCAN_HONEY_DAILY a day.
  const honeyLimit = (k) => (isOwner(k) ? Infinity : Number(process.env.SCAN_HONEY_DAILY ?? 2))
  app.post('/api/scan/jobs/:id/honey', { preHandler: guard }, async (req, reply) => {
    const k = req.scanKey
    const job = getJob(req.params.id)
    if (!job || !(job.key_id === k.id || isOwner(k))) return bad(reply, 404, 'not_found')
    if (await masked(req, reply, k, 'honey')) return
    if (!honeyEnabled() || !tunnelState.up) return bad(reply, 503, 'honey_unavailable')
    const prev = latestRun(job.id)
    if (prev && ['queued', 'running'].includes(prev.status)) return ok({ status: prev.status, task: prev.task_id })
    if (honeyToday(k.id) >= honeyLimit(k)) { onLimit({ key: k, ip: req.ip, kind: 'honey' }); return bad(reply, 429, 'honey_quota_exceeded') }
    const run = await startHoney(job, k.id).catch((e) => { req.log.error(e, 'honey submit failed'); return null })
    if (!run) return bad(reply, 502, 'honey_submit_failed')
    return ok({ status: run.status, task: run.task_id, seconds: HONEY_SECONDS })
  })
  app.get('/api/scan/honey-info', { preHandler: guard }, async (req) => ok({
    available: honeyEnabled() && tunnelState.up, seconds: HONEY_SECONDS,
    left: Number.isFinite(honeyLimit(req.scanKey)) ? Math.max(0, honeyLimit(req.scanKey) - honeyToday(req.scanKey.id)) : null,
  }))

  // The trap login (/panel/giris on the shop): every answer is "wrong password", after a human-looking pause.
  // A bait username/password from a Token Tuzağı run means a stealer's loot reached someone who tried it.
  const trapTries = new Map() // ip -> times
  setInterval(() => { const t = Date.now() - 600_000; for (const [ip, a] of trapTries) { const f = a.filter((x) => x > t); if (f.length) trapTries.set(ip, f); else trapTries.delete(ip) } }, 60_000).unref()
  app.post('/api/scan/panel/login', { bodyLimit: 4096 }, async (req, reply) => {
    const tries = (trapTries.get(req.ip) || []).concat(Date.now())
    trapTries.set(req.ip, tries)
    if (tries.length <= 20) {
      await trapAttempt({ user: req.body?.username, pass: req.body?.password, ip: req.ip, country: String(req.headers['cf-ipcountry'] || '').slice(0, 4), ua: req.headers['user-agent'] }).catch((e) => req.log.error(e, 'trap attempt'))
    }
    await new Promise((r) => setTimeout(r, 700 + Math.random() * 700))
    return reply.code(401).send({ ok: false, error: 'invalid_credentials' })
  })

  // "Yanlış alarm bildir": the key holder flags a verdict; the owner decides in the admin panel.
  app.post('/api/scan/jobs/:id/false-positive', { preHandler: guard }, async (req, reply) => {
    const job = getJob(req.params.id)
    const k = req.scanKey
    if (!job || job.key_id !== k.id) return bad(reply, 404, 'not_found')
    if (job.status !== 'done' || !['malicious', 'suspicious', 'pua'].includes(job.verdict)) return bad(reply, 400, 'not_flagged')
    const note = String(req.body?.note || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 500)
    const r = createFpReport({ jobId: job.id, keyId: k.id, ip: req.ip, note })
    if (!r.duplicate) onFalsePositive({ job, key: k, ip: req.ip, note })
    return ok({ id: r.id, status: 'open' })
  })

  /* ------------------------------------------------------- analyst chat */

  // Every key may chat about its own scans; the "owner" key may also open any scan.
  const ownerGuard = guard
  const isOwner = (k) => k.label === 'owner'
  // Messages per key per day: the owner is only bound by the daily AI budget, others by 4 × their scan quota.
  const turnLimit = (k) => (isOwner(k) ? Infinity : k.daily_quota * 4)
  // And at most SCAN_CHAT_IP_DAILY messages per visitor IP per day (owner exempt).
  const ipLimit = (k) => (isOwner(k) ? Infinity : Number(process.env.SCAN_CHAT_IP_DAILY || 10))
  const chatQuota = (req) => {
    const k = req.scanKey
    const left = Math.min(turnLimit(k) - chatTurnsToday(k.id), ipLimit(k) - ipTurnsToday(req.ip))
    return { left: Number.isFinite(left) ? Math.max(0, left) : null, limit: Number.isFinite(ipLimit(k)) ? ipLimit(k) : null }
  }

  app.get('/api/scan/chat/quota', { preHandler: guard }, async (req) => ok(chatQuota(req)))

  // On a shared (public) key every visitor IP has its own chats; on a personal key the key holder sees all.
  const chatIp = (req) => (req.scanKey.shared ? req.ip : null)
  const mine = (c, req) => !!c && c.key_id === req.scanKey.id && (!req.scanKey.shared || c.ip === req.ip)

  // The owner key may read (and follow live) anyone's chat, read-only: it can't post into it.
  const canView = (c, req) => mine(c, req) || (!!c && isOwner(req.scanKey))
  const viewMeta = (c, req) => {
    if (mine(c, req)) return {}
    const k = getKey(c.key_id)
    // personal keys don't store a chat IP; the uploader IP of the chat's file stands in
    return { readonly: true, viewer: { key_label: k?.label || '?', key_prefix: k?.prefix || '', ip: c.ip || (c.job_id && getJob(c.job_id)?.ip) || null } }
  }

  app.get('/api/scan/chats', { preHandler: ownerGuard }, async (req) => ok({ chats: listChats(req.scanKey.id, 50, chatIp(req)) }))

  // Owner only: every user's chats, newest activity first.
  app.get('/api/scan/chats-all', { preHandler: guard }, async (req, reply) => {
    if (!isOwner(req.scanKey)) return bad(reply, 403, 'forbidden')
    return ok({ chats: listAllChats(200).map((c) => ({ ...c, running: isTurnRunning(c.id) })) })
  })

  app.get('/api/scan/chats/:id', { preHandler: ownerGuard }, async (req, reply) => {
    const c = getChat(req.params.id)
    if (!canView(c, req)) return bad(reply, 404, 'not_found')
    const { key_id, ip, ...rest } = viewChat(c, isOwner(req.scanKey))
    return ok({ chat: { ...rest, running: isTurnRunning(c.id), ...viewMeta(c, req) } })
  })

  // Pipes a chat's running turn to this response as server-sent events, starting with `head` events.
  // Ends when the turn sends "done" (or at once when no turn is running). A dropped page only unsubscribes.
  function pipeTurn(req, reply, chatId, head = []) {
    reply.hijack()
    const res = reply.raw
    res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' })
    // Non-owner viewers never get reversing inputs/outputs (chat.js viewEvent).
    const full = isOwner(req.scanKey)
    const write = (ev) => { if (!res.writableEnded) res.write(`data: ${JSON.stringify(viewEvent(ev, full))}\n\n`) }
    head.forEach(write)
    let unsub = null
    const ping = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n') }, 15_000)
    const end = () => { clearInterval(ping); unsub?.(); if (!res.writableEnded) res.end() }
    res.on('close', end)
    unsub = subscribeTurn(chatId, (ev) => { write(ev); if (ev.type === 'done') end() })
    if (!unsub) { write({ type: 'done' }); end() }
  }

  // Re-attach to a chat (after a reload, a dropped connection or a backend restart): the saved transcript, then the live turn.
  app.get('/api/scan/chats/:id/stream', { preHandler: ownerGuard }, async (req, reply) => {
    const c = getChat(req.params.id)
    if (!canView(c, req)) return bad(reply, 404, 'not_found')
    const { key_id, ip, ...rest } = c
    pipeTurn(req, reply, c.id, [{ type: 'sync', chat: { ...rest, running: isTurnRunning(c.id), ...viewMeta(c, req) } }])
  })

  // The owner may also stop someone's runaway turn.
  app.post('/api/scan/chats/:id/stop', { preHandler: ownerGuard }, async (req, reply) => {
    const c = getChat(req.params.id)
    if (!canView(c, req)) return bad(reply, 404, 'not_found')
    stopTurn(c.id)
    return ok({ stopped: true })
  })

  app.delete('/api/scan/chats/:id', { preHandler: ownerGuard }, async (req, reply) => {
    const c = getChat(req.params.id)
    if (!mine(c, req)) return bad(reply, 404, 'not_found')
    deleteChat(c.id)
    return ok({ deleted: true })
  })

  // One user turn, streamed as server-sent events (one JSON object per "data:" line). Free keys come in through
  // the sealed route below (rotating path + encrypted body), the owner through /api/scan/chat.
  const chatTurnRoute = async (req, reply) => {
    const k = req.scanKey
    // Our page only ever sends { text, chat_id, job_id, auto, b, cf_token }; Nyx's system prompt and tools
    // are added here on the server. A body carrying chat-API fields (system, tools, messages…) or a
    // non-string text is an IDE agent trying to drive Nyx as a model endpoint.
    const apiFields = API_FIELDS.filter((f) => req.body && Object.hasOwn(req.body, f))
    if (apiFields.length || (req.body?.text != null && typeof req.body.text !== 'string')) {
      if (!isOwner(k)) onAutomation({ key: k, ip: req.ip, kind: 'agent', blocked: true, hits: apiFields.length ? apiFields.map((f) => `api_field:${f}`) : ['api_field:text_not_string'], text: JSON.stringify(req.body).slice(0, 500), deviceId: String(req.headers['x-cg-dev'] || '') })
      req.log.warn({ ip: req.ip, fields: apiFields }, 'scan: chat-API shaped body refused')
      return bad(reply, 403, 'automation_detected')
    }
    const text = String(req.body?.text || '').trim().slice(0, 20_000)
    const jobId = req.body?.job_id ? String(req.body.job_id) : null
    if (!text) return bad(reply, 400, 'empty_message')
    if (await masked(req, reply, k, 'chat')) return
    const ownJob = jobId ? getJob(jobId) : null
    if (jobId && (!ownJob || !(isOwner(k) || ownJob.key_id === k.id))) return bad(reply, 404, 'job_not_found')
    let chatId = req.body?.chat_id ? String(req.body.chat_id) : null
    if (chatId && !mine(getChat(chatId), req)) return bad(reply, 404, 'chat_not_found')
    if (chatId && isTurnRunning(chatId)) return bad(reply, 409, 'turn_running')
    // A chat Nyx closed for misuse takes no more messages, and three strikes ban the key (and for a week
    // its IP) from Nyx. Free users may ask without a file; Nyx itself ends chats that waste it.
    if (!isOwner(k)) {
      if (notFromSite(req, reply, 'chat')) return
      if (unsigned(req, reply)) return
      if (String(req.body?.text ?? '').length > FREE_MSG_MAX) return bad(reply, 413, 'message_too_long')
      // A driven browser (Playwright / Puppeteer / Selenium) or an IDE agent's prompt scaffolding: refused
      // before the model is called. Weak marks only alert; Nyx still judges the message itself.
      const devId = String(req.headers['x-cg-dev'] || '')
      const bot = botScore(req.body?.b)
      const sig = agentSignatures(text)
      if (bot.score >= BOT_BLOCK_AT || sig.strong.length) {
        const kind = sig.strong.length ? 'agent' : 'bot'
        onAutomation({ key: k, ip: req.ip, kind, blocked: true, hits: kind === 'agent' ? sig.strong : bot.hits, text, deviceId: devId })
        req.log.warn({ ip: req.ip, kind, bot: bot.hits, agent: sig.strong }, 'scan: automation refused')
        return bad(reply, 403, 'automation_detected')
      }
      if (bot.score > 0 || sig.weak.length) onAutomation({ key: k, ip: req.ip, kind: sig.weak.length ? 'agent' : 'bot', blocked: false, hits: [...bot.hits, ...sig.weak], text, deviceId: devId })
      if (await noHuman(req, reply, 'nyx', sha256hex(String(req.body?.text ?? '')).slice(0, 32))) return
      if (tooFast(req, reply, k)) return
      touchDevice(k.id, devId, req.ip)
      if (strikesOf(k.id, req.ip) >= NYX_BAN_AT) return reply.code(403).send({ ok: false, error: 'nyx_banned', misuse: { level: 3, ...lastStrike(k.id, req.ip) } })
      if (chatId && getChat(chatId)?.closed) return bad(reply, 409, 'chat_closed')
    }
    // The automatic "analyse this file" turn of a file Nyx already analysed (for anyone) is copied, not
    // paid for again; it doesn't use up a message either. Follow-up questions run normally.
    if (req.body?.auto === true && !chatId && ownJob) {
      const reuse = reusableAnalysis(ownJob, AUTO_MARKER)
      if (reuse) {
        chatId = createChat({ keyId: k.id, jobId, title: text.slice(0, 80), ip: chatIp(req) })
        saveChat(chatId, { messages: reuse.messages, toolMs: reuse.toolMs, jobId })
        const { key_id, ip, ...rest } = getChat(chatId)
        return pipeTurn(req, reply, chatId, [{ type: 'chat', id: chatId }, { type: 'sync', chat: { ...rest, running: false, reused: true } }])
      }
    }
    if (chatTurnsToday(k.id) >= turnLimit(k)) { onLimit({ key: k, ip: req.ip, kind: 'chat_key' }); return bad(reply, 429, 'chat_quota_exceeded') }
    if (ipTurnsToday(req.ip) >= ipLimit(k)) { onLimit({ key: k, ip: req.ip, kind: 'chat_ip' }); return bad(reply, 429, 'chat_ip_quota_exceeded') }
    onChatMessage({ key: k, ip: req.ip, text, chatId })
    recordChatTurn(k.id)
    if (!isOwner(k)) recordIpTurn(req.ip)
    if (!chatId) chatId = createChat({ keyId: k.id, jobId, title: text.slice(0, 80), ip: chatIp(req) })

    // The turn runs detached from this request; this response just follows it.
    startTurn({ chatId, keyId: k.id, owner: isOwner(k), text, jobId, ip: req.ip })
    pipeTurn(req, reply, chatId, [{ type: 'chat', id: chatId }])
  }
  // Owner: plain JSON. A free key's plain request (a script, an old tab) is told to use the page.
  app.post('/api/scan/chat', { preHandler: ownerGuard }, async (req, reply) => {
    if (!isOwner(req.scanKey)) return bad(reply, 403, 'browser_required')
    return chatTurnRoute(req, reply)
  })
  // Free keys: /api/scan/x/<tag>, where the tag, the field carrying the ciphertext and the key change every
  // 5 minutes (seal.js). Anything that doesn't open is refused like a non-browser request.
  app.post('/api/scan/x/:tag', { preHandler: ownerGuard, bodyLimit: 262_144 }, async (req, reply) => {
    const inner = openSealed(req.cookies?.[COOKIE], req.params.tag, req.body)
    if (!inner) {
      req.log.warn({ ip: req.ip, tag: req.params.tag }, 'scan: sealed request did not open')
      return bad(reply, 403, 'browser_required')
    }
    req.body = inner
    return chatTurnRoute(req, reply)
  })

  /* -------------------------------------------------------------- admin */

  const adminGuard = async (req, reply) => { if (!isAdmin(req)) return bad(reply, 401, 'not_authenticated') }

  app.get('/api/admin/scan/keys', { preHandler: adminGuard }, async () => ok({ keys: listKeys(), providers: describeProviders() }))

  // Wipes today's free-tier counters (scans, new keys, Nyx messages); owner keys are untouched.
  app.post('/api/admin/scan/reset-limits', { preHandler: adminGuard }, async () => ok(resetFreeLimits()))
  // Old analyses stop being copied to new uploads of the same file (nothing is deleted).
  app.post('/api/admin/scan/clear-analysis-reuse', { preHandler: adminGuard }, async () => ok(clearAnalysisReuse()))
  // Keys Nyx struck for misuse (3 = banned from Nyx); pardoning clears the key's and its IPs' strikes.
  app.get('/api/admin/scan/nyx-strikes', { preHandler: adminGuard }, async () => ok({ strikes: listStrikes(), ban_at: NYX_BAN_AT }))
  app.post('/api/admin/scan/nyx-strikes/:keyId/pardon', { preHandler: adminGuard }, async (req) => ok({ pardoned: pardon(String(req.params.keyId)) }))

  // False-positive queue. Accepting stores an override for the file's sha256 and re-scores every scan of it.
  app.get('/api/admin/scan/false-positives', { preHandler: adminGuard }, async (req) =>
    ok({ reports: listFpReports(req.query?.status === 'closed' ? 'accepted' : 'open'), overrides: listOverrides() }))
  app.post('/api/admin/scan/false-positives/:id', { preHandler: adminGuard }, async (req, reply) => {
    const r = getFpReport(req.params.id)
    if (!r) return bad(reply, 404, 'not_found')
    const action = String(req.body?.action || '')
    if (action === 'reject') { decideFpReport(r.id, 'rejected'); return ok({ status: 'rejected' }) }
    const verdict = { clean: 'clean', pua: 'pua' }[action]
    if (!verdict) return bad(reply, 400, 'bad_action')
    const job = getJob(r.job_id)
    setOverride(job.sha256, verdict, String(req.body?.note || r.note || '').slice(0, 300))
    decideFpReport(r.id, 'accepted')
    const rescored = jobsWithSha(job.sha256).map((id) => rescoreJob(id)).filter(Boolean).length
    return ok({ status: 'accepted', verdict, rescored })
  })
  app.delete('/api/admin/scan/overrides/:sha256', { preHandler: adminGuard }, async (req) => {
    const n = deleteOverride(req.params.sha256)
    jobsWithSha(req.params.sha256).forEach((id) => rescoreJob(id))
    return ok({ deleted: n })
  })

  // Health of every source, the tunnel services, the CAPE queue and the AI budget.
  app.get('/api/admin/scan/health', { preHandler: adminGuard }, async () => ok(await scanHealth()))
  // Score regression: labelled files re-scored with the current rules.
  app.post('/api/admin/scan/regress', { preHandler: adminGuard }, async () => ok(runRegression()))
  app.get('/api/admin/scan/labels', { preHandler: adminGuard }, async () => ok({ labels: allLabels() }))
  app.post('/api/admin/scan/labels', { preHandler: adminGuard }, async (req, reply) => {
    const v = String(req.body?.verdict || '')
    let sha = String(req.body?.sha256 || '').trim().toLowerCase()
    const jobId = String(req.body?.job_id || '').trim() || null
    if (!sha && jobId) sha = getJob(jobId)?.sha256 || ''
    if (!/^[0-9a-f]{64}$/.test(sha) || !['clean', 'pua', 'suspicious', 'malicious'].includes(v)) return bad(reply, 400, 'bad_label')
    setLabel(sha, v, String(req.body?.note || '').slice(0, 300), jobId)
    return ok({ sha256: sha, verdict: v })
  })
  app.delete('/api/admin/scan/labels/:sha256', { preHandler: adminGuard }, async (req) => ok({ deleted: deleteLabel(req.params.sha256).changes }))

  app.post('/api/admin/scan/keys', { preHandler: adminGuard }, async (req, reply) => {
    const label = String(req.body?.label || '').trim().slice(0, 80)
    const quota = Number(req.body?.daily_quota ?? 25)
    const days = Number(req.body?.days || 0)
    if (!label) return bad(reply, 400, 'invalid_label')
    if (!Number.isInteger(quota) || quota < 1 || quota > 10000) return bad(reply, 400, 'invalid_quota')
    const { id, key } = createKey({ label, dailyQuota: quota, expiresAt: days > 0 ? Date.now() + days * 86400_000 : null, shared: req.body?.shared === true })
    return ok({ id, key })
  })

  app.patch('/api/admin/scan/keys/:id', { preHandler: adminGuard }, async (req, reply) => {
    const b = req.body || {}
    const patch = {}
    if (typeof b.label === 'string' && b.label.trim()) patch.label = b.label.trim().slice(0, 80)
    if (Number.isInteger(b.daily_quota) && b.daily_quota >= 1 && b.daily_quota <= 10000) patch.daily_quota = b.daily_quota
    if (typeof b.revoked === 'boolean') patch.revoked = b.revoked
    if (typeof b.shared === 'boolean') patch.shared = b.shared
    const row = updateKey(req.params.id, patch)
    return row ? ok({ id: row.id }) : bad(reply, 404, 'not_found')
  })

  /* --------------------------------------------------------------- boot */

  const sweep = () => {
    sweepScanSessions()
    for (const sha of samplesOlderThan(Date.now() - RETENTION)) deleteSample(sha)
    for (const ip of [...fails.keys()]) blocked(ip)
  }
  setInterval(sweep, 6 * 60 * 60_000).unref()
  sweep()
  resumeJobs()
  resumeChats()
  resumeHoney()
  startWatcher()
}
