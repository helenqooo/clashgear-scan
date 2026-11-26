// Scan tables on the shared app.db: access keys, their sessions, jobs and per-source results.

import { randomBytes, createHash } from 'node:crypto'
import { db } from '../store.js'

db.exec(`
  CREATE TABLE IF NOT EXISTS scan_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    daily_quota INTEGER NOT NULL,
    expires_at INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    parent_id TEXT,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    static_json TEXT,
    score INTEGER,
    verdict TEXT,
    ai_json TEXT,
    created_at INTEGER NOT NULL,
    finished_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS scan_jobs_key ON scan_jobs (key_id, created_at);
  CREATE INDEX IF NOT EXISTS scan_jobs_parent ON scan_jobs (parent_id);
  CREATE TABLE IF NOT EXISTS scan_results (
    job_id TEXT NOT NULL,
    source TEXT NOT NULL,
    layer INTEGER NOT NULL,
    status TEXT NOT NULL,
    ref TEXT,
    summary_json TEXT,
    error TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (job_id, source)
  );
  CREATE TABLE IF NOT EXISTS scan_ai_usage (
    day TEXT PRIMARY KEY,
    usd REAL NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scan_chats (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    job_id TEXT,
    title TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS scan_chats_key ON scan_chats (key_id, updated_at);
`)

// Shared keys (one key handed to a whole forum) get a public-key warning on the scan screen.
try { db.exec('ALTER TABLE scan_keys ADD COLUMN shared INTEGER NOT NULL DEFAULT 0') } catch { /* already there */ }
// On shared keys a chat belongs to the visitor's IP, not to everyone holding the key.
try { db.exec('ALTER TABLE scan_chats ADD COLUMN ip TEXT') } catch { /* already there */ }
// A Nyx turn in progress (so a restart can resume it) and whether it runs with owner rights.
try { db.exec('ALTER TABLE scan_chats ADD COLUMN running INTEGER NOT NULL DEFAULT 0') } catch { /* already there */ }
try { db.exec('ALTER TABLE scan_chats ADD COLUMN run_owner INTEGER NOT NULL DEFAULT 0') } catch { /* already there */ }
// The uploader's IP, kept for the owner's abuse alerts (never returned by the public API).
try { db.exec('ALTER TABLE scan_jobs ADD COLUMN ip TEXT') } catch { /* already there */ }
// Self-service keys minted from the landing page: the IP that asked, so one visitor can't farm keys.
try { db.exec('ALTER TABLE scan_keys ADD COLUMN created_ip TEXT') } catch { /* already there */ }
// Shared reports: anyone with the /scan/r/<id> link can read them (owner, 2026-11-07).
try { db.exec('ALTER TABLE scan_jobs ADD COLUMN public INTEGER NOT NULL DEFAULT 0') } catch { /* already there */ }

const now = () => Date.now()
const parse =(s) => { try { return s ? JSON.parse(s) : null } catch { return null } }
export const hashKey = (k) => createHash('sha256').update(String(k)).digest('hex')

// --- keys --------------------------------------------------------------------
const insKey = db.prepare('INSERT INTO scan_keys (id, key_hash, prefix, label, daily_quota, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
const keyByHash = db.prepare('SELECT * FROM scan_keys WHERE key_hash = ?')
const keyById = db.prepare('SELECT * FROM scan_keys WHERE id = ?')
const allKeys = db.prepare('SELECT * FROM scan_keys ORDER BY created_at DESC')
const touchKey = db.prepare('UPDATE scan_keys SET last_used_at = ? WHERE id = ?')

/** Returns the plaintext key once; only its hash is stored. */
export function createKey({ label, dailyQuota = 25, expiresAt = null, shared = false }) {
  const id = randomBytes(8).toString('hex')
  const key = `cgs_${randomBytes(24).toString('base64url')}`
  insKey.run(id, hashKey(key), key.slice(0, 8), label, dailyQuota, expiresAt, now())
  if (shared) db.prepare('UPDATE scan_keys SET shared = 1 WHERE id = ?').run(id)
  return { id, key }
}
export function keyUsable(row) {
  return !!row && !row.revoked && (!row.expires_at || row.expires_at > now())
}
export const findKey = (plain) => keyByHash.get(hashKey(plain)) || null
export const getKey = (id) => keyById.get(id) || null
export const listKeys = () => allKeys.all().map((k) => ({ ...k, key_hash: undefined, revoked: !!k.revoked, shared: !!k.shared, used_today: usedToday(k.id) }))
export const markKeyUsed = (id) => touchKey.run(now(), id)
export function updateKey(id, { label, daily_quota, expires_at, revoked, shared }) {
  const row = getKey(id)
  if (!row) return null
  db.prepare('UPDATE scan_keys SET label = ?, daily_quota = ?, expires_at = ?, revoked = ?, shared = ? WHERE id = ?').run(
    label ?? row.label,
    daily_quota ?? row.daily_quota,
    expires_at === undefined ? row.expires_at : expires_at,
    revoked === undefined ? row.revoked : revoked ? 1 : 0,
    shared === undefined ? row.shared : shared ? 1 : 0,
    id,
  )
  return getKey(id)
}

// --- sessions ----------------------------------------------------------------
const insSess = db.prepare('INSERT INTO scan_sessions (id, key_id, expires_at) VALUES (?, ?, ?)')
const getSess = db.prepare('SELECT * FROM scan_sessions WHERE id = ?')
const delSess = db.prepare('DELETE FROM scan_sessions WHERE id = ?')
const pruneSess = db.prepare('DELETE FROM scan_sessions WHERE expires_at < ?')

export function createScanSession(keyId, ttlMs) {
  const id = randomBytes(32).toString('hex')
  insSess.run(id, keyId, now() + ttlMs)
  return id
}
/** The key row behind a session, or null when the session or the key is no longer valid. */
export function sessionKey(id) {
  if (!id) return null
  const s = getSess.get(id)
  if (!s) return null
  if (s.expires_at < now()) { delSess.run(id); return null }
  const k = getKey(s.key_id)
  return keyUsable(k) ? k : null
}
export const destroyScanSession = (id) => id && delSess.run(id)
export const sweepScanSessions = () => pruneSess.run(now())

// --- jobs --------------------------------------------------------------------
const insJob = db.prepare(`INSERT INTO scan_jobs (id, key_id, parent_id, file_name, size, md5, sha1, sha256, status, static_json, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)`)
const jobRow = db.prepare('SELECT * FROM scan_jobs WHERE id = ?')
const jobsOfKey = db.prepare('SELECT * FROM scan_jobs WHERE key_id = ? AND parent_id IS NULL ORDER BY created_at DESC LIMIT ?')
const childrenOf = db.prepare('SELECT * FROM scan_jobs WHERE parent_id = ? ORDER BY created_at')
const sameFile = db.prepare('SELECT id FROM scan_jobs WHERE key_id = ? AND sha256 = ? AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1')
const countToday = db.prepare('SELECT count(*) AS n FROM scan_jobs WHERE key_id = ? AND parent_id IS NULL AND created_at >= ?')
const runningJobs = db.prepare("SELECT id FROM scan_jobs WHERE status = 'running'")
const oldSamples = db.prepare('SELECT DISTINCT sha256 FROM scan_jobs WHERE created_at < ? AND sha256 NOT IN (SELECT sha256 FROM scan_jobs WHERE created_at >= ?)')

// --- false-positive reports and owner overrides ---------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS scan_overrides (
    sha256 TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    note TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scan_fp_reports (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ip TEXT,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at INTEGER NOT NULL,
    decided_at INTEGER
  );
`)
export const getOverride = (sha256) => db.prepare('SELECT verdict, note FROM scan_overrides WHERE sha256 = ?').get(sha256) || null
export function setOverride(sha256, verdict, note = '') {
  db.prepare('INSERT INTO scan_overrides (sha256, verdict, note, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(sha256) DO UPDATE SET verdict = excluded.verdict, note = excluded.note, created_at = excluded.created_at')
    .run(sha256, verdict, note, now())
}
export const deleteOverride = (sha256) => db.prepare('DELETE FROM scan_overrides WHERE sha256 = ?').run(sha256).changes

// --- Nyx + Rune verdicts (owner, 2026-11-07): after reading the code, Rune proposes a verdict and score and
// Nyx confirms it (chat.js set_verdict). score.js applies it below an owner override and never against hard proof.
db.exec(`
  CREATE TABLE IF NOT EXISTS scan_ai_verdicts (
    sha256 TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    reason TEXT,
    job_id TEXT,
    key_id TEXT,
    created_at INTEGER NOT NULL
  );
`)
export const getAiVerdict = (sha256) => db.prepare('SELECT verdict, score, reason, created_at FROM scan_ai_verdicts WHERE sha256 = ?').get(sha256) || null
export function setAiVerdict({ sha256, verdict, score, reason, jobId, keyId }) {
  db.prepare('INSERT INTO scan_ai_verdicts (sha256, verdict, score, reason, job_id, key_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(sha256) DO UPDATE SET verdict = excluded.verdict, score = excluded.score, reason = excluded.reason, job_id = excluded.job_id, key_id = excluded.key_id, created_at = excluded.created_at')
    .run(sha256, verdict, score, reason, jobId, keyId, now())
}
export const deleteAiVerdict = (sha256) => db.prepare('DELETE FROM scan_ai_verdicts WHERE sha256 = ?').run(sha256).changes
export const listOverrides = () => db.prepare('SELECT * FROM scan_overrides ORDER BY created_at DESC').all()
export function createFpReport({ jobId, keyId, ip, note }) {
  const open = db.prepare("SELECT id FROM scan_fp_reports WHERE job_id = ? AND status = 'open'").get(jobId)
  if (open) return { id: open.id, duplicate: true }
  const id = randomBytes(8).toString('hex')
  db.prepare('INSERT INTO scan_fp_reports (id, job_id, key_id, ip, note, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, jobId, keyId, ip, note, now())
  return { id }
}
export const fpReportOf = (jobId) => db.prepare('SELECT id, status, created_at FROM scan_fp_reports WHERE job_id = ? ORDER BY created_at DESC LIMIT 1').get(jobId) || null
export const listFpReports = (status = 'open') =>
  db.prepare(`SELECT r.*, j.file_name, j.sha256, j.verdict, j.score, k.label AS key_label FROM scan_fp_reports r
    JOIN scan_jobs j ON j.id = r.job_id LEFT JOIN scan_keys k ON k.id = r.key_id WHERE r.status = ? ORDER BY r.created_at DESC LIMIT 200`).all(status)
export const getFpReport = (id) => db.prepare('SELECT * FROM scan_fp_reports WHERE id = ?').get(id) || null
export const decideFpReport = (id, status) => db.prepare('UPDATE scan_fp_reports SET status = ?, decided_at = ? WHERE id = ?').run(status, now(), id)
export const setJobPublic = (id, on) => db.prepare('UPDATE scan_jobs SET public = ? WHERE id = ?').run(on ? 1 : 0, id).changes
export const jobsWithSha = (sha256) => db.prepare("SELECT id FROM scan_jobs WHERE sha256 = ? AND status = 'done'").all(sha256).map((r) => r.id)
export function setJobScore(id, { score, verdict, computed }) {
  const job = getJob(id)
  if (!job) return
  db.prepare('UPDATE scan_jobs SET score = ?, verdict = ?, ai_json = ? WHERE id = ?').run(score, verdict, JSON.stringify({ ...(job.ai || {}), computed }), id)
}

// --- Nyx misuse strikes --------------------------------------------------------------------------
// Nyx ends a chat it sees being wasted (end_chat tool) and that is a strike against the key and the IP.
// 1st: the chat is closed, 2nd: a warning, 3rd: banned from Nyx. A key's strikes count for 30 days, an
// IP's for 7 (IPs are shared and change); the owner can pardon.
db.exec(`
  CREATE TABLE IF NOT EXISTS scan_misuse (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    ip TEXT,
    chat_id TEXT,
    reason TEXT,
    behavior TEXT,
    pardoned INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
`)
try { db.exec('ALTER TABLE scan_chats ADD COLUMN closed INTEGER NOT NULL DEFAULT 0') } catch { /* already there */ }
export const NYX_BAN_AT = 3
export function strikesOf(keyId, ip) {
  const t = now()
  return db.prepare(`SELECT count(*) AS n FROM scan_misuse WHERE pardoned = 0 AND created_at > ?
    AND (key_id = ? OR (? IS NOT NULL AND ip = ? AND created_at > ?))`).get(t - 30 * 86400_000, keyId, ip, ip, t - 7 * 86400_000).n
}
/**
 * The first messages of a visitor's other chats from the last 24 h (their key, and keys made from their IP),
 * newest first, cleaned for Nyx's hidden note: the page's own prefixes dropped, brackets removed, 40 chars max.
 */
export function recentOpeners(keyId, ip, exceptChatId, limit = 6) {
  const rows = db.prepare(`SELECT c.messages_json FROM scan_chats c WHERE c.id != ? AND c.created_at > ?
    AND (c.key_id = ? OR c.key_id IN (SELECT id FROM scan_keys WHERE ? IS NOT NULL AND created_ip = ?)) ORDER BY c.created_at DESC LIMIT ?`)
    .all(exceptChatId || '', now() - 86400_000, keyId, ip, ip, limit)
  return rows.map((r) => {
    const first = (parse(r.messages_json)?.messages || []).find((m) => m.role === 'user' && Array.isArray(m.content) && m.content.some((b) => b.type === 'text'))
    const text = first?.content.find((b) => b.type === 'text').text || ''
    return text.replace(/^\[[^\]]*\]\n\n/, '').replace(/[[\]«»\n\r]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 40)
  }).filter(Boolean)
}

/** Records a strike and closes the chat; returns the strike count after it. */
export function addStrike({ keyId, ip, chatId, reason, behavior }) {
  db.prepare('INSERT INTO scan_misuse (key_id, ip, chat_id, reason, behavior, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(keyId, ip || null, chatId, reason, behavior, now())
  db.prepare('UPDATE scan_chats SET closed = 1 WHERE id = ?').run(chatId)
  return strikesOf(keyId, ip)
}
export const lastStrike = (keyId, ip) =>
  db.prepare('SELECT reason, behavior, created_at FROM scan_misuse WHERE pardoned = 0 AND (key_id = ? OR (? IS NOT NULL AND ip = ?)) ORDER BY created_at DESC LIMIT 1').get(keyId, ip, ip) || null
/** Keys with strikes, newest first, for the admin panel. */
export const listStrikes = () =>
  db.prepare(`SELECT m.key_id, k.prefix AS key_prefix, count(*) AS strikes, max(m.created_at) AS last_at, group_concat(DISTINCT m.ip) AS ips,
      (SELECT reason FROM scan_misuse x WHERE x.key_id = m.key_id AND x.pardoned = 0 ORDER BY created_at DESC LIMIT 1) AS reason
    FROM scan_misuse m LEFT JOIN scan_keys k ON k.id = m.key_id WHERE m.pardoned = 0 GROUP BY m.key_id ORDER BY last_at DESC LIMIT 100`).all()
/** Clears a key's strikes and those of the IPs it struck from. */
export function pardon(keyId) {
  const ips = db.prepare('SELECT DISTINCT ip FROM scan_misuse WHERE key_id = ? AND ip IS NOT NULL').all(keyId).map((r) => r.ip)
  let n = db.prepare('UPDATE scan_misuse SET pardoned = 1 WHERE key_id = ? AND pardoned = 0').run(keyId).changes
  for (const ip of ips) n += db.prepare('UPDATE scan_misuse SET pardoned = 1 WHERE ip = ? AND pardoned = 0').run(ip).changes
  return n
}

// The owner can wipe today's free-tier counters ("reset limits"): counting then starts at that moment.
db.exec('CREATE TABLE IF NOT EXISTS scan_settings (k TEXT PRIMARY KEY, v TEXT)')
const resetAt = () => Number(db.prepare("SELECT v FROM scan_settings WHERE k = 'limits_reset_at'").get()?.v || 0)
/** Scan closed for everyone but owner keys until this time (ms); it reopens by itself. 0 = open. */
export const closedUntil = () => { const t = Number(db.prepare("SELECT v FROM scan_settings WHERE k = 'closed_until'").get()?.v || 0); return t > Date.now() ? t : 0 }
export const setClosedUntil = (t) => db.prepare("INSERT INTO scan_settings (k, v) VALUES ('closed_until', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(String(t || 0))
const dayStart = () => { const d = new Date(); d.setUTCHours(0, 0, 0, 0); return Math.max(d.getTime(), resetAt()) }
export const usedToday = (keyId) => countToday.get(keyId, dayStart()).n
/** Resets every non-owner daily counter: scans, new self keys, Nyx messages per key and per IP. */
export function resetFreeLimits() {
  const t = now()
  db.prepare("INSERT INTO scan_settings (k, v) VALUES ('limits_reset_at', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(String(t))
  const owners = db.prepare("SELECT id FROM scan_keys WHERE label = 'owner'").all().map((r) => r.id)
  const rows = db.prepare("SELECT day FROM scan_ai_usage WHERE day LIKE 'turns:%' OR day LIKE 'turnsip:%' OR day LIKE 'live:%'").all()
  let cleared = 0
  for (const { day } of rows) {
    if (!day.endsWith(`:${today()}`) || owners.some((id) => day === `turns:${id}:${today()}` || day === `live:${id}:${today()}`)) continue
    cleared += db.prepare('DELETE FROM scan_ai_usage WHERE day = ?').run(day).changes
  }
  return { reset_at: t, chat_counters_cleared: cleared }
}

// --- self-service keys ---------------------------------------------------------
export const SELF_LABEL = 'self'
export function createSelfKey({ ip, dailyQuota }) {
  const made = createKey({ label: SELF_LABEL, dailyQuota })
  db.prepare('UPDATE scan_keys SET created_ip = ? WHERE id = ?').run(ip, made.id)
  return made
}
const selfKeysSince = db.prepare('SELECT count(*) AS n FROM scan_keys WHERE label = ? AND created_ip = ? AND created_at >= ?')
const selfKeysAllSince = db.prepare('SELECT count(*) AS n FROM scan_keys WHERE label = ? AND created_at >= ?')
export const selfKeysByIp = (ip, since) => selfKeysSince.get(SELF_LABEL, ip, Math.max(since, resetAt())).n
export const selfKeysTotal = (since) => selfKeysAllSince.get(SELF_LABEL, Math.max(since, resetAt())).n
/** Today's top-level scans from an IP across every self-service key (a visitor with several keys still has one budget). */
export const selfScansByIp = (ip) =>
  db.prepare('SELECT count(*) AS n FROM scan_jobs j JOIN scan_keys k ON k.id = j.key_id WHERE k.label = ? AND j.ip = ? AND j.parent_id IS NULL AND j.created_at >= ?')
    .get(SELF_LABEL, ip, dayStart()).n
export const selfScansTotal = () =>
  db.prepare('SELECT count(*) AS n FROM scan_jobs j JOIN scan_keys k ON k.id = j.key_id WHERE k.label = ? AND j.parent_id IS NULL AND j.created_at >= ?')
    .get(SELF_LABEL, dayStart()).n

export function createJob({ keyId, parentId = null, fileName, size, md5, sha1, sha256, staticInfo, ip = null }) {
  const id = randomBytes(12).toString('hex')
  insJob.run(id, keyId, parentId, fileName, size, md5, sha1, sha256, JSON.stringify(staticInfo), now())
  if (ip) db.prepare('UPDATE scan_jobs SET ip = ? WHERE id = ?').run(ip, id)
  return id
}
function inflate(r) {
  if (!r) return null
  const { static_json, ai_json, source_json, ...rest } = r
  return { ...rest, static: parse(static_json), ai: parse(ai_json), source: parse(source_json) }
}
export const getJob = (id) => inflate(jobRow.get(id))
export const listJobs = (keyId, limit = 50) => jobsOfKey.all(keyId, limit).map(({ static_json, ai_json, source_json, ...r }) => ({ ...r, source: parse(source_json) }))
/** Results of one source still waiting on an external task (e.g. a live CAPE run) after a restart. */
export const pendingRefs = (source) =>
  db.prepare("SELECT r.job_id, r.ref FROM scan_results r JOIN scan_jobs j ON j.id = r.job_id WHERE r.source = ? AND r.status IN ('queued', 'running') AND r.ref IS NOT NULL AND j.status = 'done'").all(source)
/** Every user's scans for the owner view, newest first, with the key label and uploader IP. */
export const listAllJobs = (limit = 100, q = '') =>
  db.prepare(`SELECT j.id, j.file_name, j.size, j.sha256, j.md5, j.sha1, j.status, j.score, j.verdict, j.created_at, j.finished_at, j.parent_id,
      j.ip, k.label AS key_label, k.prefix AS key_prefix, (SELECT count(*) FROM scan_jobs c WHERE c.parent_id = j.id) AS children
    FROM scan_jobs j LEFT JOIN scan_keys k ON k.id = j.key_id
    WHERE j.parent_id IS NULL AND (? = '' OR j.file_name LIKE ? OR j.sha256 = ? OR j.ip = ?)
    ORDER BY j.created_at DESC LIMIT ?`).all(q, `%${q}%`, q.toLowerCase(), q, limit)
export const childJobs = (id) => childrenOf.all(id).map(inflate)
export const existingJob = (keyId, sha256) => sameFile.get(keyId, sha256)?.id || null
export const runningJobIds = () => runningJobs.all().map((r) => r.id)
export const samplesOlderThan = (t) => oldSamples.all(t, t).map((r) => r.sha256)

export function finishJob(id, { score, verdict, ai }) {
  db.prepare("UPDATE scan_jobs SET status = 'done', score = ?, verdict = ?, ai_json = ?, finished_at = ? WHERE id = ?")
    .run(score, verdict, ai ? JSON.stringify(ai) : null, now(), id)
}

// --- results -----------------------------------------------------------------
const upsertRes = db.prepare(`INSERT INTO scan_results (job_id, source, layer, status, ref, summary_json, error, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(job_id, source) DO UPDATE SET status = excluded.status, ref = COALESCE(excluded.ref, scan_results.ref),
    summary_json = COALESCE(excluded.summary_json, scan_results.summary_json), error = excluded.error, updated_at = excluded.updated_at`)
const resOfJob = db.prepare('SELECT * FROM scan_results WHERE job_id = ? ORDER BY layer, source')
const resOne = db.prepare('SELECT * FROM scan_results WHERE job_id = ? AND source = ?')

export function setResult(jobId, source, layer, { status, ref = null, summary = null, error = null }) {
  upsertRes.run(jobId, source, layer, status, ref, summary ? JSON.stringify(summary) : null, error, now())
}
export const getResult = (jobId, source) => {
  const r = resOne.get(jobId, source)
  return r ? { ...r, summary: parse(r.summary_json) } : null
}
export const listResults = (jobId) => resOfJob.all(jobId).map(({ summary_json, ...r }) => ({ ...r, summary: parse(summary_json) }))

// --- AI spend ----------------------------------------------------------------
const today = () => new Date().toISOString().slice(0, 10)
export const aiSpentToday = () => db.prepare('SELECT usd FROM scan_ai_usage WHERE day = ?').get(today())?.usd || 0
export const recordAiSpend = (usd) =>
  db.prepare('INSERT INTO scan_ai_usage (day, usd) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET usd = usd + excluded.usd').run(today(), usd)
// The analyst chat has its own daily budget, kept in the same table under a "chat:" day key.
export const chatSpentToday = () => db.prepare('SELECT usd FROM scan_ai_usage WHERE day = ?').get(`chat:${today()}`)?.usd || 0
export const recordChatSpend = (usd) =>
  db.prepare('INSERT INTO scan_ai_usage (day, usd) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET usd = usd + excluded.usd').run(`chat:${today()}`, usd)

// Everything the AI cost today (reports + chats), checked against SCAN_AI_TOTAL_DAILY_USD.
export const aiTotalToday = () => aiSpentToday() + chatSpentToday()
export const aiTotalCap = () => Number(process.env.SCAN_AI_TOTAL_DAILY_USD || 10)
export const aiTotalSpent = () => aiTotalToday() >= aiTotalCap()

// Live sandbox sessions a key started today ("live:<key>:<day>").
export const liveToday = (keyId) => db.prepare('SELECT usd FROM scan_ai_usage WHERE day = ?').get(`live:${keyId}:${today()}`)?.usd || 0
export const recordLive = (keyId) =>
  db.prepare('INSERT INTO scan_ai_usage (day, usd) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET usd = usd + 1').run(`live:${keyId}:${today()}`)

// Chat messages a key sent today (same table, "turns:<key>:<day>" rows; usd holds the count).
export const chatTurnsToday = (keyId) => db.prepare('SELECT usd FROM scan_ai_usage WHERE day = ?').get(`turns:${keyId}:${today()}`)?.usd || 0
export const recordChatTurn = (keyId) =>
  db.prepare('INSERT INTO scan_ai_usage (day, usd) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET usd = usd + 1').run(`turns:${keyId}:${today()}`)
// The same per visitor IP ("turnsip:<ip>:<day>"), whatever key they use.
export const ipTurnsToday = (ip) => db.prepare('SELECT usd FROM scan_ai_usage WHERE day = ?').get(`turnsip:${ip}:${today()}`)?.usd || 0
export const recordIpTurn = (ip) =>
  db.prepare('INSERT INTO scan_ai_usage (day, usd) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET usd = usd + 1').run(`turnsip:${ip}:${today()}`)

// --- analyst chats -----------------------------------------------------------
const insChat = db.prepare('INSERT INTO scan_chats (id, key_id, job_id, title, messages_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
const chatRow = db.prepare('SELECT * FROM scan_chats WHERE id = ?')
const chatsOfKey = db.prepare('SELECT id, job_id, title, created_at, updated_at FROM scan_chats WHERE key_id = ? ORDER BY updated_at DESC LIMIT ?')
const chatsOfKeyIp = db.prepare('SELECT id, job_id, title, created_at, updated_at FROM scan_chats WHERE key_id = ? AND ip = ? ORDER BY updated_at DESC LIMIT ?')

export function createChat({ keyId, jobId = null, title, ip = null }) {
  const id = randomBytes(10).toString('hex')
  insChat.run(id, keyId, jobId, title, '{}', now(), now())
  if (ip) db.prepare('UPDATE scan_chats SET ip = ? WHERE id = ?').run(ip, id)
  return id
}
// messages_json holds the API transcript plus per-tool durations and Rune's step lists (per ask_rune call,
// for the page's rail; never its code): { messages, tool_ms, rune }.
export function getChat(id) {
  const r = chatRow.get(id)
  if (!r) return null
  const { messages_json, ...rest } = r
  const body = parse(messages_json) || {}
  const closed_reason = r.closed ? db.prepare('SELECT reason FROM scan_misuse WHERE chat_id = ? ORDER BY created_at DESC LIMIT 1').get(id)?.reason || null : null
  return { ...rest, closed_reason, messages: body.messages || [], tool_ms: body.tool_ms || {}, rune: body.rune || {} }
}
/** With `ip` (shared keys) only that visitor's chats are listed. */
export const listChats = (keyId, limit = 50, ip = null) => (ip ? chatsOfKeyIp.all(keyId, ip, limit) : chatsOfKey.all(keyId, limit))
/**
 * A finished first-turn Nyx analysis of the same file (any user), rewritten for `job`: forum users upload
 * the same cheats over and over, so the auto analysis is reused instead of paid for again. Only the first
 * turn is taken (never the other user's follow-up questions); their job id and file name are swapped out.
 */
// Owner's "analysis history clear": analyses made before this time are no longer copied (they stay in
// place, chats and reports included), so the same file gets a fresh Nyx + Rune analysis.
const reuseAfter = () => Number(db.prepare("SELECT v FROM scan_settings WHERE k = 'analysis_reuse_after'").get()?.v || 0)
export function clearAnalysisReuse() {
  const t = Date.now()
  db.prepare("INSERT INTO scan_settings (k, v) VALUES ('analysis_reuse_after', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(String(t))
  return { cleared_at: t }
}
// Owner, 2026-11-07: every upload gets its own fresh analysis (Nyx + Rune); copying is off until this
// setting is removed.
const reuseOff = () => db.prepare("SELECT v FROM scan_settings WHERE k = 'analysis_reuse_off'").get()?.v === '1'
export const setAnalysisReuseOff = (off) => db.prepare("INSERT INTO scan_settings (k, v) VALUES ('analysis_reuse_off', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(off ? '1' : '0')
export function reusableAnalysis(job, marker) {
  if (reuseOff()) return null
  const rows = db.prepare(`SELECT c.messages_json, j.id AS donor_job, j.file_name AS donor_name FROM scan_chats c JOIN scan_jobs j ON j.id = c.job_id
    WHERE j.sha256 = ? AND c.running = 0 AND c.closed = 0 AND c.created_at >= ? ORDER BY c.updated_at DESC LIMIT 20`).all(job.sha256, reuseAfter())
  const isPrompt = (m) => m?.role === 'user' && Array.isArray(m.content) && m.content.some((b) => b.type === 'text')
  for (const r of rows) {
    const saved = parse(r.messages_json) || {}
    const msgs = saved.messages || []
    if (!isPrompt(msgs[0]) || !msgs[0].content.find((b) => b.type === 'text').text.includes(marker)) continue
    let end = msgs.findIndex((m, i) => i > 0 && isPrompt(m))
    if (end < 0) end = msgs.length
    const turn = msgs.slice(0, end)
    const last = turn.at(-1)
    const answer = last?.role === 'assistant' && last.content.filter((b) => b.type === 'text').map((b) => b.text).join('')
    if (!answer || answer.length < 300) continue
    const esc = (s) => JSON.stringify(String(s)).slice(1, -1)
    let json = JSON.stringify(turn).split(r.donor_job).join(job.id)
    if (r.donor_name && r.donor_name !== job.file_name) json = json.split(esc(r.donor_name)).join(esc(job.file_name))
    return { messages: JSON.parse(json), toolMs: saved.tool_ms || {} }
  }
  return null
}

/** Every user's Nyx chats for the owner view: who (key label, IP), about which file, and whether a turn is running. */
export const listAllChats = (limit = 150) =>
  db.prepare(`SELECT c.id, c.title, c.job_id, c.created_at, c.updated_at, c.running, COALESCE(c.ip, j.ip) AS ip, k.label AS key_label, k.prefix AS key_prefix,
      j.file_name, j.verdict FROM scan_chats c LEFT JOIN scan_keys k ON k.id = c.key_id LEFT JOIN scan_jobs j ON j.id = c.job_id
    ORDER BY c.updated_at DESC LIMIT ?`).all(limit)
export function saveChat(id, { messages, toolMs, jobId, rune }) {
  const keep = rune === undefined ? parse(chatRow.get(id)?.messages_json)?.rune : rune
  db.prepare('UPDATE scan_chats SET messages_json = ?, job_id = COALESCE(?, job_id), updated_at = ? WHERE id = ?')
    .run(JSON.stringify({ messages, tool_ms: toolMs, ...(keep ? { rune: keep } : {}) }), jobId ?? null, now(), id)
}
export const deleteChat = (id) => db.prepare('DELETE FROM scan_chats WHERE id = ?').run(id)
export function setChatRunning(id, running, owner = false) {
  db.prepare('UPDATE scan_chats SET running = ?, run_owner = CASE WHEN ? THEN ? ELSE run_owner END WHERE id = ?').run(running ? 1 : 0, running ? 1 : 0, owner ? 1 : 0, id)
}
export const runningChats = () => db.prepare('SELECT id, key_id, run_owner FROM scan_chats WHERE running = 1').all()

// --- 2026-11-16: fuzzy hashes, link sources, re-checks -------------------------------------------
try { db.exec('ALTER TABLE scan_jobs ADD COLUMN tlsh TEXT') } catch { /* already there */ }
try { db.exec('ALTER TABLE scan_jobs ADD COLUMN ssdeep TEXT') } catch { /* already there */ }
// Where a link scan fetched the file from: { url, final_url, redirects, ip, content_type, host_kind }
try { db.exec('ALTER TABLE scan_jobs ADD COLUMN source_json TEXT') } catch { /* already there */ }
db.exec(`
  CREATE TABLE IF NOT EXISTS scan_watch (
    job_id TEXT PRIMARY KEY,
    round INTEGER NOT NULL DEFAULT 0,
    due_at INTEGER NOT NULL,
    history_json TEXT,
    changed INTEGER NOT NULL DEFAULT 0,
    seen INTEGER NOT NULL DEFAULT 1
  );
  CREATE INDEX IF NOT EXISTS scan_watch_due ON scan_watch (due_at);
  CREATE TABLE IF NOT EXISTS scan_labels (
    sha256 TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    note TEXT,
    job_id TEXT,
    created_at INTEGER NOT NULL
  );
`)
export const setJobFuzzy = (id, { tlsh, ssdeep }) => db.prepare('UPDATE scan_jobs SET tlsh = ?, ssdeep = ? WHERE id = ?').run(tlsh || null, ssdeep || null, id)
export const setJobSource = (id, src) => db.prepare('UPDATE scan_jobs SET source_json = ? WHERE id = ?').run(JSON.stringify(src), id)
/** Every other finished file with a fuzzy hash or an imphash, newest first (the similarity search space). */
export const fuzzyCandidates = (exceptSha, limit = 20000) =>
  db.prepare(`SELECT id, key_id, parent_id, file_name, sha256, tlsh, ssdeep, score, verdict, created_at, public, json_extract(static_json, '$.pe.imphash') AS imphash
    FROM scan_jobs WHERE status = 'done' AND sha256 != ? AND (tlsh IS NOT NULL OR ssdeep IS NOT NULL OR json_extract(static_json, '$.pe.imphash') IS NOT NULL)
    ORDER BY created_at DESC LIMIT ?`).all(exceptSha, limit)
export const familyOfJob = (id) => {
  const r = db.prepare('SELECT ai_json FROM scan_jobs WHERE id = ?').get(id)
  return parse(r?.ai_json)?.computed?.family || null
}

// Re-checks of finished root scans after 1, 3 and 7 days.
export const WATCH_DAYS = [1, 3, 7]
export const watchJob = (jobId, at) =>
  db.prepare('INSERT OR IGNORE INTO scan_watch (job_id, round, due_at, history_json) VALUES (?, 0, ?, ?)').run(jobId, at + WATCH_DAYS[0] * 86400_000, '[]')
export const dueWatches = (t, limit = 20) => db.prepare('SELECT * FROM scan_watch WHERE due_at <= ? ORDER BY due_at LIMIT ?').all(t, limit)
export function advanceWatch(jobId, entry, changed) {
  const w = db.prepare('SELECT * FROM scan_watch WHERE job_id = ?').get(jobId)
  if (!w) return
  const hist = [...(parse(w.history_json) || []), entry]
  const next = w.round + 1
  const job = db.prepare('SELECT created_at FROM scan_jobs WHERE id = ?').get(jobId)
  const due = next < WATCH_DAYS.length && job ? job.created_at + WATCH_DAYS[next] * 86400_000 : 8.64e15
  db.prepare('UPDATE scan_watch SET round = ?, due_at = ?, history_json = ?, changed = MAX(changed, ?), seen = CASE WHEN ? THEN 0 ELSE seen END WHERE job_id = ?')
    .run(next, due, JSON.stringify(hist), changed ? 1 : 0, changed ? 1 : 0, jobId)
}
export const watchOf = (jobId) => {
  const w = db.prepare('SELECT * FROM scan_watch WHERE job_id = ?').get(jobId)
  return w ? { round: w.round, next_at: w.due_at < 8e15 ? w.due_at : null, history: parse(w.history_json) || [], changed: !!w.changed, seen: !!w.seen } : null
}
export const markWatchSeen = (jobId) => db.prepare('UPDATE scan_watch SET seen = 1 WHERE job_id = ?').run(jobId)
export const unseenWatchChanges = (keyId) =>
  db.prepare('SELECT w.job_id FROM scan_watch w JOIN scan_jobs j ON j.id = w.job_id WHERE j.key_id = ? AND w.seen = 0').all(keyId).map((r) => r.job_id)

// Labelled files for the score regression check: owner overrides count as labels too.
export const setLabel = (sha256, verdict, note = '', jobId = null) =>
  db.prepare('INSERT INTO scan_labels (sha256, verdict, note, job_id, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(sha256) DO UPDATE SET verdict = excluded.verdict, note = excluded.note, job_id = COALESCE(excluded.job_id, scan_labels.job_id)')
    .run(sha256, verdict, note, jobId, now())
export const deleteLabel = (sha256) => db.prepare('DELETE FROM scan_labels WHERE sha256 = ?').run(sha256)
export const allLabels = () => db.prepare(`SELECT sha256, verdict, note, job_id, 'label' AS origin FROM scan_labels
  UNION ALL SELECT o.sha256, o.verdict, o.note, NULL, 'override' FROM scan_overrides o WHERE o.sha256 NOT IN (SELECT sha256 FROM scan_labels)`).all()
export const latestJobOf = (sha256) => db.prepare("SELECT id FROM scan_jobs WHERE sha256 = ? AND status = 'done' ORDER BY created_at DESC LIMIT 1").get(sha256)?.id || null

// Provider health: result counts per source and status since `since`, with error kinds.
export const providerStats = (since) => db.prepare(`SELECT source, status, COALESCE(error, '') AS error, count(*) AS n, avg(r.updated_at - j.created_at) AS avg_ms
  FROM scan_results r JOIN scan_jobs j ON j.id = r.job_id WHERE j.created_at >= ? GROUP BY source, status, COALESCE(error, '')`).all(since)
export const scanCounts = (since) => db.prepare(`SELECT count(*) AS total, sum(parent_id IS NULL) AS roots, sum(status = 'running') AS running,
  sum(verdict = 'malicious') AS malicious, sum(verdict = 'clean') AS clean FROM scan_jobs WHERE created_at >= ?`).get(since)
// Small per-day counters in the AI usage table ("<name>:<day>"; usd holds the count).
const day0 = () => new Date().toISOString().slice(0, 10)
export const counterToday = (name) => db.prepare('SELECT usd FROM scan_ai_usage WHERE day = ?').get(`${name}:${day0()}`)?.usd || 0
export const bumpCounter = (name) => db.prepare('INSERT INTO scan_ai_usage (day, usd) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET usd = usd + 1').run(`${name}:${day0()}`)
/** Puts one source of a job back in the queue with no task reference (a fresh lookup). */
export const resetResult = (jobId, source, layer) =>
  db.prepare("INSERT INTO scan_results (job_id, source, layer, status, ref, summary_json, error, updated_at) VALUES (?, ?, ?, 'queued', NULL, NULL, NULL, ?) ON CONFLICT(job_id, source) DO UPDATE SET status = 'queued', ref = NULL, error = NULL, updated_at = excluded.updated_at")
    .run(jobId, source, layer, now())
