// Cloudflare Turnstile: free Nyx messages and new free keys carry a one-time token that only a real browser
// running Cloudflare's challenge can mint, so scripts and API relays (Nyx fed to an IDE as an OpenAI endpoint,
// 2026-11-05) can't use them. The secret stays here; the page gets the site key from /api/scan/info.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { config } from '../config.js'

export const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || ''
const SECRET = process.env.TURNSTILE_SECRET || ''
export const turnstileOn = () => !!(TURNSTILE_SITE_KEY && SECRET)
const HOST = new URL(config.publicUrl).hostname

/**
 * 'ok', 'missing' or 'invalid'. When Cloudflare itself can't be reached the request is let through ('ok'):
 * an outage there shouldn't take Nyx down for everyone, and the other limits still apply.
 */
export async function checkTurnstile(token, ip, action, cdata = null) {
  if (!turnstileOn()) return 'ok'
  if (!token || typeof token !== 'string' || token.length > 4096) return 'missing'
  let r
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: new URLSearchParams({ secret: SECRET, response: token, ...(ip ? { remoteip: ip } : {}) }),
      signal: AbortSignal.timeout(8000),
    })
    r = await res.json()
  } catch (e) {
    console.warn('turnstile unreachable, letting the request through:', String(e?.message || e))
    return 'ok'
  }
  if (!r?.success) return 'invalid'
  if (r.hostname && r.hostname !== HOST && r.hostname !== `www.${HOST}`) return 'invalid'
  if (action && r.action && r.action !== action) return 'invalid'
  // A Nyx token is minted for one message (cData = hash of its text): a token solved elsewhere can't carry another.
  if (cdata && r.cdata !== cdata) return 'invalid'
  return 'ok'
}

/* ------------------------------------------------------------ signed requests
 * Free Nyx messages also carry x-cg-ts / x-cg-sig: an HMAC over the time, chat, file and text hash with a key
 * derived from the visitor's session (handed to the page by /api/scan/session). A copied cookie alone is
 * not enough: a relay must also rebuild the page's signing code. Each signature works once, for 2 minutes. */
const SIG_SECRET = process.env.SCAN_SIG_SECRET || ''
const SIG_WINDOW = 120_000
const usedSigs = new Map() // sig -> expiry
setInterval(() => { const t = Date.now(); for (const [s, exp] of usedSigs) if (exp < t) usedSigs.delete(s) }, 60_000).unref()

export const sha256hex = (s) => createHash('sha256').update(String(s), 'utf8').digest('hex')
export const sigKeyFor = (sessionId) => (SIG_SECRET && sessionId ? createHmac('sha256', SIG_SECRET).update(`nyx:${sessionId}`).digest('hex') : null)

// Each frontend build writes a new salt here (clashgear-app/vite.config.ts cgSig); the previous one stays valid.
const SALT_FILE = fileURLToPath(new URL('../../data/sig_salt.json', import.meta.url))
let salts = { at: 0, list: [] }
export function currentSalts() {
  try {
    const m = statSync(SALT_FILE).mtimeMs
    if (m !== salts.at) { const j = JSON.parse(readFileSync(SALT_FILE, 'utf8')); salts = { at: m, list: [j.current, j.previous].filter((s) => /^[0-9a-f]{32}$/.test(s || '')) } }
  } catch { /* no build yet */ }
  return salts.list
}
/** The signed string, same as the page's (clashgear-app/src/lib/sig.ts): the salt picks the fields' order. */
export function sigBase(salt, { ts, chatId, jobId, text, dev }) {
  const fields = [String(ts), chatId || '', jobId || '', sha256hex(text), dev || '']
  const w = (i) => (parseInt(salt.slice(i * 2, i * 2 + 2), 16) || 0) ^ (i * 37)
  const order = [0, 1, 2, 3, 4].sort((a, b) => w(a) - w(b) || a - b)
  return `${salt.slice(0, 8)}|${order.map((i) => fields[i]).join('|')}|${salt.slice(8)}`
}

export function checkSignature(req, sessionId) {
  const key = sigKeyFor(sessionId)
  const list = currentSalts()
  if (!key || !list.length) return 'ok'
  const ts = Number(req.headers['x-cg-ts'])
  const sig = String(req.headers['x-cg-sig'] || '')
  if (!ts || !/^[0-9a-f]{64}$/.test(sig)) return 'missing'
  if (Math.abs(Date.now() - ts) > SIG_WINDOW) return 'stale'
  if (usedSigs.has(sig)) return 'replayed'
  const got = Buffer.from(sig, 'hex')
  const fields = { ts, chatId: req.body?.chat_id, jobId: req.body?.job_id, text: String(req.body?.text ?? ''), dev: String(req.headers['x-cg-dev'] || '') }
  const okSalt = list.some((salt) => { const want = createHmac('sha256', key).update(sigBase(salt, fields)).digest(); return got.length === want.length && timingSafeEqual(got, want) })
  if (!okSalt) return 'invalid'
  usedSigs.set(sig, Date.now() + SIG_WINDOW)
  return 'ok'
}
