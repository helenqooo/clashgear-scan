// Small helpers every scan provider uses: JSON over fetch with a timeout, multipart bodies,
// a per-service rate limiter and a polling loop.

export class HttpError extends Error {
  constructor(status, message, body) {
    super(message)
    this.status = status
    this.body = body
  }
}

export async function http(url, { method = 'GET', headers = {}, body, json, timeout = 60_000, raw = false } = {}) {
  const init = { method, headers: { 'User-Agent': 'ClashGear-Scan/1.0', ...headers }, signal: AbortSignal.timeout(timeout) }
  if (json !== undefined) {
    init.body = JSON.stringify(json)
    init.headers['Content-Type'] = 'application/json'
  } else if (body !== undefined) {
    init.body = body
  }
  const res = await fetch(url, init)
  if (raw) {
    if (!res.ok) throw new HttpError(res.status, `HTTP ${res.status}`)
    return Buffer.from(await res.arrayBuffer())
  }
  const text = await res.text()
  let data = text
  try { data = text ? JSON.parse(text) : null } catch { /* not JSON */ }
  if (!res.ok) {
    const msg = (data && typeof data === 'object' && (data.message || data.error?.message || data.error || data.detail)) || `HTTP ${res.status}`
    throw new HttpError(res.status, String(typeof msg === 'string' ? msg : JSON.stringify(msg)).slice(0, 300), data)
  }
  return data
}

/** multipart/form-data with the sample attached under `field`. */
export function formWith(fields = {}, file = null, field = 'file', name = 'sample') {
  const fd = new FormData()
  for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== null) fd.append(k, typeof v === 'string' ? v : JSON.stringify(v))
  if (file) fd.append(field, new Blob([file]), name)
  return fd
}

export const urlForm = (fields) => new URLSearchParams(Object.entries(fields).filter(([, v]) => v != null).map(([k, v]) => [k, String(v)]))

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Requests per minute, per service.
const windows = new Map()
export async function limit(id, rpm) {
  if (!rpm) return
  for (;;) {
    const now = Date.now()
    const w = (windows.get(id) || []).filter((t) => now - t < 60_000)
    if (w.length < rpm) { w.push(now); windows.set(id, w); return }
    windows.set(id, w)
    await sleep(60_000 - (now - w[0]) + 50)
  }
}

/** Calls `check` until it returns a non-null value or the time runs out. */
export async function poll(check, { every = 20_000, timeout = 25 * 60_000 } = {}) {
  const end = Date.now() + timeout
  for (;;) {
    const v = await check()
    if (v != null) return v
    if (Date.now() + every > end) throw new Error('timeout')
    await sleep(every)
  }
}
