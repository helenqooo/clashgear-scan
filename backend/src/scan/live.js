// Live sandbox: the key holder runs their file in our CAPE VM with CAPE's interactive mode on and
// drives the Windows desktop from the browser. The screen travels guacd (on the sandbox box) →
// SSH tunnel → guacamole-lite here → WebSocket to the page. Sessions live in memory: a backend
// restart ends them (the CAPE task itself still finishes and reports).

import { randomBytes, createHash, createCipheriv } from 'node:crypto'
import { createRequire } from 'node:module'
import { http, formWith } from './http.js'
import { loadSample } from './storage.js'
import { TUNNEL_GUACD_PORT, TUNNEL_FILES_PORT } from './tunnel.js'
import { CAPE_RUN_OPTIONS } from './providers/sandbox.js'

const require = createRequire(import.meta.url)
const GuacamoleLite = require('guacamole-lite')

export const LIVE_SECONDS = Math.max(60, Number(process.env.SCAN_LIVE_SECONDS) || 300)
const CAPE = () => (process.env.CAPE_URL || '').replace(/\/+$/, '')
const cape = (path, opts = {}) => http(`${CAPE()}${path}`, { ...opts, headers: { Authorization: `Token ${process.env.CAPE_API_KEY}`, ...(opts.headers || {}) } })
// VNC port of each CAPE machine on the sandbox host (libvirt display :0 = 5900).
const vncPort = (machine) => { try { return JSON.parse(process.env.CAPE_VNC_PORTS || '{}')[machine] || 5900 } catch { return 5900 } }
// Token key: derived from the scan encryption key so nothing new has to be configured.
const KEY = createHash('sha256').update(`live:${process.env.SCAN_ENC_KEY || ''}`).digest()

const sessions = new Map()
export const liveEnabled = () => !!(process.env.CAPE_URL && process.env.CAPE_API_KEY && process.env.CAPE_TUNNEL)

/** Submits the job's sample as an interactive CAPE task. */
export async function startLive({ job, keyId }) {
  const buf = loadSample(job.sha256)
  const up = await cape('/tasks/create/file/', {
    method: 'POST',
    // nohuman: CAPE's "human" module moves the mouse and clicks dialogs to fool sandbox checks; in a
    // live session the user is the human, so it must keep its hands off.
    body: formWith({ options: `interactive=1,nohuman=1,${CAPE_RUN_OPTIONS}`, timeout: String(LIVE_SECONDS), enforce_timeout: '1', priority: '3' }, buf, 'file', job.file_name),
    timeout: 120_000,
  })
  const taskId = up?.data?.task_ids?.[0]
  if (!taskId) throw new Error(up?.error_value || 'live_submit_failed')
  const id = randomBytes(9).toString('base64url')
  sessions.set(id, { id, jobId: job.id, keyId, taskId, fileName: job.file_name, status: 'queued', created: Date.now(), startedAt: null, machine: null })
  return sessions.get(id)
}

export const getLive = (id) => sessions.get(id) || null

/** Refreshes a session from CAPE; returns what the page needs (and a connect token once the VM runs). */
export async function liveStatus(s) {
  if (s.status === 'running' || s.status === 'queued' || s.status === 'starting') {
    const v = await cape(`/tasks/view/${s.taskId}/`).catch(() => null)
    const t = v?.data
    if (t) {
      if (t.status === 'running') {
        if (!s.startedAt) s.startedAt = Date.now()
        s.machine = t.guest?.name || t.machine || s.machine || 'win10'
        // The screen opens only once the file sits on the desktop (owner's ask); 2.5 min fallback.
        if (s.status !== 'running') s.status = (await onDesktop(s)) || Date.now() - s.startedAt > 150_000 ? 'running' : 'starting'
      } else if (['completed', 'reported', 'failed_analysis', 'failed_processing', 'failed_reporting'].includes(t.status)) {
        s.status = 'ended'
      } else {
        s.status = 'queued'
      }
    }
  }
  const left = s.startedAt ? Math.max(0, LIVE_SECONDS - Math.round((Date.now() - s.startedAt) / 1000)) : LIVE_SECONDS
  const out = { id: s.id, job_id: s.jobId, status: s.status, seconds: LIVE_SECONDS, left }
  if (s.status === 'running') out.token = connectToken(s)
  return out
}

// Asks the sandbox's file service whether the monitored desktop shell has seen the sample on the desktop.
async function onDesktop(s) {
  try {
    const r = await http(`http://127.0.0.1:${TUNNEL_FILES_PORT}/ready/${s.taskId}/${Buffer.from(s.fileName).toString('hex')}`, { headers: { Authorization: `Token ${process.env.CAPE_FILES_TOKEN}` }, timeout: 10_000 })
    return !!r?.ready
  } catch { return false }
}

/** Ends the analysis early (CAPE stops the VM and processes what it saw). */
export async function stopLive(s) {
  if (s.status === 'ended') return
  await cape(`/tasks/status/${s.taskId}/`, { method: 'POST', json: { status: 'finish' } }).catch(() => {})
  s.status = 'ended'
}

function connectToken(s) {
  const plain = JSON.stringify({
    connection: {
      type: 'vnc',
      settings: { hostname: '127.0.0.1', port: String(vncPort(s.machine)), 'color-depth': 16, cursor: 'local', 'disable-audio': true },
    },
    live: s.id,
    exp: Date.now() + 60_000,
  })
  // guacamole-lite decodes the IV as an ASCII string, so it must be printable bytes only
  const iv = Buffer.from(randomBytes(12).toString('base64').slice(0, 16), 'ascii')
  const c = createCipheriv('aes-256-cbc', KEY, iv)
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()])
  return Buffer.from(JSON.stringify({ iv: iv.toString('base64'), value: enc.toString('base64') })).toString('base64')
}

/** Attaches the guacamole WebSocket endpoint to the Fastify HTTP server. */
export function attachLiveSocket(server) {
  if (!liveEnabled()) return
  new GuacamoleLite(
    { server, path: '/api/scan/live/ws' },
    { host: '127.0.0.1', port: TUNNEL_GUACD_PORT },
    { crypt: { cypher: 'AES-256-CBC', key: KEY }, log: { level: 'ERRORS' }, maxInactivityTime: 30_000 },
    {
      // Tokens are short-lived and only work while their session's VM is running.
      processConnectionSettings: (settings, cb) => {
        const s = sessions.get(settings.live)
        if (!s || s.status !== 'running' || !(settings.exp > Date.now())) return cb(new Error('live_session_invalid'))
        cb(undefined, settings)
      },
    },
  )
}
