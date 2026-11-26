// CrowdSec watch: the local CrowdSec engine (Windows service, LAPI on CROWDSEC_LAPI) reads Caddy's
// access log and raises alerts for probing / exploit attempts. Its notification plugins don't run under
// the Windows service account, so the backend logs in to the LAPI as its own machine and polls new local
// alerts every minute, handing them to onCrowdsec (Discord DMs). Alerts that already existed when the
// backend started are skipped. Nothing is blocked: no bouncer is installed.

import { onCrowdsec } from './alerts.js'

const LAPI = process.env.CROWDSEC_LAPI || 'http://127.0.0.1:8089'
let token = null
let tokenExp = 0
let lastId = null
// The LAPI refuses the login with fetch's default "node" User-Agent, so send our own.
const UA = 'clashgear-backend/1.0'

async function login() {
  const res = await fetch(`${LAPI}/v1/watchers/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': UA },
    body: JSON.stringify({ machine_id: process.env.CROWDSEC_MACHINE_ID, password: process.env.CROWDSEC_MACHINE_PASSWORD, scenarios: [] }),
  })
  if (!res.ok) throw new Error(`login ${res.status}`)
  const j = await res.json()
  token = j.token
  tokenExp = Date.parse(j.expire) - 60_000
}

async function poll() {
  if (!token || Date.now() > tokenExp) await login()
  const res = await fetch(`${LAPI}/v1/alerts?since=6h&include_capi=false&limit=200`, { headers: { Authorization: `Bearer ${token}`, 'User-Agent': UA } })
  if (res.status === 401) { token = null; return }
  if (!res.ok) throw new Error(`alerts ${res.status}`)
  const alerts = (await res.json()) || []
  // A Caddy restart makes CrowdSec re-read old log lines and raise alerts for long-past events,
  // so only report alerts whose last event is recent.
  const fresh = lastId === null ? [] : alerts.filter((a) => a.id > lastId && Date.now() - Date.parse(a.stop_at) < 30 * 60_000)
  lastId = Math.max(lastId ?? 0, ...alerts.map((a) => a.id))
  if (fresh.length) onCrowdsec(fresh)
}

export function startCrowdsecWatch() {
  if (!process.env.CROWDSEC_MACHINE_ID) return
  const run = () => poll().catch((e) => console.error('crowdsec poll', String(e.message || e)))
  run()
  setInterval(run, 60_000).unref()
}
