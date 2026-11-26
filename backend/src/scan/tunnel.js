// Encrypted link to our CAPE box: an SSH session as the restricted "cgtunnel" user that may only forward
// the CAPE API (127.0.0.1:8000), guacd (127.0.0.1:4822), the captured-file service (127.0.0.1:8001),
// Nyx's Ghidra decompiler (127.0.0.1:8002) the Motion film renderer (127.0.0.1:8003),
// the link fetcher (127.0.0.1:8004) and the static engines (127.0.0.1:8005).
// None of them is reachable from the internet;
// the backend supervises the ssh process and restarts it whenever it drops.

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

const SSH = 'C:\\Windows\\System32\\OpenSSH\\ssh.exe'
const DATA = join(process.cwd(), 'data')
export const TUNNEL_API_PORT = 18000
export const TUNNEL_GUACD_PORT = 14822
export const TUNNEL_FILES_PORT = 18001
export const TUNNEL_GHIDRA_PORT = 18002
export const TUNNEL_MOTION_PORT = 18003
export const TUNNEL_FETCH_PORT = 18004
export const TUNNEL_STATIC_PORT = 18005

let child = null
let stopping = false
let backoff = 2000
export const tunnelState = { up: false, since: null, restarts: 0, lastError: '' }

function start() {
  const target = process.env.CAPE_TUNNEL
  const key = join(DATA, 'cape_tunnel')
  if (!target || !existsSync(key)) return
  child = spawn(SSH, [
    '-N', '-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
    '-o', `UserKnownHostsFile=${join(DATA, 'cape_known_hosts')}`, '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3',
    '-L', `127.0.0.1:${TUNNEL_API_PORT}:127.0.0.1:8000`,
    '-L', `127.0.0.1:${TUNNEL_GUACD_PORT}:127.0.0.1:4822`,
    '-L', `127.0.0.1:${TUNNEL_FILES_PORT}:127.0.0.1:8001`,
    '-L', `127.0.0.1:${TUNNEL_GHIDRA_PORT}:127.0.0.1:8002`,
    '-L', `127.0.0.1:${TUNNEL_MOTION_PORT}:127.0.0.1:8003`,
    '-L', `127.0.0.1:${TUNNEL_FETCH_PORT}:127.0.0.1:8004`,
    '-L', `127.0.0.1:${TUNNEL_STATIC_PORT}:127.0.0.1:8005`,
    target,
  ], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] })
  const started = Date.now()
  tunnelState.up = true
  tunnelState.since = started
  child.stderr.on('data', (d) => { tunnelState.lastError = String(d).trim().slice(-300) })
  child.on('exit', (code) => {
    tunnelState.up = false
    child = null
    if (stopping) return
    // a session that lived a while resets the backoff; quick failures back off up to a minute
    backoff = Date.now() - started > 60_000 ? 2000 : Math.min(backoff * 2, 60_000)
    tunnelState.restarts++
    console.error(`cape tunnel exited (${code}) ${tunnelState.lastError}; retrying in ${backoff / 1000}s`)
    setTimeout(start, backoff)
  })
}

export function startTunnel() {
  if (child || !process.env.CAPE_TUNNEL) return
  start()
  const stop = () => { stopping = true; child?.kill() }
  process.once('exit', stop)
}
