// Stand-in for the host app's store: the shared sqlite handle plus admin sessions.
import { DatabaseSync } from 'node:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))
const dbPath = process.env.DB_PATH || resolve(here, '..', 'data', 'app.db')
mkdirSync(dirname(dbPath), { recursive: true })

export const db = new DatabaseSync(dbPath)
db.exec(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);`)

const ins = db.prepare('INSERT INTO sessions (id, created_at, expires_at) VALUES (?, ?, ?)')
const get = db.prepare('SELECT expires_at FROM sessions WHERE id = ?')
const del = db.prepare('DELETE FROM sessions WHERE id = ?')

export function createSession(ttlMs) {
  const id = randomBytes(32).toString('hex')
  const now = Date.now()
  ins.run(id, now, now + ttlMs)
  return id
}
export function sessionValid(id) {
  if (!id) return false
  const row = get.get(id)
  if (!row) return false
  if (row.expires_at < Date.now()) { del.run(id); return false }
  return true
}
export const destroySession = (id) => id && del.run(id)
