// Example host: boots Fastify with the Scan routes and a minimal admin login.
//   node server.example.js
// Mint an access key (printed once; only its SHA-256 is stored):
//   node -e "import('./src/scan/db.js').then(m => console.log(m.createKey({ label: 'owner', dailyQuota: 1000 })))"
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import { timingSafeEqual } from 'node:crypto'
import { config } from './src/config.js'
import { createSession, destroySession } from './src/store.js'
import { registerScan } from './src/scan/index.js'

const app = Fastify({ trustProxy: '127.0.0.1', bodyLimit: 1024 * 1024 })
await app.register(cookie)

const ADMIN_COOKIE = 'cg_sess'
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y) }
app.post('/api/admin/login', async (req, reply) => {
  if (!config.adminPassword || !same(req.body?.password || '', config.adminPassword)) return reply.code(401).send({ ok: false, error: 'invalid_password' })
  reply.setCookie(ADMIN_COOKIE, createSession(config.sessionTtlMs), { httpOnly: true, secure: !config.insecureCookies, sameSite: 'strict', path: '/', maxAge: Math.floor(config.sessionTtlMs / 1000) })
  return { ok: true }
})
app.post('/api/admin/logout', async (req, reply) => { destroySession(req.cookies?.[ADMIN_COOKIE]); reply.clearCookie(ADMIN_COOKIE, { path: '/' }); return { ok: true } })

await registerScan(app)
await app.listen({ host: config.host, port: config.port })
console.log(`scan backend on http://${config.host}:${config.port}`)
