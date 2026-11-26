// Stand-in for the host app's config: only the fields the Scan module reads.
import 'dotenv/config'

const val = (name) => (process.env[name] || '').trim() || null

export const config = {
  port: Number(process.env.PORT || 8787),
  host: process.env.HOST || '127.0.0.1',
  publicUrl: (process.env.PUBLIC_URL || 'http://localhost:5180').replace(/\/+$/, ''),
  adminPassword: val('ADMIN_PASSWORD'),
  sessionSecret: val('SESSION_SECRET') || 'dev-insecure-secret-change-me',
  sessionTtlMs: 1000 * 60 * 60 * 12,
  insecureCookies: process.env.INSECURE_COOKIES === '1',
}
