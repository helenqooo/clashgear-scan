// Opens a sealed free Nyx request (clashgear-app/src/lib/sig.ts sealNyx): per 5-minute epoch on our clock,
// the URL tag, the JSON field holding the ciphertext and the AES-GCM key are all derived from the session's
// signing key and the build salt. The previous and next epoch are accepted for requests crossing a boundary.

import { createHmac, createDecipheriv } from 'node:crypto'
import { sigKeyFor, currentSalts } from './turnstile.js'

const EPOCH_MS = 300_000
const hmac = (key, msg) => createHmac('sha256', key).update(msg).digest()
/** Same as the page: 6-11 lowercase letters from the bytes. */
const word = (b) => Array.from(b.subarray(1, 7 + (b[0] % 6)), (x) => String.fromCharCode(97 + (x % 26))).join('')

/** The decrypted inner body, or null (wrong tag / epoch / field / key / tampered). */
export function openSealed(sessionId, tag, outer) {
  const key = sigKeyFor(sessionId)
  if (!key || !/^[0-9a-f]{12}$/.test(String(tag || '')) || !outer || typeof outer !== 'object') return null
  const cur = Math.floor(Date.now() / EPOCH_MS)
  for (const salt of currentSalts()) {
    for (const epoch of [cur, cur - 1, cur + 1]) {
      if (hmac(key, `${salt}:${epoch}:p`).toString('hex').slice(0, 12) !== tag) continue
      const value = outer[word(hmac(key, `${salt}:${epoch}:f`))]
      if (typeof value !== 'string' || value.length > 200_000) return null
      try {
        const buf = Buffer.from(value, 'base64')
        if (buf.length < 12 + 16 + 2) return null
        const d = createDecipheriv('aes-256-gcm', hmac(key, `${salt}:${epoch}:k`), buf.subarray(0, 12))
        d.setAuthTag(buf.subarray(buf.length - 16))
        const plain = Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString('utf8')
        const body = JSON.parse(plain)
        return body && typeof body === 'object' ? body : null
      } catch { return null }
    }
  }
  return null
}
