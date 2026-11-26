// Samples are kept only encrypted (AES-256-GCM), so nothing on disk is runnable and Defender has
// nothing to quarantine. Plaintext exists only in memory while a file is sent to a scan service.

import { createCipheriv, createDecipheriv, createHash, randomBytes, hkdfSync } from 'node:crypto'
import { mkdirSync, writeFileSync, readFileSync, existsSync, unlinkSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { config } from '../config.js'

const DIR = fileURLToPath(new URL('../../data/scan/samples/', import.meta.url))
mkdirSync(DIR, { recursive: true })

// SCAN_ENC_KEY (64 hex chars) when set; otherwise derived from the session secret.
const KEY = /^[0-9a-f]{64}$/i.test(process.env.SCAN_ENC_KEY || '')
  ? Buffer.from(process.env.SCAN_ENC_KEY, 'hex')
  : Buffer.from(hkdfSync('sha256', config.sessionSecret, 'clashgear-scan', 'sample-key', 32))

const pathOf = (sha256) => `${DIR}${sha256}.bin`

export function hashes(buf) {
  const h = (a) => createHash(a).update(buf).digest('hex')
  return { md5: h('md5'), sha1: h('sha1'), sha256: h('sha256'), sha512: h('sha512') }
}

export function saveSample(sha256, buf) {
  if (existsSync(pathOf(sha256))) return
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', KEY, iv)
  const body = Buffer.concat([c.update(buf), c.final()])
  writeFileSync(pathOf(sha256), Buffer.concat([iv, c.getAuthTag(), body]))
}

export function loadSample(sha256) {
  if (!/^[0-9a-f]{64}$/.test(sha256) || !existsSync(pathOf(sha256))) return null
  const raw = readFileSync(pathOf(sha256))
  const d = createDecipheriv('aes-256-gcm', KEY, raw.subarray(0, 12))
  d.setAuthTag(raw.subarray(12, 28))
  return Buffer.concat([d.update(raw.subarray(28)), d.final()])
}

export function deleteSample(sha256) {
  try { unlinkSync(pathOf(sha256)) } catch { /* already gone */ }
}
