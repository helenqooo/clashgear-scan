// Free Nyx messages leave the page sealed (shipped obfuscated; a fresh salt every build, see vite.config.ts
// cgSig). Every 5 minutes (an "epoch", on the server's clock) the AES key, the JSON field that carries the
// ciphertext and the URL path all change, decoy fields ride along, and the request is signed
// (x-cg-ts / x-cg-sig / x-cg-dev). The backend derives the same values (clashgear-backend/src/scan/seal.js).
const SALT = '__CG_SIG_SALT__'
export const EPOCH_MS = 300_000

const enc = new TextEncoder()
const hex = (b: ArrayBuffer | Uint8Array) => Array.from(b instanceof Uint8Array ? b : new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('')
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
const sha256 = async (s: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)))
async function hmac(key: string, msg: string) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)))
}
/** A field name from bytes: 6-11 lowercase letters. */
const word = (b: Uint8Array) => Array.from(b.slice(1, 7 + (b[0] % 6)), (x) => String.fromCharCode(97 + (x % 26))).join('')

/** Field order for this salt: the 5 signed fields sorted by a weight taken from the salt's bytes. */
function order(salt: string) {
  const w = (i: number) => (parseInt(salt.slice(i * 2, i * 2 + 2), 16) || 0) ^ (i * 37)
  return [0, 1, 2, 3, 4].sort((a, b) => w(a) - w(b) || a - b)
}

type Body = { chat_id?: string | null; job_id?: string | null; text: string; [k: string]: unknown }

async function sign(sigKey: string, deviceId: string, body: Body, ts: number) {
  const fields = [String(ts), body.chat_id || '', body.job_id || '', await sha256(body.text), deviceId]
  const base = `${SALT.slice(0, 8)}|${order(SALT).map((i) => fields[i]).join('|')}|${SALT.slice(8)}`
  return { 'x-cg-ts': String(ts), 'x-cg-dev': deviceId, 'x-cg-sig': hex(await hmac(sigKey, base)) }
}

/** The request for one free Nyx message: where to send it, its headers and its sealed JSON body. */
export async function sealNyx(sigKey: string, deviceId: string, body: Body, clockOffset: number) {
  const ts = Date.now() + clockOffset
  const epoch = Math.floor(ts / EPOCH_MS)
  const [kRaw, fRaw, pRaw] = await Promise.all(['k', 'f', 'p'].map((x) => hmac(sigKey, `${SALT}:${epoch}:${x}`)))
  const aes = await crypto.subtle.importKey('raw', kRaw, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plain = enc.encode(JSON.stringify({ ...body, n: hex(crypto.getRandomValues(new Uint8Array(8))) }))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, plain))
  const sealed = new Uint8Array(iv.length + ct.length); sealed.set(iv); sealed.set(ct, iv.length)
  const entries: [string, string][] = [[word(fRaw), b64(sealed)]]
  const decoys = 2 + (crypto.getRandomValues(new Uint8Array(1))[0] % 3)
  for (let i = 0; i < decoys; i++) {
    const r = crypto.getRandomValues(new Uint8Array(12 + (sealed.length % 40) + i * 7))
    entries.push([word(crypto.getRandomValues(new Uint8Array(12))), b64(r)])
  }
  entries.sort(() => crypto.getRandomValues(new Uint8Array(1))[0] - 128)
  return {
    path: `/api/scan/x/${hex(pRaw).slice(0, 12)}`,
    headers: await sign(sigKey, deviceId, body, ts),
    body: JSON.stringify(Object.fromEntries(entries)),
  }
}
