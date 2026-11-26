import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import { fileURLToPath, URL } from 'node:url'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { randomBytes } from 'node:crypto'
import JavaScriptObfuscator from 'javascript-obfuscator'

// Nyx request signing (src/lib/sig.ts), the device fingerprint (src/lib/fp.ts) and bot signals (src/lib/bot.ts)
// ship obfuscated, and each build gives the signature a fresh salt. The backend reads it from
// backend/data/sig_salt.json; the previous salt stays valid so pages opened before a deploy keep working.
const SALT_FILE = fileURLToPath(new URL('../backend/data/sig_salt.json', import.meta.url))
function cgSig(): Plugin {
  let salt = ''
  return {
    name: 'cg-sig',
    apply: 'build',
    enforce: 'post',
    buildStart() {
      salt = randomBytes(16).toString('hex')
      let previous: string | null = null
      try { previous = JSON.parse(readFileSync(SALT_FILE, 'utf8')).current || null } catch { /* first build */ }
      mkdirSync(dirname(SALT_FILE), { recursive: true })
      writeFileSync(SALT_FILE, JSON.stringify({ current: salt, previous, at: Date.now() }))
    },
    transform(code, id) {
      const file = id.replace(/\\/g, '/')
      if (!/\/src\/lib\/(sig|fp|bot)\.ts$/.test(file)) return null
      const src = code.replace(/__CG_SIG_SALT__/g, salt)
      const out = JavaScriptObfuscator.obfuscate(src, {
        compact: true, controlFlowFlattening: true, controlFlowFlatteningThreshold: 0.75, deadCodeInjection: true, deadCodeInjectionThreshold: 0.3,
        identifierNamesGenerator: 'hexadecimal', numbersToExpressions: true, splitStrings: true, splitStringsChunkLength: 6,
        stringArray: true, stringArrayEncoding: ['rc4'], stringArrayThreshold: 1, stringArrayWrappersCount: 2, transformObjectKeys: true,
        renameGlobals: false, selfDefending: false, sourceMap: false, seed: parseInt(salt.slice(0, 8), 16),
      })
      return { code: out.getObfuscatedCode(), map: null }
    },
  }
}

export default defineConfig({
  plugins: [react(), cgSig()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: { port: 5180, strictPort: true, proxy: { '/api': 'http://127.0.0.1:8787' } },
})
