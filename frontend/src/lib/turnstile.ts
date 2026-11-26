// Cloudflare Turnstile tokens for free Nyx messages and new keys (the backend checks them, see
// clashgear-backend/src/scan/turnstile.js). Each call renders a fresh widget that stays hidden unless
// Cloudflare wants an interaction, and resolves with its one-time token.

type TurnstileApi = {
  render: (el: HTMLElement, opts: Record<string, unknown>) => string
  remove: (id: string) => void
}
declare global { interface Window { turnstile?: TurnstileApi } }

const SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
let loading: Promise<void> | null = null
const load = () => (loading ||= new Promise<void>((resolve, reject) => {
  if (window.turnstile) return resolve()
  const s = document.createElement('script')
  s.src = SRC
  s.async = true
  s.onload = () => resolve()
  s.onerror = () => { loading = null; reject(new Error('turnstile_load_failed')) }
  document.head.appendChild(s)
}))

/** Preloads the script so the first message doesn't wait for it. */
export const preloadTurnstile = () => { load().catch(() => {}) }

export async function turnstileToken(siteKey: string, action: string, cData?: string): Promise<string> {
  await load()
  return new Promise((resolve, reject) => {
    const el = document.createElement('div')
    el.style.cssText = 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:300'
    document.body.appendChild(el)
    let id = ''
    const finish = (fn: () => void) => { try { if (id) window.turnstile?.remove(id) } catch { /* already gone */ } el.remove(); fn() }
    id = window.turnstile!.render(el, {
      sitekey: siteKey,
      action,
      ...(cData ? { cData } : {}),
      appearance: 'interaction-only',
      theme: 'dark',
      language: 'tr',
      callback: (t: string) => finish(() => resolve(t)),
      'error-callback': () => finish(() => reject(new Error('turnstile_failed'))),
      'timeout-callback': () => finish(() => reject(new Error('turnstile_timeout'))),
    })
  })
}
