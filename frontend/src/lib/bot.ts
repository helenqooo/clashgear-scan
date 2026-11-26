// Automation signals for free Nyx messages (shipped obfuscated, see vite.config.ts cgSig). The backend scores
// them (clashgear-backend/src/scan/botcheck.js): strong signs of Playwright / Puppeteer / Selenium block the
// message, weak ones only alert. They travel inside the sealed request body.

export type BotSignals = Record<string, string | number | boolean | null>
// Chrome DevTools Protocol: automation tools enable the Runtime domain, which serialises console arguments
// and so reads an Error's stack (an open DevTools window does the same).
function cdpProbe(): boolean {
  let hit = false
  try {
    const e = new Error('')
    Object.defineProperty(e, 'stack', { configurable: true, get() { hit = true; return '' } })
    // eslint-disable-next-line no-console
    console.debug(e)
  } catch { /* ignore */ }
  return hit
}
const GLOBALS = ['__playwright__binding__', '__pwInitScripts', '__playwright_evaluation_script__', '_phantom', 'callPhantom', '__nightmare', 'domAutomation',
  'domAutomationController', '__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate',
  '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium',
  '$chrome_asyncScriptInfo', '__lastWatirAlert', '__lastWatirConfirm', '__lastWatirPrompt', 'Cypress', '__puppeteer_evaluation_script__']

// Owner, 2026-11-06: desktop screens of exactly 1280×720 (the automation default) get the 403 page
// (components/Denied.tsx) instead of the site. Kept here so it ships obfuscated.
export function deniedScreen(): boolean {
  // Phones and iPads only (iPadOS reports a Mac UA with touch); touch-screen Windows laptops are still checked.
  const ua = navigator.userAgent
  const mobile = /Android|iPhone|iPad|Mobile/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)
  return !mobile && screen.width === 1280 && screen.height === 720
}

export async function botSignals(): Promise<BotSignals> {
  const nav = navigator as any
  const w = window as any
  const ua = navigator.userAgent
  const isChrome = /Chrome\//.test(ua) && !/Edg\/|OPR\//.test(ua)
  const mobile = /Android|iPhone|iPad|Mobile/i.test(ua) || navigator.maxTouchPoints > 1
  const globals = GLOBALS.filter((g) => g in w).concat(Object.keys(document).filter((k) => /^\$?cdc_|^\$wdc_/.test(k)))
  let gl = ''
  try {
    const c = document.createElement('canvas').getContext('webgl') as WebGLRenderingContext | null
    const d = c?.getExtension('WEBGL_debug_renderer_info')
    gl = d && c ? String(c.getParameter(d.UNMASKED_RENDERER_WEBGL)) : ''
  } catch { /* none */ }
  let permMismatch: boolean | null = null
  try {
    const st = await navigator.permissions.query({ name: 'notifications' as PermissionName })
    permMismatch = (window as any).Notification?.permission === 'denied' && st.state === 'prompt'
  } catch { /* unsupported */ }
  return {
    webdriver: !!nav.webdriver,
    headless_ua: /HeadlessChrome|PhantomJS|SlimerJS/i.test(ua),
    globals: globals.join(',') || null,
    cdp: cdpProbe(),
    outer_zero: window.outerWidth === 0 || window.outerHeight === 0,
    no_chrome_ui: !mobile && window.outerHeight - window.innerHeight < 1 && window.outerWidth - window.innerWidth < 1,
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    screen: `${screen.width}x${screen.height}`,
    soft_gl: /SwiftShader|llvmpipe|Basic Render|softpipe|Mesa OffScreen/i.test(gl),
    plugins: navigator.plugins?.length ?? 0,
    chrome_obj: isChrome ? !!w.chrome : null,
    perm_mismatch: permMismatch,
    langs: (navigator.languages || []).length,
    brands_ok: nav.userAgentData ? (nav.userAgentData.brands || []).some((b: any) => /Chrom|Edge|Opera|Brave/i.test(b.brand)) === /Chrome\//.test(ua) : null,
    mobile,
    visible: document.visibilityState === 'visible',
    focus: document.hasFocus(),
  }
}
