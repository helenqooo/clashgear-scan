// Device fingerprint for free Scan keys (anti-abuse, owner 2026-11-05): a persistent device id kept in three
// places (localStorage, IndexedDB, a cookie; the server adds an httpOnly copy) plus browser/hardware signals.
// The backend links keys that share a device and alerts on Discord when someone who was flagged comes back
// on a new key. Every signal is best-effort: a failing one is just left out.

const DID = 'cg_did'
const enc = new TextEncoder()
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('')
export const sha256 = async (s: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)))
const safe = async <T,>(fn: () => T | Promise<T>): Promise<T | null> => { try { return await fn() } catch { return null } }

/* ------------------------------------------------------------ device id */
function idbGet(): Promise<string | null> {
  return new Promise((resolve) => {
    try {
      const open = indexedDB.open('cg', 1)
      open.onupgradeneeded = () => open.result.createObjectStore('kv')
      open.onerror = () => resolve(null)
      open.onsuccess = () => {
        try {
          const g = open.result.transaction('kv').objectStore('kv').get(DID)
          g.onsuccess = () => resolve(typeof g.result === 'string' ? g.result : null)
          g.onerror = () => resolve(null)
        } catch { resolve(null) }
      }
    } catch { resolve(null) }
  })
}
function idbSet(v: string) {
  try {
    const open = indexedDB.open('cg', 1)
    open.onupgradeneeded = () => open.result.createObjectStore('kv')
    open.onsuccess = () => { try { open.result.transaction('kv', 'readwrite').objectStore('kv').put(v, DID) } catch { /* private mode */ } }
  } catch { /* no IndexedDB */ }
}
const cookieGet = () => document.cookie.split('; ').find((c) => c.startsWith(`${DID}=`))?.slice(DID.length + 1) || null
const cookieSet = (v: string) => { document.cookie = `${DID}=${v}; Max-Age=63072000; Path=/; SameSite=Lax; Secure` }
const lsGet = () => { try { return localStorage.getItem(DID) } catch { return null } }
const lsSet = (v: string) => { try { localStorage.setItem(DID, v) } catch { /* blocked */ } }
const valid = (v: string | null) => (v && /^[0-9a-f]{32}$/.test(v) ? v : null)

let didPromise: Promise<{ id: string; restoredFrom: string[] }> | null = null
/** The device id, restored from whichever store still has it and written back to all of them. */
export function deviceId() {
  return (didPromise ||= (async () => {
    const found = { ls: valid(lsGet()), idb: valid(await idbGet()), cookie: valid(cookieGet()) }
    const id = found.ls || found.idb || found.cookie || hex(crypto.getRandomValues(new Uint8Array(16)).buffer)
    lsSet(id); idbSet(id); cookieSet(id)
    return { id, restoredFrom: Object.entries(found).filter(([, v]) => v === id).map(([k]) => k) }
  })())
}

/* ------------------------------------------------------------ signals */
function canvasSig() {
  const c = document.createElement('canvas'); c.width = 280; c.height = 60
  const x = c.getContext('2d')!
  x.textBaseline = 'top'; x.font = '16px Arial'; x.fillStyle = '#f60'; x.fillRect(120, 1, 62, 20)
  x.fillStyle = '#069'; x.fillText('ClashGear Scan ✓ 😃 ğüşöç', 2, 15)
  x.fillStyle = 'rgba(102,204,0,0.7)'; x.fillText('ClashGear Scan ✓ 😃 ğüşöç', 4, 17)
  x.globalCompositeOperation = 'multiply'; x.fillStyle = 'rgb(255,0,255)'; x.beginPath(); x.arc(50, 30, 25, 0, Math.PI * 2); x.fill()
  return c.toDataURL()
}
function webglSig() {
  const c = document.createElement('canvas')
  const gl = (c.getContext('webgl') || c.getContext('experimental-webgl')) as WebGLRenderingContext | null
  if (!gl) return null
  const dbg = gl.getExtension('WEBGL_debug_renderer_info')
  const p = (k: number) => { try { const v = gl.getParameter(k); return v && typeof v === 'object' ? Array.from(v as ArrayLike<number>).join(',') : String(v) } catch { return '' } }
  return {
    vendor: dbg ? String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)) : p(gl.VENDOR),
    renderer: dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) : p(gl.RENDERER),
    params: [gl.MAX_TEXTURE_SIZE, gl.MAX_RENDERBUFFER_SIZE, gl.MAX_VIEWPORT_DIMS, gl.ALIASED_LINE_WIDTH_RANGE, gl.ALIASED_POINT_SIZE_RANGE,
      gl.MAX_VERTEX_ATTRIBS, gl.MAX_VERTEX_UNIFORM_VECTORS, gl.MAX_FRAGMENT_UNIFORM_VECTORS, gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS, gl.SHADING_LANGUAGE_VERSION].map(p).join('|'),
    extensions: (gl.getSupportedExtensions() || []).join(','),
  }
}
async function audioSig() {
  const Ctx = (window as any).OfflineAudioContext || (window as any).webkitOfflineAudioContext
  if (!Ctx) return null
  const ctx = new Ctx(1, 5000, 44100)
  const osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 10000
  const comp = ctx.createDynamicsCompressor()
  comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12; comp.attack.value = 0; comp.release.value = 0.25
  osc.connect(comp); comp.connect(ctx.destination); osc.start(0)
  const buf: AudioBuffer = await Promise.race([ctx.startRendering(), new Promise<never>((_, rej) => setTimeout(() => rej(new Error('audio timeout')), 1500))])
  const d = buf.getChannelData(0)
  let s = 0
  for (let i = 4500; i < 5000; i++) s += Math.abs(d[i])
  return s.toFixed(10)
}
const FONTS = ['Arial', 'Arial Black', 'Bahnschrift', 'Calibri', 'Cambria', 'Candara', 'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel', 'Courier New',
  'Ebrima', 'Franklin Gothic Medium', 'Gabriola', 'Gadugi', 'Georgia', 'HoloLens MDL2 Assets', 'Impact', 'Ink Free', 'Javanese Text', 'Leelawadee UI',
  'Lucida Console', 'Lucida Sans Unicode', 'Malgun Gothic', 'Marlett', 'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft YaHei', 'MS Gothic',
  'MV Boli', 'Myanmar Text', 'Nirmala UI', 'Palatino Linotype', 'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Emoji', 'SimSun', 'Sitka Text',
  'Sylfaen', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Yu Gothic', 'Helvetica Neue', 'Menlo', 'Monaco', 'San Francisco', 'Avenir',
  'Futura', 'Gill Sans', 'Optima', 'Ubuntu', 'DejaVu Sans', 'Liberation Sans', 'Noto Sans', 'Roboto', 'Cantarell', 'Fira Sans', 'Source Code Pro',
  'Adobe Arabic', 'Minion Pro', 'Myriad Pro', 'Discord', 'Steam', 'Agency FB', 'Bauhaus 93', 'Broadway', 'Chiller', 'Jokerman', 'Papyrus']
function fontsSig() {
  const x = document.createElement('canvas').getContext('2d')!
  const w = (f: string) => { x.font = `72px ${f}`; return x.measureText('mmmmmmmmmmlli1WQ@').width }
  const base = ['monospace', 'sans-serif', 'serif'].map(w)
  return FONTS.filter((f) => ['monospace', 'sans-serif', 'serif'].some((b, i) => w(`'${f}',${b}`) !== base[i]))
}
async function mediaSig() {
  if (!navigator.mediaDevices?.enumerateDevices) return null
  const ds = await navigator.mediaDevices.enumerateDevices()
  const n = (k: string) => ds.filter((d) => d.kind === k).length
  return `${n('audioinput')}/${n('videoinput')}/${n('audiooutput')}`
}
function voicesSig() {
  const v = window.speechSynthesis?.getVoices?.() || []
  return v.map((x) => `${x.name}:${x.lang}`).sort().join(',') || null
}
function mathSig() {
  return [Math.acos(0.123124234234234242), Math.acosh(1e308), Math.asinh(1), Math.atanh(0.5), Math.expm1(1), Math.sinh(1), Math.cosh(10), Math.tan(-1e300), Math.log1p(10), Math.cbrt(100)].join(',')
}

export type Fingerprint = { device_id: string; restored_from: string[]; hash: string; hard_hash: string; components: Record<string, unknown> }

let fpPromise: Promise<Fingerprint> | null = null
export function fingerprint(): Promise<Fingerprint> {
  return (fpPromise ||= (async () => {
    const nav = navigator as any
    const uaData = await safe(() => nav.userAgentData?.getHighEntropyValues?.(['platform', 'platformVersion', 'architecture', 'bitness', 'model', 'fullVersionList', 'wow64']))
    const [canvas, audio, media, storage] = await Promise.all([
      safe(async () => (await sha256(canvasSig())).slice(0, 32)),
      safe(audioSig),
      safe(mediaSig),
      safe(async () => (await navigator.storage?.estimate?.())?.quota ?? null),
    ])
    const webgl = await safe(webglSig)
    const fonts = await safe(fontsSig)
    const components: Record<string, unknown> = {
      ua: navigator.userAgent, ua_data: uaData, platform: navigator.platform, vendor: navigator.vendor,
      languages: navigator.languages, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, tz_offset: new Date().getTimezoneOffset(),
      screen: `${screen.width}x${screen.height}@${devicePixelRatio}`, avail: `${screen.availWidth}x${screen.availHeight}`, color_depth: screen.colorDepth,
      cores: navigator.hardwareConcurrency, memory: nav.deviceMemory ?? null, touch: navigator.maxTouchPoints,
      webdriver: !!nav.webdriver, cookies: navigator.cookieEnabled, dnt: navigator.doNotTrack, pdf: nav.pdfViewerEnabled ?? null,
      connection: nav.connection ? `${nav.connection.effectiveType}/${nav.connection.rtt}/${nav.connection.downlink}` : null,
      canvas, webgl_vendor: webgl?.vendor ?? null, webgl_renderer: webgl?.renderer ?? null,
      webgl_hash: webgl ? (await sha256(`${webgl.params}#${webgl.extensions}`)).slice(0, 32) : null,
      audio, fonts, fonts_hash: fonts ? (await sha256(fonts.join(','))).slice(0, 16) : null, media, storage_quota: storage,
      voices_hash: await safe(async () => { const v = voicesSig(); return v ? (await sha256(v)).slice(0, 16) : null }),
      math: (await sha256(mathSig())).slice(0, 16), plugins: Array.from(navigator.plugins || [], (p) => p.name).join(','),
    }
    // hard_hash: hardware/OS level signals only (survives browser updates and a different browser on the same PC);
    // hash: everything stable for this browser profile.
    const hard = [components.canvas, components.webgl_renderer, components.webgl_hash, components.audio, components.fonts_hash, components.screen, components.cores, components.memory, components.tz, components.math]
    const soft = [...hard, components.platform, components.languages, components.voices_hash, components.media, components.plugins, (uaData as any)?.platformVersion, (uaData as any)?.model]
    const { id, restoredFrom } = await deviceId()
    return {
      device_id: id, restored_from: restoredFrom,
      hard_hash: (await sha256(JSON.stringify(hard))).slice(0, 32),
      hash: (await sha256(JSON.stringify(soft))).slice(0, 32),
      components,
    }
  })())
}
