import { ApiError } from './api'
import { turnstileToken } from './turnstile'
import { sealNyx } from './sig'
import { botSignals } from './bot'
import { deviceId, fingerprint, sha256 as fpSha256 } from './fp'

// Free Nyx messages and new keys carry a Cloudflare Turnstile token; the site key comes from /api/scan/info.
let siteKey: Promise<string | null> | null = null
const turnstileKey = () => (siteKey ||= fetch('/api/scan/info').then((r) => r.json()).then((j) => j?.data?.turnstile_site_key || null).catch(() => { siteKey = null; return null }))
async function humanToken(action: string, cData?: string): Promise<string | null> {
  const key = await turnstileKey()
  return key ? turnstileToken(key, action, cData) : null
}

// Free Nyx messages are signed with the session's key (lib/sig.ts); the backend rebuilds the same string
// and checks it once. Signed-in free keys also report their device (lib/fp.ts) once per page load.
// The session also tells the server's clock, so the 5-minute sealing epochs match even on a wrong device clock.
let sigKey: Promise<{ key: string; offset: number } | null> | null = null
const signingKey = () => (sigKey ||= call<ScanSession>('/scan/session').then((s) => (s.sig_key ? { key: s.sig_key, offset: (s.now || Date.now()) - Date.now() } : null))
  .catch(() => { sigKey = null; return null }))
/** Forget the cached key (sign-in / sign-out changes the session). */
export const resetSigning = () => { sigKey = null; reported = false }
type TurnBody = { chat_id?: string | null; text: string; job_id?: string | null; auto?: boolean; cf_token?: string | null }
/** Free keys: the sealed request (rotating path, encrypted body, signature, automation signals). Owner: plain. */
async function chatRequest(body: TurnBody): Promise<{ url: string; headers: Record<string, string>; body: string }> {
  const s = await signingKey()
  if (!s) return { url: '/api/scan/chat', headers: {}, body: JSON.stringify(body) }
  const sealed = await sealNyx(s.key, (await deviceId()).id, { ...body, b: await botSignals() }, s.offset)
  return { url: sealed.path, headers: sealed.headers, body: sealed.body }
}
let reported = false
function reportDevice() {
  if (reported) return
  reported = true
  fingerprint().then((fp) => call('/scan/fp', { body: fp })).catch(() => { reported = false })
}

// A free-tier request refused for coming through a VPN/proxy/Tor opens the 'İyi deneme, federal!' window.
const vpnCheck = (json: any) => { if (json?.error === 'vpn_blocked') window.dispatchEvent(new CustomEvent('cg-vpn-blocked', { detail: json.vpn })) }

async function call<T = unknown>(path: string, opts: { method?: string; body?: unknown; form?: FormData } = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: opts.method || (opts.body || opts.form ? 'POST' : 'GET'),
    credentials: 'include',
    headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
    body: opts.form ?? (opts.body ? JSON.stringify(opts.body) : undefined),
  })
  let json: any = null
  try { json = await res.json() } catch { /* non-JSON */ }
  if (!res.ok || !json?.ok) { vpnCheck(json); throw new ApiError(json?.message || json?.error || `HTTP ${res.status}`, res.status, json?.error, json) }
  return json.data as T
}

export type Verdict = 'malicious' | 'suspicious' | 'pua' | 'clean' | 'unknown'
export type ScoreReason = { code: string; tone: 'bad' | 'warn' | 'good' | 'info'; items?: string[]; source?: string; detail?: string; groups?: string[]; generic?: number; named?: number; n?: number; signer?: string; verdict?: string; note?: string }
export type ScoreGroup = { group: string; score: number; sources: { source: string; score: number }[] }
export type ScanProvider = { id: string; name: string; layer: number; kind: 'file' | 'ioc'; paid: boolean; enabled: boolean }
export type ScanInfo = { layers: { n: number; id: string }[]; providers: ScanProvider[]; enabled: number; total: number; max_bytes: number; turnstile_site_key?: string | null; closed_until?: number | null }
export type ScanSession = { authed: boolean; label?: string; shared?: boolean; quota?: number; used?: number; expires_at?: number | null; sig_key?: string | null; now?: number }
export type ScanJobRow = { id: string; file_name: string; size: number; sha256: string; md5: string; sha1: string; status: 'running' | 'done'; score: number | null; verdict: Verdict | null; created_at: number; finished_at: number | null; parent_id: string | null; source?: any; watch_changed?: boolean }
export type ScanResult = { job_id: string; source: string; layer: number; status: 'queued' | 'running' | 'done' | 'not_found' | 'error' | 'disabled'; summary: any; error: string | null; updated_at: number }
export type AiReport = {
  verdict?: Verdict; confidence?: 'low' | 'medium' | 'high'; family?: string
  headline_tr?: string; headline_en?: string; summary_tr?: string; summary_en?: string
  key_findings_tr?: string[]; key_findings_en?: string[]; capabilities?: string[]
  recommendations_tr?: string[]; recommendations_en?: string[]
  computed?: { score: number; verdict: Verdict; family: string | null; known_good: boolean; engines: number; detected: number; ioc_hits: number; warnings?: { kind: string; source: string; urls: string[] }[]; reasons?: ScoreReason[]; groups?: ScoreGroup[] }
}
export type ScanJob = ScanJobRow & { static: any; ai: AiReport | null }
export type ScanChild = { id: string; file_name: string; sha256: string; size: number; status: string; score: number | null; verdict: Verdict | null; type: string }
export type AllScanRow = ScanJobRow & { ip: string | null; key_label: string | null; key_prefix: string | null; children: number }
export type ScanReport ={ job: ScanJob & { public?: boolean }; results: ScanResult[]; children: ScanChild[]; mine?: boolean; share_root?: string; fp_report?: { id: string; status: 'open' | 'accepted' | 'rejected'; created_at: number } | null
  watch?: { round: number; next_at: number | null; history: { at: number; day: number; before: { score: number; verdict: string }; after: { score: number; verdict: string } | null; vt?: { malicious: number | null; total: number | null } | null; skipped?: boolean }[]; changed: boolean; seen: boolean } | null
  share?: { link: string; image: string; bbcode: string; markdown: string; html: string } | null }
export type FpReport = { id: string; job_id: string; file_name: string; sha256: string; verdict: Verdict; score: number; note: string; ip: string | null; key_label: string | null; created_at: number }
export type LiveState = { id: string; job_id: string; status: 'queued' | 'starting' | 'running' | 'ended'; seconds: number; left: number; token?: string }
export type ScanOverride ={ sha256: string; verdict: Verdict; note: string; created_at: number }
export type ScanKey = { id: string; prefix: string; label: string; daily_quota: number; expires_at: number | null; revoked: boolean; shared: boolean; created_at: number; last_used_at: number | null; used_today: number }

export type ChatRow = { id: string; job_id: string | null; title: string; created_at: number; updated_at: number }
export type ChatBlock = { type: string; text?: string; thinking?: string; id?: string; name?: string; input?: any; tool_use_id?: string; content?: any; is_error?: boolean }
export type ChatViewer = { key_label: string; key_prefix: string; ip: string | null }
/** One step of Rune (the reversing agent) under an ask_rune call; input/output reach owner keys only. */
/** A thinking phase has name "thought" (its text reaches owner keys only); "ask_nyx" is Rune turning to Nyx. */
export type RuneStep = { id: string; name: string; input?: any; ms?: number; error?: string; output?: string; text?: string; message?: string; answer?: string }
/** What Rune said and did for one ask_rune call: its greeting, its steps, its (code-free) report. */
export type RuneEntry = { intro: string; steps: RuneStep[]; report: string }
export type ChatFull = ChatRow & { messages: { role: 'user' | 'assistant'; content: ChatBlock[] }[]; tool_ms: Record<string, number>; rune?: Record<string, RuneEntry>; running?: boolean; readonly?: boolean; closed?: number; closed_reason?: string | null; viewer?: ChatViewer }
export type AllChatRow = ChatRow & { running: boolean; ip: string | null; key_label: string | null; key_prefix: string | null; file_name: string | null; verdict: Verdict | null }
export type NyxStrikeRow = { key_id: string; key_prefix: string | null; strikes: number; last_at: number; ips: string | null; reason: string | null }
export type ChatEvent =
  | { type: 'chat'; id: string }
  | { type: 'sync'; chat: ChatFull }
  | { type: 'misuse'; level: 1 | 2 | 3; reason: string; behavior: string }
  | { type: 'note' | 'text'; key: string; text: string }
  | { type: 'tool_start'; id: string; name: string }
  | { type: 'tool_input'; id: string; name: string; input: any }
  | { type: 'tool_done'; id: string; name?: string; ms: number; error?: string; bytes?: number; output?: string }
  | { type: 'rune_start'; parent: string }
  | { type: 'verdict'; job_id: string; before: number | null; score: number; verdict: string }
  | { type: 'rune_text' | 'rune_report'; parent: string; text: string }
  | { type: 'rune_ask' | 'nyx_reply'; parent: string; id: string; text: string }
  | { type: 'sub_tool_start'; parent: string; id: string; name: string; input?: any }
  | { type: 'sub_tool_input'; parent: string; id: string; input?: any }
  | { type: 'rune_note'; parent: string; id: string; text: string }
  | { type: 'rune_note_done'; parent: string; id: string; ms: number }
  | { type: 'sub_tool_done'; parent: string; id: string; ms: number; error?: string; output?: string }
  | { type: 'error'; message: string }
  | { type: 'retry' }
  | { type: 'done'; usd?: number }

/** Reads a server-sent-event response (one JSON object per "data:" line) until it ends. */
async function readSse(request: Promise<Response>, onEvent: (ev: ChatEvent) => void) {
  const res = await request
  if (!res.ok || !res.body) {
    let json: any = null
    try { json = await res.json() } catch { /* non-JSON */ }
    vpnCheck(json)
    throw new ApiError(json?.error || `HTTP ${res.status}`, res.status, json?.error, json)
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buf += value
    let i
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const chunk = buf.slice(0, i)
      buf = buf.slice(i + 2)
      for (const line of chunk.split('\n')) if (line.startsWith('data: ')) { try { onEvent(JSON.parse(line.slice(6))) } catch { /* partial */ } }
    }
  }
}

export type SimilarFile = {
  similarity: number; tlsh_distance: number | null; ssdeep: number; imphash: boolean
  verdict: string | null; score: number | null; family: string | null; created_at: number; mine: boolean
  id?: string; file_name?: string; sha256?: string
}

export const scanApi = {
  info: () => call<ScanInfo>('/scan/info'),
  session: () => call<ScanSession>('/scan/session').then((s) => { if (s.authed && s.label !== 'owner') reportDevice(); return s }),
  login: (key: string) => { resetSigning(); return call<{ authed: boolean }>('/scan/login', { body: { key } }) },
  newKey: async () => { resetSigning(); return call<{ key: string; quota: number }>('/scan/keys/new', { body: { cf_token: await humanToken('key') } }) },
  /** A Turnstile token for a free Nyx message (null when Turnstile is off). */
  nyxToken: async (text: string) => humanToken('nyx', (await fpSha256(text)).slice(0, 32)),
  logout: () => { resetSigning(); return call('/scan/logout', { method: 'POST', body: {} }) },
  upload: (file: File, rescan: boolean, honey = false) => {
    const fd = new FormData()
    if (rescan) fd.append('rescan', '1')
    // fields must come before the file part: the server reads them as the stream reaches the file
    if (honey) fd.append('honey', '1')
    fd.append('file', file, file.name)
    return call<{ id: string; cached: boolean; honey?: 'started' | 'running' | 'quota' | 'unavailable' | null }>('/scan/upload', { form: fd })
  },
  link: (url: string, rescan = false, honey = false) => call<{ id: string; cached: boolean; name?: string }>('/scan/link', { body: { url, rescan, honey } }),
  hash: (hash: string) => call<{ id: string; cached: boolean; full?: boolean }>('/scan/hash', { body: { hash } }),
  shareKit: (id: string) => call<{ link: string; image: string; card: string; badge_bbcode: string; bbcode: string; markdown: string; html: string }>(`/scan/jobs/${encodeURIComponent(id)}/share-kit`),
  similar: (id: string) => call<{ similar: SimilarFile[] }>(`/scan/jobs/${encodeURIComponent(id)}/similar`),
  diff: (a: string, b: string) => call<any>(`/scan/diff/${encodeURIComponent(a)}/${encodeURIComponent(b)}`),
  adminHealth: () => call<any>('/admin/scan/health'),
  adminRegress: () => call<any>('/admin/scan/regress', { body: {} }),
  adminLabels: () => call<{ labels: { sha256: string; verdict: string; note: string; job_id: string | null; origin: string }[] }>('/admin/scan/labels'),
  adminSetLabel: (body: { sha256?: string; job_id?: string; verdict: string; note?: string }) => call('/admin/scan/labels', { body }),
  adminDeleteLabel: (sha256: string) => call(`/admin/scan/labels/${sha256}`, { method: 'DELETE' }),
  jobs: () => call<{ jobs: ScanJobRow[] }>('/scan/jobs'),
  jobsAll: (q = '') => call<{ jobs: AllScanRow[] }>(`/scan/jobs-all${q ? `?q=${encodeURIComponent(q)}` : ''}`),
  report: (id: string) => call<ScanReport>(`/scan/jobs/${encodeURIComponent(id)}`),
  liveStart: (jobId: string) => call<{ id: string; seconds: number }>(`/scan/jobs/${encodeURIComponent(jobId)}/live`, { body: {} }),
  liveStatus: (lid: string) => call<LiveState>(`/scan/live/${encodeURIComponent(lid)}`),
  liveStop: (lid: string) => call<{ status: string }>(`/scan/live/${encodeURIComponent(lid)}/stop`, { body: {} }),
  liveInfo: () => call<{ available: boolean; seconds: number; left: number | null }>('/scan/live-info'),
  honeyStart: (jobId: string) => call<{ status: string; task: number; seconds?: number }>(`/scan/jobs/${encodeURIComponent(jobId)}/honey`, { body: {} }),
  honeyInfo: () => call<{ available: boolean; seconds: number; left: number | null }>('/scan/honey-info'),
  share: (id: string, on: boolean) => call<{ id: string; public: boolean }>(`/scan/jobs/${encodeURIComponent(id)}/share`, { body: { public: on } }),
  reportFalsePositive: (id: string, note: string) => call<{ id: string; status: string }>(`/scan/jobs/${encodeURIComponent(id)}/false-positive`, { body: { note } }),

  chats: () => call<{ chats: ChatRow[] }>('/scan/chats'),
  chatsAll: () => call<{ chats: AllChatRow[] }>('/scan/chats-all'),
  /** Messages left today for this visitor (null = unlimited, the owner key). */
  chatQuota: () => call<{ left: number | null; limit: number | null }>('/scan/chat/quota'),
  chat: (id: string) => call<{ chat: ChatFull }>(`/scan/chats/${encodeURIComponent(id)}`),
  deleteChat: (id: string) => call(`/scan/chats/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  /** One chat turn; calls onEvent for every server-sent event until the stream ends. */
  chatTurn(body: TurnBody, onEvent: (ev: ChatEvent) => void, signal: AbortSignal) {
    return readSse(chatRequest(body).then((r) => fetch(r.url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', ...r.headers }, body: r.body, signal })), onEvent)
  },
  /** Re-attach to a chat: a "sync" event with the saved transcript, then the live turn if one is running. */
  chatStream(id: string, onEvent: (ev: ChatEvent) => void, signal: AbortSignal) {
    return readSse(fetch(`/api/scan/chats/${encodeURIComponent(id)}/stream`, { credentials: 'include', signal }), onEvent)
  },
  chatStop: (id: string) => call(`/scan/chats/${encodeURIComponent(id)}/stop`, { method: 'POST', body: {} }),

  adminKeys: () => call<{ keys: ScanKey[]; providers: ScanProvider[] }>('/admin/scan/keys'),
  adminCreateKey: (body: { label: string; daily_quota: number; days?: number; shared?: boolean }) => call<{ id: string; key: string }>('/admin/scan/keys', { body }),
  adminUpdateKey: (id: string, body: { revoked?: boolean; daily_quota?: number; label?: string; shared?: boolean }) => call<{ id: string }>(`/admin/scan/keys/${id}`, { method: 'PATCH', body }),
  adminNyxStrikes: () => call<{ strikes: NyxStrikeRow[]; ban_at: number }>('/admin/scan/nyx-strikes'),
  adminPardon: (keyId: string) => call<{ pardoned: number }>(`/admin/scan/nyx-strikes/${encodeURIComponent(keyId)}/pardon`, { body: {} }),
  adminResetLimits:() => call<{ reset_at: number; chat_counters_cleared: number }>('/admin/scan/reset-limits', { body: {} }),
  adminClearAnalysisReuse: () => call<{ cleared_at: number }>('/admin/scan/clear-analysis-reuse', { body: {} }),
  adminFalsePositives: () => call<{ reports: FpReport[]; overrides: ScanOverride[] }>('/admin/scan/false-positives'),
  adminDecideFp: (id: string, action: 'clean' | 'pua' | 'reject') => call<{ status: string; rescored?: number }>(`/admin/scan/false-positives/${id}`, { body: { action } }),
  adminDeleteOverride: (sha256: string) => call<{ deleted: number }>(`/admin/scan/overrides/${sha256}`, { method: 'DELETE' }),
}
