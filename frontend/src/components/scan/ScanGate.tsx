import { useEffect, useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { Loader, Moon } from 'lucide-react'
import { AiAvatar } from '@/components/ui/ai-avatar'
import { BrandMark } from '@/components/ui/brand'
import { scanApi } from '@/lib/scanApi'
import { ApiError } from '@/lib/api'

// Closed hours (owner, 2026-11-06): while /api/scan/info reports closed_until, every Scan page shows this
// screen instead (owner keys still get through). The countdown reloads the page when it opens again.
// `always`: pages that stay readable while closed (a report, so shared links keep working).
export function ScanGate({ children, always = false }: { children: ReactNode; always?: boolean }) {
  const [state, setState] = useState<{ until: number } | 'open' | null>(always ? 'open' : null)
  useEffect(() => {
    if (always) return
    Promise.all([scanApi.info(), scanApi.session().catch(() => ({ authed: false, label: undefined }))])
      .then(([i, s]) => setState(i.closed_until && s.label !== 'owner' ? { until: i.closed_until } : 'open'))
      .catch(() => setState('open'))
  }, [])
  if (state === null) return <div className="scan-dark dark min-h-[100dvh] bg-[#0a0a0a]" />
  if (state === 'open') return <>{children}</>
  return <ScanClosed until={state.until} />
}

const two = (n: number) => String(n).padStart(2, '0')

// Admin key input: keys are `cgs_` + 32 base64url characters. Anything else (spaces, zero-width or
// look-alike characters from a paste, quotes, markup) is dropped as it is typed, the length is capped,
// and only a well-formed key is ever sent.
const KEY_RE = /^cgs_[A-Za-z0-9_-]{32}$/
const KEY_MAX = 36
const cleanKey = (v: string) => v.normalize('NFKC').replace(/[^A-Za-z0-9_-]/g, '').replace(/^cgs_?/i, (m) => (m.length === 4 ? 'cgs_' : m)).slice(0, KEY_MAX)

function ScanClosed({ until }: { until: number }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(t) }, [])
  useEffect(() => { if (now >= until) window.location.reload() }, [now, until])
  const left = Math.max(0, Math.floor((until - now) / 1000))
  const opens = new Date(until).toLocaleTimeString('tr-TR', { timeZone: 'Europe/Istanbul', hour: '2-digit', minute: '2-digit' })

  // Owner sign-in stays possible: a free key just gets "closed" back.
  const [showKey, setShowKey] = useState(false)
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  // A few wrong keys in a row lock the form for a while (the server throttles too).
  const [fails, setFails] = useState(0)
  const [lockedUntil, setLockedUntil] = useState(0)
  const locked = lockedUntil > now
  const login = async () => {
    const k = cleanKey(key)
    if (locked || busy) return
    if (!KEY_RE.test(k)) { setErr('Anahtar biçimi geçersiz.'); return }
    setErr(''); setBusy(true)
    try { await scanApi.login(k); window.location.reload() } catch (e) {
      const code = e instanceof ApiError ? e.code : ''
      const n = fails + 1
      setFails(n)
      if (n >= 5) { setLockedUntil(Date.now() + 60_000); setFails(0) }
      setErr(code === 'scan_closed' ? `Scan şu an herkese kapalı, ${opens}'da açılacak.` : code === 'too_many_attempts' ? 'Çok fazla deneme. Biraz sonra tekrar dene.' : 'Anahtar geçersiz.')
      setKey('')
    } finally { setBusy(false) }
  }

  return (
    <div className="scan-dark dark relative grid min-h-[100dvh] place-items-center overflow-hidden bg-[#0a0a0a] px-4 text-center text-white">
      <div aria-hidden className="pointer-events-none absolute left-1/2 top-1/3 size-[520px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[#d4ff3a]/[0.06] blur-[120px]" />
      <motion.div initial={{ opacity: 0, y: 18, filter: 'blur(8px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} transition={{ type: 'spring', bounce: 0.2, duration: 0.7 }}
        className="relative flex max-w-md flex-col items-center">
        <div className="mb-8 flex items-center gap-2 text-[15px] font-semibold"><BrandMark size={20} /> ClashGear <span className="font-normal text-neutral-400">Scan</span></div>
        <div className="relative">
          <AiAvatar size="xl" blinking={false} label="Nyx" className="opacity-80 [filter:saturate(.6)]" />
          <motion.span className="absolute -right-3 -top-2 text-[#d4ff3a]/80" animate={{ y: [0, -6, 0], opacity: [0.5, 1, 0.5] }} transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}>
            <Moon className="size-6" />
          </motion.span>
        </div>
        <h1 className="mt-8 text-[28px] font-bold tracking-[-0.02em] sm:text-[34px]">ClashGear Scan şu an kapalı</h1>
        <p className="mt-3 text-[15px] leading-relaxed text-neutral-400">
          Nyx biraz dinleniyor. Dosya taraması, raporlar ve Nyx sabah <b className="text-white">{opens}</b>'da yeniden açılacak.
        </p>
        <div className="mt-8 flex items-end gap-3 font-mono tabular-nums" aria-label="Açılmasına kalan süre">
          {[[Math.floor(left / 3600), 'saat'], [Math.floor((left % 3600) / 60), 'dakika'], [left % 60, 'saniye']].map(([v, l]) => (
            <div key={l as string} className="flex w-20 flex-col items-center rounded-2xl border border-white/10 bg-white/[0.04] py-3">
              <span className="text-[30px] font-semibold leading-none text-white">{two(v as number)}</span>
              <span className="mt-1.5 font-sans text-[11px] uppercase tracking-wider text-neutral-500">{l}</span>
            </div>
          ))}
        </div>
        <div className="mt-10 text-[12.5px] text-neutral-500">
          {!showKey ? (
            <button type="button" onClick={() => setShowKey(true)} className="hover:text-neutral-300">Yönetici girişi</button>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); login() }} className="flex items-center gap-2">
              <input value={key} onChange={(e) => setKey(cleanKey(e.target.value))} placeholder="cgs_…" autoFocus
                type="password" autoComplete="off" spellCheck={false} autoCapitalize="off" autoCorrect="off" maxLength={KEY_MAX}
                pattern="cgs_[A-Za-z0-9_\-]{32}" aria-label="Yönetici anahtarı" disabled={locked}
                className="h-9 w-48 rounded-lg border border-white/10 bg-white/[0.04] px-3 font-mono text-[13px] text-white outline-none placeholder:text-neutral-600 focus:border-white/25 disabled:opacity-40" />
              <button type="submit" disabled={busy || locked || !KEY_RE.test(key)} className="press grid h-9 place-items-center rounded-lg bg-white/10 px-3 text-[13px] text-white hover:bg-white/15 disabled:opacity-40">
                {busy ? <Loader className="size-4 animate-spin" /> : locked ? `${Math.ceil((lockedUntil - now) / 1000)} sn` : 'Giriş'}
              </button>
            </form>
          )}
          {err && <p className="mt-2 text-amber-400">{err}</p>}
        </div>
      </motion.div>
    </div>
  )
}
