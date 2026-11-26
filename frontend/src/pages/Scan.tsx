import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { AnimatePresence, MotionConfig, motion } from 'framer-motion'
import {
  Fingerprint, BadgeCheck, ShieldCheck, Globe, ScanSearch, PackageOpen, Code, Cpu, Network, Dna,
  KeyRound, ArrowRight, ArrowDown, LogOut, Check, ArrowLeft, ExternalLink, Sparkles, TriangleAlert, Loader, MonitorPlay,
  Share2, Lock, Copy,
} from 'lucide-react'
import { ScanGlass } from '@/components/scan/ScanGlass'
import { LiquidMetalButton } from '@/components/ui/liquid-metal-button'
import { CapeActivity } from '@/components/scan/CapeActivity'
import { TokenTrap } from '@/components/scan/TokenTrap'
import { HoneypotOption } from '@/components/scan/HoneypotOption'
import { InfiniteSlider } from '@/components/ui/infinite-slider'
import { UploadDemo } from '@/components/scan/UploadDemo'
import { BorderBeam } from '@/components/ui/border-beam'
import { brandsOf } from '@/components/scan/brands'
import { ScanNav } from '@/components/scan/ScanNav'
import { AiChatDemo } from '@/components/scan/AiChatDemo'
import { ScanLoader } from '@/components/scan/ScanLoader'
import { NyxIntro, PerchedNyx, type IntroState } from '@/components/scan/NyxIntro'
// three.js only loads when the landing page needs the prism.
import { StaticEngines, StealerCard, SourceCard, SimilarFiles, DiffView, WatchCard, SystemChanges, BadgeSnippets, CapeExtras } from '@/components/scan/ScanExtras'
import { SegmentedControl } from '@/components/ui/segmented-control'
const PrismSection = lazy(() => import('@/components/scan/PrismSection').then((m) => ({ default: m.PrismSection })))
import { VerticalTabs, type VerticalTabItem } from '@/components/ui/vertical-tabs'
import { AnimatedRadialChart } from '@/components/ui/animated-radial-chart'
import AnimatedTabs from '@/components/ui/animated-tabs'
import { ProcessTimeline, type TimelineStep } from '@/components/ui/process-timeline'
import { FileDropzone } from '@/components/ui/file-dropzone'
import { Button } from '@/components/ui/button'
import { BrandMark } from '@/components/ui/brand'
import { LangToggle } from '@/components/ui/lang-toggle'
import { cn } from '@/lib/utils'
import { ApiError } from '@/lib/api'
import { scanApi, type AllScanRow, type ScanInfo, type ScanJobRow, type ScanReport, type ScanResult, type ScanSession, type Verdict } from '@/lib/scanApi'
import { useScan, type ScanDict } from '@/i18n/scan'

const LAYER_ICON = [Fingerprint, BadgeCheck, ShieldCheck, Globe, ScanSearch, PackageOpen, Code, Cpu, Network, Dna]
const fmtSize = (n: number) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`)
const VERDICT_TONE: Record<string, string> = {
  malicious: 'bg-red-500/15 text-red-500 border-red-500/30',
  suspicious: 'bg-amber-500/15 text-amber-500 border-amber-500/30',
  pua: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  clean: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30',
  unknown: 'bg-secondary text-muted-foreground border-border',
}

function useInfo() {
  const [info, setInfo] = useState<ScanInfo | null>(null)
  useEffect(() => { scanApi.info().then(setInfo).catch(() => {}) }, [])
  return info
}

function VerdictPill({ v, className }: { v?: Verdict | string | null; className?: string }) {
  const { t } = useScan()
  const key = v || 'unknown'
  return <span className={cn('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold', VERDICT_TONE[key] || VERDICT_TONE.unknown, className)}>{t.verdicts[key] || key}</span>
}

function Shell({ children, onLogout }: { children: ReactNode; onLogout?: () => void }) {
  const { t } = useScan()
  return (
    <div className="scan-dark dark relative isolate min-h-screen">
      {/* the landing's glass background, faded out under the header so the work area stays calm */}
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[460px] [mask-image:linear-gradient(to_bottom,black,transparent)]">
        <ScanGlass variant="top" />
      </div>
      <nav className="sticky top-0 z-40 px-3 pt-3">
        <div className="glass mx-auto flex h-12 max-w-6xl items-center justify-between gap-3 rounded-2xl px-3">
          <Link to="/scan" className="flex items-center gap-2 text-[15px] font-semibold tracking-[-0.01em] text-white"><BrandMark size={22} /> ClashGear <span className="font-normal text-neutral-500">Scan</span></Link>
          <div className="flex items-center gap-2">
            <LangToggle />
            {onLogout && <button type="button" onClick={onLogout} className="press flex items-center gap-1.5 rounded-xl px-2.5 py-1.5 text-[13px] text-neutral-400 hover:bg-white/[0.06] hover:text-white"><LogOut className="size-4" /><span className="hidden sm:inline">{t.logout}</span></button>}
          </div>
        </div>
      </nav>
      <div className="relative mx-auto max-w-6xl px-4 pb-6 pt-8 sm:px-6">
        {children}
        <footer className="mt-16 border-t border-border pt-6 text-center text-xs text-muted-foreground">
          © ClashGear · <a href="https://cheatglobal.com" target="_blank" title="Cheatglobal" className="text-foreground hover:underline">Cheatglobal</a>
        </footer>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ landing */
const KEY_INPUT = 'scan-key-input'
// Critically damped by default; things materialise (blur + scale + fade) instead of sliding in.
const SPRING = { type: 'spring' as const, bounce: 0, duration: 0.6 }
const rise = (i: number) => ({
  initial: { opacity: 0, y: 14, filter: 'blur(8px)' },
  animate: { opacity: 1, y: 0, filter: 'blur(0px)' },
  transition: { ...SPRING, delay: 0.08 * i },
})
const focusKey = () => {
  const el = document.getElementById(KEY_INPUT) as HTMLInputElement | null
  if (!el) return
  el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  window.setTimeout(() => el.focus({ preventScroll: true }), 350)
}

function KeyForm({ compact }: { compact?: boolean }) {
  const { t } = useScan()
  const nav = useNavigate()
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  // Pasted keys pick up quotes/backticks and invisible characters, and mobile keyboards capitalise "Cgs_".
  // Besides cgs_ keys there are plain shared words (e.g. "cheatglobal"), so any shape is accepted.
  const trimmed = key.replace(/[\s​-‍﻿`'"“”‘’]/g, '').replace(/^cgs_/i, 'cgs_')
  const shapeOff = false
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!trimmed || shapeOff) return
    setErr(''); setBusy(true)
    try {
      await scanApi.login(trimmed)
      nav('/scan/app')
    } catch (e2) {
      const code = e2 instanceof ApiError ? e2.code : ''
      setErr(code === 'vpn_blocked' ? '' : code === 'invalid_key' ? t.wrongKey : code === 'key_inactive' ? t.inactiveKey : code === 'too_many_attempts' ? t.tooMany : t.failed)
    } finally { setBusy(false) }
  }
  return (
    <form onSubmit={submit} className={cn('glass mx-auto w-full max-w-md rounded-2xl p-2 text-left shadow-[0_20px_60px_-20px_rgba(0,0,0,0.8)]', !compact && 'mt-10')}>
      <div className="flex items-center gap-2">
        <KeyRound aria-hidden className="ml-2 size-4 shrink-0 text-neutral-500" />
        <input id={compact ? undefined : KEY_INPUT} value={key} onChange={(e) => { setKey(e.target.value); setErr('') }} placeholder={t.keyPlaceholder}
          aria-label={t.keyTitle} aria-invalid={shapeOff || !!err} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false}
          className="h-11 min-w-0 flex-1 bg-transparent tabular-nums text-sm tracking-wide text-white outline-none placeholder:text-neutral-600" />
        <button type="submit" disabled={busy || !trimmed || shapeOff} className="press flex h-10 items-center gap-1.5 rounded-xl bg-white px-4 text-sm font-semibold text-black hover:bg-neutral-200 disabled:opacity-40">
          {busy ? <Loader className="size-4 animate-spin" /> : <>{t.enter} <ArrowRight className="size-4" /></>}
        </button>
      </div>
      <AnimatePresence initial={false} mode="wait">
        {(err || shapeOff) && (
          <motion.p key={err || 'shape'} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={{ type: 'spring', bounce: 0, duration: 0.3 }}
            role="alert" className="overflow-hidden px-3 pb-1.5 pt-1 text-xs text-red-400">
            {err || t.keyShape}
          </motion.p>
        )}
      </AnimatePresence>
      {!compact && <NewKey />}
    </form>
  )
}

/** Self-service key: one click mints a personal key, signs the visitor in and shows the key once. */
function NewKey() {
  const { t } = useScan()
  const nav = useNavigate()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [made, setMade] = useState<{ key: string; quota: number } | null>(null)
  const [copied, setCopied] = useState(false)
  const make = async () => {
    setErr(''); setBusy(true)
    try { setMade(await scanApi.newKey()) } catch (e) {
      const code = e instanceof ApiError ? e.code : ''
      setErr(code === 'vpn_blocked' ? '' : !code || code === 'captcha_required' || code === 'browser_required' ? 'Tarayıcı doğrulaması geçilemedi. Sayfayı yenileyip tekrar dene.' : code === 'key_limit_ip' ? t.keyLimitIp : code === 'key_limit_day' ? t.keyLimitDay : t.failed)
    } finally { setBusy(false) }
  }
  const copy = async () => {
    if (!made) return
    try { await navigator.clipboard.writeText(made.key); setCopied(true); window.setTimeout(() => setCopied(false), 1600) } catch { /* select it by hand */ }
  }
  return (
    <>
      <div className="flex flex-wrap items-center justify-center gap-x-2 gap-y-1 border-t border-white/[0.06] px-3 pb-1 pt-2.5 text-xs text-neutral-500">
        {t.noKey}
        <button type="button" onClick={make} disabled={busy} className="press inline-flex items-center gap-1 font-semibold text-white hover:underline disabled:opacity-50">
          {busy ? <><Loader className="size-3.5 animate-spin" /> {t.makingKey}</> : <><Sparkles className="size-3.5" /> {t.makeKey}</>}
        </button>
      </div>
      {err && <p role="alert" className="px-3 pb-1.5 text-center text-xs text-amber-400">{err}</p>}
      {/* portalled: the glass form's backdrop-filter would otherwise trap a fixed overlay inside it */}
      {createPortal(<AnimatePresence>
        {made && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="scan-dark dark fixed inset-0 z-[100] grid place-items-center bg-black/70 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="new-key-title">
            <motion.div initial={{ opacity: 0, y: 12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={SPRING} className="w-full max-w-md rounded-2xl border border-white/10 bg-card p-6 text-left shadow-2xl">
              <div className="flex items-center gap-3">
                <span className="grid size-10 shrink-0 place-items-center rounded-full bg-white/10"><KeyRound className="size-5 text-white" /></span>
                <h2 id="new-key-title" className="text-lg font-semibold text-foreground">{t.newKeyTitle}</h2>
              </div>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">{t.newKeyBody}</p>
              <div className="mt-4 flex items-center gap-2 rounded-xl border border-white/10 bg-black/40 p-1.5 pl-3">
                <code className="min-w-0 flex-1 select-all break-all font-mono text-[13px] text-white">{made.key}</code>
                <button type="button" onClick={copy} className="press flex h-9 shrink-0 items-center gap-1.5 rounded-lg bg-white/10 px-3 text-xs font-semibold text-white hover:bg-white/15">
                  {copied ? <><Check className="size-3.5" /> {t.copied}</> : t.copy}
                </button>
              </div>
              <p className="mt-3 text-xs text-muted-foreground">{t.newKeyQuota(made.quota)}</p>
              <Button className="mt-6 h-11 w-full" onClick={() => nav('/scan/app')}>{t.savedGo}</Button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>, document.body)}
    </>
  )
}

function LandingNav({ authed }: { authed: boolean }) {
  const { t } = useScan()
  const links = useMemo(() => [
    { href: '#scene', label: t.nav.scene },
    { href: '#how', label: t.nav.how },
    { href: '#sample', label: t.nav.sample },
    { href: '#trust', label: t.nav.trust },
  ], [t])
  const cta = authed
    ? <Link to="/scan/app" className="press rounded-xl bg-white px-3.5 py-1.5 text-[13px] font-semibold text-black hover:bg-neutral-200">{t.newScan}</Link>
    : <button type="button" onClick={focusKey} className="press rounded-xl bg-white px-3.5 py-1.5 text-[13px] font-semibold text-black hover:bg-neutral-200">{t.nav.signIn}</button>
  return <ScanNav links={links} cta={cta} />
}

function LayerPanel({ n, info }: { n: number; info: ScanInfo | null }) {
  const { t } = useScan()
  const Icon = LAYER_ICON[n - 1]
  const srcs = (info?.providers || []).filter((p) => p.layer === n)
  return (
    <div className="flex h-full min-h-[360px] flex-col p-6 sm:p-8">
      <div className="flex items-start justify-between">
        <div className="flex size-11 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04]"><Icon className="size-5 text-neutral-200" /></div>
        <span className="text-6xl font-semibold tabular-nums tracking-[-0.04em] text-white/[0.07]">{String(n).padStart(2, '0')}</span>
      </div>
      <h3 className="mt-6 text-2xl font-semibold tracking-[-0.02em] text-white">{t.layers[n][0]}</h3>
      <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-neutral-300">{t.layerDetails[n].body}</p>
      <ul className="mt-5 grid gap-2.5 sm:grid-cols-2">
        {t.layerDetails[n].points.map((pt) => (
          <li key={pt} className="flex items-start gap-2.5 text-[13px] leading-relaxed text-neutral-400">
            <Check aria-hidden className="mt-[3px] size-3.5 shrink-0 text-neutral-300" strokeWidth={2.5} />
            <span>{pt}</span>
          </li>
        ))}
      </ul>
      <div className="mt-auto pt-8">
        {n === 1 ? <p className="text-xs text-neutral-500">{t.localOnly}</p> : (
          <>
            <p className="mb-3 text-[11px] font-medium uppercase tracking-[0.12em] text-neutral-500">{t.sources}</p>
            <div className="flex flex-wrap gap-1.5">
              {srcs.map((s) => (
                <span key={s.id} className={cn('inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs', s.enabled ? 'border-white/15 text-neutral-200' : 'border-white/[0.06] text-neutral-500')}>
                  <span className={cn('size-1.5 rounded-full', s.enabled ? 'bg-white' : 'bg-white/20')} />
                  {s.name}{s.paid ? ' ·  $' : ''}
                </span>
              ))}
              {n === 10 && <span className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 px-2.5 py-1 text-xs text-neutral-200"><span className="size-1.5 rounded-full bg-white" />Claude</span>}
            </div>
            {n === 10 && <p className="mt-3 text-xs text-neutral-500">{t.aiOnly}</p>}
          </>
        )}
      </div>
    </div>
  )
}

function SampleReport() {
  const { t } = useScan()
  const tabs = Object.values(t.tabs)
  return (
    <div className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-white/[0.02]">
      <BorderBeam duration={16} />
      <span className="absolute right-4 top-4 rounded-full border border-white/10 px-2.5 py-0.5 text-[11px] text-neutral-400">{t.sampleTag}</span>
      <div className="grid gap-6 p-6 sm:p-8 lg:grid-cols-[auto_1fr] lg:items-center">
        <div className="flex flex-col items-center">
          <AnimatedRadialChart value={87} size={240} caption={t.score} duration={1.6} />
          <VerdictPill v="malicious" className="mt-1 px-4 py-1 text-sm" />
        </div>
        <div className="min-w-0">
          <p className="truncate tabular-nums text-xs text-neutral-500">{t.sampleFile}</p>
          <p className="mt-3 flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.12em] text-neutral-500"><Sparkles className="size-3.5" /> {t.aiTitle}</p>
          <p className="mt-2 text-lg font-medium leading-snug tracking-[-0.01em] text-white">{t.sampleHeadline}</p>
          <ul className="mt-4 space-y-1.5 text-sm text-neutral-400">
            {t.sampleFindings.map((f) => <li key={f} className="flex gap-2"><span className="mt-2 size-1 shrink-0 rounded-full bg-neutral-500" />{f}</li>)}
          </ul>
          <div className="mt-6 flex flex-wrap gap-1.5 border-t border-white/[0.06] pt-5">
            {tabs.map((x) => <span key={x} className="rounded-lg bg-white/[0.04] px-2.5 py-1 text-xs text-neutral-400">{x}</span>)}
          </div>
        </div>
      </div>
    </div>
  )
}

function ScanLanding() {
  const { t } = useScan()
  const info = useInfo()
  const [session, setSession] = useState<ScanSession | null>(null)
  useEffect(() => { scanApi.session().then(setSession).catch(() => setSession({ authed: false })) }, [])
  const authed = !!session?.authed

  const layers: VerticalTabItem[] = Array.from({ length: 10 }, (_, i) => ({
    id: String(i + 1).padStart(2, '0'),
    title: t.layers[i + 1][0],
    description: t.layers[i + 1][1],
    panel: <LayerPanel n={i + 1} info={info} />,
  }))

  return (
    <MotionConfig reducedMotion="user">
      <div className="scan-dark dark min-h-screen">
        <ScanLoader />
        <LandingNav authed={authed} />

        <header className="relative isolate overflow-hidden">
          <ScanGlass />
          <div className="pointer-events-none absolute inset-x-0 bottom-0 -z-10 h-40 bg-gradient-to-b from-transparent to-[hsl(var(--background))]" />
          <div className="mx-auto grid min-h-[100svh] max-w-7xl items-center gap-14 px-5 pb-20 pt-28 lg:grid-cols-[0.85fr_1.15fr] lg:gap-14">
            <div className="text-center lg:text-left">
              <motion.p {...rise(0)} className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-[12px] text-neutral-300 backdrop-blur-md">
                <span className="relative flex size-1.5"><span className="absolute inline-flex size-full animate-ping rounded-full bg-white/60 motion-reduce:animate-none" /><span className="relative inline-flex size-1.5 rounded-full bg-white" /></span>
                {t.heroLead}
              </motion.p>
              <motion.h1 {...rise(1)} className="display mt-6 text-balance bg-gradient-to-b from-white via-white to-neutral-400 bg-clip-text font-semibold text-transparent">{t.heroTitle}</motion.h1>
              <motion.p {...rise(2)} className="mx-auto mt-6 max-w-xl text-pretty text-[15px] leading-relaxed text-neutral-400 lg:mx-0">{t.heroSub}</motion.p>
              <motion.div {...rise(3)} className="lg:[&>form]:mx-0">
                {authed ? (
                  <Link to="/scan/app" className="press mx-auto mt-10 flex w-fit items-center gap-2 rounded-2xl bg-white px-6 py-3 text-sm font-semibold text-black hover:bg-neutral-200 lg:mx-0">
                    {t.newScan} <ArrowRight className="size-4" />
                  </Link>
                ) : <KeyForm />}
                <p className="mt-3 text-xs text-neutral-500">{t.keyHint}</p>
              </motion.div>
              <motion.dl {...rise(4)} className="mx-auto mt-12 grid max-w-md grid-cols-4 gap-4 border-t border-white/[0.08] pt-6 lg:mx-0">
                {t.stats.map(([v, l]) => (
                  <div key={l}>
                    <dt className="text-xl font-semibold tabular-nums tracking-[-0.02em] text-white">{v}</dt>
                    <dd className="mt-0.5 text-[11px] leading-tight text-neutral-500">{l}</dd>
                  </div>
                ))}
              </motion.dl>
            </div>
            <motion.div initial={{ opacity: 0, y: 24, scale: 0.97, filter: 'blur(10px)' }} animate={{ opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }} transition={{ ...SPRING, duration: 0.9, delay: 0.35 }}>
              <UploadDemo />
            </motion.div>
          </div>
          <a href="#how" className="absolute bottom-6 left-1/2 hidden -translate-x-1/2 flex-col items-center gap-1.5 text-[11px] text-neutral-500 transition-colors hover:text-neutral-300 sm:flex">
            {t.scrollCue}
            <motion.span animate={{ y: [0, 4, 0] }} transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}><ArrowDown className="size-3.5" /></motion.span>
          </a>
        </header>

        {info && (
          <section className="border-y border-white/[0.06] py-7">
            <p className="mb-5 text-center text-[11px] font-medium uppercase tracking-[0.14em] text-neutral-500">{t.poweredBy}</p>
            <InfiniteSlider gap={44} duration={55} durationOnHover={130} className="[mask-image:linear-gradient(to_right,transparent,black_12%,black_88%,transparent)]">
              {brandsOf(info.providers).map((b) => (
                <span key={b.slug} title={b.name}
                  className="flex shrink-0 items-center gap-2.5 whitespace-nowrap text-[15px] font-medium tracking-[-0.01em] text-neutral-100 transition-colors duration-300 hover:text-white">
                  {b.logo ? (
                    <img src={b.logo} alt="" width={22} height={22} loading="lazy" decoding="async" className="size-[22px] rounded-md object-contain" />
                  ) : (
                    <span className="flex size-[22px] items-center justify-center rounded-md bg-white/[0.12] text-[11px] font-semibold text-white">{b.name[0]}</span>
                  )}
                  {b.name}
                </span>
              ))}
            </InfiniteSlider>
          </section>
        )}

        <Suspense fallback={<div className="min-h-[100svh] bg-[#101010]" />}>
          <PrismSection />
        </Suspense>

        <AiChatDemo />

        <section id="how" className="mx-auto max-w-6xl scroll-mt-24 px-5 py-24">
          <div className="mb-12 max-w-2xl">
            <h2 className="text-4xl font-semibold leading-[1.08] tracking-[-0.03em] text-white">{t.howTitle}</h2>
            <p className="mt-3 text-[15px] leading-relaxed text-neutral-400">{t.howSub}</p>
            {info && <p className="mt-4 inline-flex items-center gap-2 text-xs text-neutral-500"><span className="size-1.5 rounded-full bg-white/70" /> {t.activeSources(info.enabled, info.total)}</p>}
          </div>
          <VerticalTabs items={layers} />
        </section>

        <section id="sample" className="mx-auto max-w-6xl scroll-mt-24 px-5 py-24">
          <div className="mb-10 max-w-2xl">
            <h2 className="text-4xl font-semibold leading-[1.08] tracking-[-0.03em] text-white">{t.sampleTitle}</h2>
            <p className="mt-3 text-[15px] leading-relaxed text-neutral-400">{t.sampleSub}</p>
          </div>
          <SampleReport />
        </section>

        <section id="trust" className="mx-auto max-w-6xl scroll-mt-24 px-5 py-24">
          <h2 className="mb-10 text-4xl font-semibold leading-[1.08] tracking-[-0.03em] text-white">{t.trustTitle}</h2>
          <div className="grid gap-px overflow-hidden rounded-3xl border border-white/[0.08] bg-white/[0.06] md:grid-cols-3">
            {t.trust.map(([h, b], i) => {
              const Icon = [Cpu, KeyRound, ShieldCheck][i]
              return (
                <div key={h} className="bg-background p-7">
                  <Icon className="size-5 text-neutral-300" />
                  <h3 className="mt-5 text-[17px] font-medium tracking-[-0.01em] text-white">{h}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-neutral-400">{b}</p>
                </div>
              )
            })}
          </div>
          <p className="mt-6 max-w-3xl text-xs leading-relaxed text-neutral-500">{t.privacy}</p>
        </section>

        <section className="mx-auto max-w-6xl px-5 pb-24">
          <div className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-[radial-gradient(60%_80%_at_50%_0%,rgba(255,255,255,0.07),transparent)] px-6 py-16 text-center">
            <BorderBeam duration={14} delay={4} />
            <h2 className="text-3xl font-semibold tracking-[-0.03em] text-white">{t.ctaTitle}</h2>
            <p className="mt-2 text-sm text-neutral-400">{t.ctaSub}</p>
            <div className="mt-8">
              {authed ? (
                <Link to="/scan/app" className="press mx-auto flex w-fit items-center gap-2 rounded-2xl bg-white px-6 py-3 text-sm font-semibold text-black hover:bg-neutral-200">{t.newScan} <ArrowRight className="size-4" /></Link>
              ) : <KeyForm compact />}
            </div>
          </div>
        </section>

        <footer className="border-t border-white/[0.06] py-8 text-center text-xs text-neutral-500">
          © ClashGear · <a href="https://cheatglobal.com" target="_blank" title="Cheatglobal" className="text-neutral-300 hover:underline">Cheatglobal</a>
        </footer>
      </div>
    </MotionConfig>
  )
}


/* -------------------------------------------------------------- app */

function useSessionGate() {
  const nav = useNavigate()
  const [session, setSession] = useState<ScanSession | null>(null)
  const reload = useCallback(() => scanApi.session().then((s) => { if (!s.authed) nav('/scan'); else setSession(s) }).catch(() => nav('/scan')), [nav])
  useEffect(() => { reload() }, [reload])
  const logout = async () => { await scanApi.logout().catch(() => {}); nav('/scan') }
  return { session, reload, logout }
}

/** Shared (forum-wide) keys: a modal the user must acknowledge once per browser session. */
function SharedKeyNotice() {
  const { t } = useScan()
  const ACK = 'cg_scan_shared_ack'
  const [open, setOpen] = useState(() => { try { return sessionStorage.getItem(ACK) !== '1' } catch { return true } })
  const ok = () => { try { sessionStorage.setItem(ACK, '1') } catch { /* private mode */ } setOpen(false) }
  return (
    <AnimatePresence>
      {open && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="shared-key-title">
          <motion.div initial={{ opacity: 0, y: 12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={SPRING} className="w-full max-w-md rounded-2xl border border-amber-500/30 bg-card p-6 shadow-2xl">
            <div className="flex items-center gap-3">
              <span className="grid size-10 shrink-0 place-items-center rounded-full bg-amber-500/15"><TriangleAlert className="size-5 text-amber-400" /></span>
              <h2 id="shared-key-title" className="text-lg font-semibold text-foreground">{t.sharedTitle}</h2>
            </div>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">{t.sharedBody}</p>
            <ul className="mt-4 space-y-2">
              {t.sharedPoints.map((p) => <li key={p} className="flex gap-2.5 text-sm text-foreground/90"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-amber-400" />{p}</li>)}
            </ul>
            <Button className="mt-6 h-11 w-full" onClick={ok} autoFocus>{t.sharedOk}</Button>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

function ScanApp() {
  const { t, date } = useScan()
  const nav = useNavigate()
  const { session, reload, logout } = useSessionGate()
  const info = useInfo()
  const [file, setFile] = useState<File | null>(null)
  const [mode, setMode] = useState<'file' | 'link' | 'hash'>('file')
  const [link, setLink] = useState('')
  const [hash, setHash] = useState('')
  const [rescan, setRescan] = useState(false)
  const [honey, setHoney] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [jobs, setJobs] = useState<ScanJobRow[] | null>(null)
  useEffect(() => { scanApi.jobs().then((d) => setJobs(d.jobs)).catch(() => setJobs([])) }, [])
  const full = !!session && (session.used ?? 0) >= (session.quota ?? 0)
  const maxMB = Math.floor((info?.max_bytes || 100 * 1024 * 1024) / 1024 / 1024)

  const ready = mode === 'file' ? !!file : mode === 'link' ? /^https?:\/\/\S+\.\S+/i.test(link.trim()) : /^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i.test(hash.trim())
  const start = async () => {
    if (!ready) return
    setErr(''); setBusy(true)
    try {
      const r = mode === 'file' ? await scanApi.upload(file as File, rescan, honey) : mode === 'link' ? await scanApi.link(link.trim(), rescan, honey) : await scanApi.hash(hash.trim())
      reload()
      // Owner uploads go straight to Nyx; free uploads open the report (Nyx starts only when asked: AI cost).
      nav(session?.label === 'owner' ? `/scan/chat?job=${r.id}&auto=1` : `/scan/r/${r.id}`)
    } catch (e) {
      const code = e instanceof ApiError ? e.code : ''
      const detail = e instanceof ApiError ? (e as any).body?.detail : null
      const LINK_ERR: Record<string, string> = {
        unsupported_host: `${detail || 'Bu site'} linkleri doğrudan indirilemiyor; dosyayı indirip yükleyin.`,
        not_a_file: `Link bir dosyaya değil, bir sayfaya gidiyor${detail ? ` (“${detail}”)` : ''}. Doğrudan indirme linkini yapıştırın.`,
        bad_url: 'Geçerli bir http(s) linki girin.', http_error: `Site hata döndürdü (${detail || '?'}).`, empty_file: 'Link boş bir dosya döndürdü.',
        dns_failed: 'Alan adı çözülemedi.', connect_failed: 'Siteye bağlanılamadı.', refused_address: 'Bu adres taranamaz.', fetcher_unreachable: 'İndirme servisine ulaşılamadı, biraz sonra deneyin.',
        hash_unknown: 'Bu hash ne MalwareBazaar\'da ne VirusTotal\'da kayıtlı. Dosyanın kendisini yükleyin.', bad_hash: 'MD5, SHA-1 ya da SHA-256 girin.', too_fast: 'Aynı anda en çok iki link indirilebilir.',
      }
      setErr(code === 'vpn_blocked' ? '' : code === 'quota_exceeded' ? t.quotaFull : code === 'service_busy' ? t.serviceBusy : code === 'file_too_large' ? t.tooLarge : LINK_ERR[code || ''] || t.failed)
    } finally { setBusy(false) }
  }

  if (!session) return <Shell><p className="text-sm text-muted-foreground">{t.loading}</p></Shell>
  return (
    <Shell onLogout={logout}>
      {session.shared && <SharedKeyNotice />}
      {session.shared && (
        <div className="mb-6 flex items-start gap-3 rounded-2xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-400" /> {t.sharedBanner}
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <section className="rounded-2xl border border-border bg-card p-5 sm:p-6">
          <div className="mb-4 flex items-center justify-between gap-2">
            <h1 className="text-xl font-semibold">{t.dropTitle}</h1>
            <div className="flex shrink-0 items-center gap-2">
              {<Link to="/scan/chat" className="press flex items-center gap-1.5 rounded-full border border-white/10 px-2.5 py-1 text-xs text-neutral-200 hover:bg-white/[0.06]"><Sparkles className="size-3.5" /> Nyx ile analiz</Link>}
              <span className="rounded-full bg-secondary px-2.5 py-1 text-xs text-muted-foreground">{t.quota(session.used ?? 0, session.quota ?? 0)}</span>
            </div>
          </div>
          <SegmentedControl label="Tarama türü" className="mb-4" value={mode} onValueChange={(v) => { setMode(v as typeof mode); setErr('') }}
            options={[{ value: 'file', label: 'Dosya' }, { value: 'link', label: 'Link' }, { value: 'hash', label: 'Hash' }]} />
          {mode === 'file' && <FileDropzone maxSizeMB={maxMB} disabled={busy} file={file} onFile={setFile} labels={{ drop: t.drop, any: t.anyType, select: t.select, tooLarge: t.tooLarge, remove: t.remove }} />}
          {mode === 'link' && (
            <div>
              <input value={link} onChange={(e) => setLink(e.target.value)} disabled={busy} placeholder="https://www.mediafire.com/file/… ya da doğrudan indirme linki" inputMode="url" autoComplete="off"
                onKeyDown={(e) => { if (e.key === 'Enter') start() }}
                className="h-12 w-full rounded-xl border border-white/10 bg-black/30 px-3.5 text-sm text-white outline-none placeholder:text-neutral-600 focus:border-white/25" />
              <p className="mt-2 text-xs text-muted-foreground">Dosya bizim sandbox sunucumuzdan indirilir; siz bağlanmazsınız. MediaFire, Google Drive, Dropbox, GitHub, Discord ve doğrudan linkler çalışır. MEGA ve Gofile desteklenmiyor. En fazla {maxMB} MB.</p>
            </div>
          )}
          {mode === 'hash' && (
            <div>
              <input value={hash} onChange={(e) => setHash(e.target.value)} disabled={busy} placeholder="MD5, SHA-1 ya da SHA-256" autoComplete="off" spellCheck={false}
                onKeyDown={(e) => { if (e.key === 'Enter') start() }}
                className="h-12 w-full rounded-xl border border-white/10 bg-black/30 px-3.5 font-mono text-sm text-white outline-none placeholder:font-sans placeholder:text-neutral-600 focus:border-white/25" />
              <p className="mt-2 text-xs text-muted-foreground">Dosya elinizde değilse: hash MalwareBazaar ve VirusTotal'da aranır. Örnek bulunursa tüm katmanlar çalışır, bulunmazsa yalnızca hash sorguları.</p>
            </div>
          )}
          {mode !== 'hash' && <HoneypotOption checked={honey} onChange={setHoney} disabled={busy} />}
          <label className={cn('mt-4 flex items-center gap-2 text-sm text-muted-foreground', mode === 'hash' && 'hidden')}>
            <input type="checkbox" checked={rescan} onChange={(e) => setRescan(e.target.checked)} className="size-4 accent-primary" /> {t.rescan}
          </label>
          {err && <p className="mt-3 text-sm text-destructive">{err}</p>}
          {full && <p className="mt-3 text-sm text-warning">{t.quotaFull}</p>}
          <Button className="mt-4 h-11 w-full" disabled={!ready || busy || full} onClick={start}>
            {busy ? <><Loader className="size-4 animate-spin" /> {mode === 'link' ? 'İndiriliyor…' : mode === 'hash' ? 'Aranıyor…' : t.uploading}</> : <><Sparkles className="size-4" /> {t.analyze}</>}
          </Button>
          <p className="mt-4 text-xs text-muted-foreground">{t.privacy}</p>
        </section>
        <section className="rounded-2xl border border-border bg-card p-5 sm:p-6">
          <h2 className="mb-4 text-lg font-semibold">{t.history}</h2>
          {!jobs ? <p className="text-sm text-muted-foreground">{t.loading}</p> : !jobs.length ? <p className="text-sm text-muted-foreground">{t.noHistory}</p> : (
            <ul className="divide-y divide-border">
              {jobs.map((j) => (
                <li key={j.id}>
                  <Link to={`/scan/r/${j.id}`} className="flex items-center gap-3 py-3 hover:opacity-80">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{j.file_name}{j.watch_changed && <span className="ml-2 rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300">karar değişti</span>}</p>
                      <p className="text-xs text-muted-foreground">{date(j.created_at)} · {fmtSize(j.size)}{j.source?.url ? ' · link' : j.source?.hash ? ' · hash' : ''}</p>
                    </div>
                    {j.status === 'running' ? <Loader className="size-4 animate-spin text-muted-foreground" /> : <VerdictPill v={j.verdict} />}
                    {j.score != null && <span className="w-8 text-right tabular-nums text-sm">{j.score}</span>}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      {session.label === 'owner' && <AllScans />}
    </Shell>
  )
}

/** Owner only: every user's scans, searchable by file name, sha256 or uploader IP. */
function AllScans() {
  const { date } = useScan()
  const [q, setQ] = useState('')
  const [rows, setRows] = useState<AllScanRow[] | null>(null)
  useEffect(() => {
    const t = window.setTimeout(() => scanApi.jobsAll(q.trim()).then((d) => setRows(d.jobs)).catch(() => setRows([])), q ? 300 : 0)
    return () => window.clearTimeout(t)
  }, [q])
  const keyName = (l: string | null) => (l === 'self' ? 'ücretsiz anahtar' : l === 'owner' ? 'sen' : l || '?')
  return (
    <section className="mt-6 rounded-2xl border border-border bg-card p-5 sm:p-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">Tüm analizler</h2>
        <span className="rounded-full bg-[#d4ff3a]/15 px-2 py-0.5 text-[11px] font-semibold text-[#d4ff3a]">Admin</span>
        {rows && <span className="text-xs text-muted-foreground">{rows.length} kayıt</span>}
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Dosya adı, sha256 ya da IP ara…"
          className="ml-auto h-9 w-full rounded-xl border border-white/10 bg-black/30 px-3 text-sm text-white outline-none placeholder:text-neutral-600 focus:border-white/25 sm:w-72" />
      </div>
      {!rows ? <p className="text-sm text-muted-foreground">Yükleniyor…</p> : !rows.length ? <p className="text-sm text-muted-foreground">Kayıt yok.</p> : (
        <ul className="divide-y divide-border">
          {rows.map((j) => (
            <li key={j.id}>
              <Link to={`/scan/r/${j.id}`} className="flex items-center gap-3 py-3 hover:opacity-80">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{j.file_name}{j.children ? <span className="ml-1.5 text-xs font-normal text-muted-foreground">+{j.children} alt dosya</span> : null}</p>
                  <p className="truncate text-xs text-muted-foreground">
                    {date(j.created_at)} · {fmtSize(j.size)} · {keyName(j.key_label)}{j.key_label && j.key_label !== 'owner' && j.key_prefix ? ` (${j.key_prefix}…)` : ''}{j.ip ? ` · ${j.ip}` : ''}
                  </p>
                </div>
                {j.status === 'running' ? <Loader className="size-4 animate-spin text-muted-foreground" /> : <VerdictPill v={j.verdict} />}
                {j.score != null && <span className="w-8 text-right tabular-nums text-sm">{j.score}</span>}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/* ------------------------------------------------------------- report */

function Box({ title, children, action, className }: { title?: ReactNode; children: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <section className={cn('rounded-2xl border border-border bg-card p-5', className)}>
      {(title || action) && <div className="mb-3 flex items-center justify-between gap-2">{title && <h3 className="font-semibold">{title}</h3>}{action}</div>}
      {children}
    </section>
  )
}
const Empty = ({ t }: { t: ScanDict }) => <p className="text-sm text-muted-foreground">{t.noData}</p>
const Mono = ({ children }: { children: ReactNode }) => <span className="break-all tabular-nums text-xs">{children}</span>
const Chip = ({ children, tone }: { children: ReactNode; tone?: 'red' }) => (
  <span className={cn('inline-block rounded-md px-2 py-0.5 text-xs', tone === 'red' ? 'bg-red-500/10 text-red-500' : 'bg-secondary text-muted-foreground')}>{children}</span>
)

function SourceHead({ r, name }: { r: ScanResult; name: string }) {
  const { t } = useScan()
  const s = r.summary || {}
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="font-medium">{name}</span>
      {r.status === 'done' ? <VerdictPill v={s.verdict} /> : <Chip>{t.status[r.status] || r.status}{r.error ? ` · ${t.errors[r.error] || r.error}` : ''}</Chip>}
      {typeof s.score === 'number' && <Chip>{s.score}/100</Chip>}
      {s.family && <Chip tone="red">{s.family}</Chip>}
      {s.link && <a href={s.link} target="_blank" rel="noreferrer noopener" className="ml-auto inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">{t.report} <ExternalLink className="size-3" /></a>}
    </div>
  )
}

function List({ items, render }: { items: any[] | undefined; render: (x: any, i: number) => ReactNode }) {
  if (!items?.length) return null
  return <ul className="mt-2 space-y-1 text-sm">{items.map((x, i) => <li key={i}>{render(x, i)}</li>)}</ul>
}

/* Sandbox results, tidied: signatures by severity (info folded), de-duplicated ATT&CK, processes, network, drops. */
const SEV_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 }
const SEV_DOT: Record<string, string> = { high: 'bg-amber-500', medium: 'bg-amber-300', low: 'bg-neutral-400', info: 'bg-neutral-600' }
const SEV_PILL: Record<string, string> = { high: 'bg-amber-500/15 text-amber-400', medium: 'bg-amber-300/10 text-amber-200', low: 'bg-secondary text-muted-foreground', info: 'bg-secondary text-muted-foreground/70' }
function sevOf(s: any): string {
  const raw = String(s?.severity ?? s?.threat_level_human ?? s?.threat_level ?? '').replace(/^IMPACT_SEVERITY_/i, '').toLowerCase()
  if (/high|critical|malicious|^3$|^2$/.test(raw)) return 'high'
  if (/medium|suspicious|^1$/.test(raw)) return 'medium'
  if (/low/.test(raw)) return 'low'
  return 'info'
}
const prettySig = (n: string) => (/^[a-z0-9]+(_[a-z0-9]+)+$/.test(n) ? n.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()) : n)

function SandboxDetail({ s }: { s: any }) {
  const { t } = useScan()
  const [showInfo, setShowInfo] = useState(false)
  const seen = new Set<string>()
  const sigs = (s.signatures || [])
    .map((g: any) => ({ name: prettySig(String(g.name || g.description || '')), sev: sevOf(g) }))
    .filter((g: any) => g.name && !seen.has(g.name.toLowerCase()) && seen.add(g.name.toLowerCase()))
    .sort((a: any, b: any) => SEV_RANK[a.sev] - SEV_RANK[b.sev])
  const main = sigs.filter((g: any) => g.sev !== 'info')
  const info = sigs.filter((g: any) => g.sev === 'info')
  // Sources disagree on the shape ({id,name}, a bare string, or CAPE's {signature, ttps: []}); flatten to strings
  // so one odd entry can never take the whole report down.
  const attack = [...new Map((s.attack || []).flatMap((a: any) => {
    if (typeof a === 'string') return [{ id: a, name: '' }]
    const ids = typeof a?.id === 'string' ? [a.id] : Array.isArray(a?.id?.ttps) ? a.id.ttps : Array.isArray(a?.ttps) ? a.ttps : []
    const name = typeof a?.name === 'string' ? a.name : String(a?.id?.signature || a?.signature || '')
    return ids.filter((x: unknown) => typeof x === 'string').map((id: string) => ({ id, name }))
  }).map((a: any) => [`${a.id}|${a.name}`, a])).values()] as any[]
  const procs = [...new Set<string>([...(s.processes_created || []), ...(s.command_executions || []), ...(s.processes || []).filter((p: any) => typeof p === 'string' || p.command_line).map((p: any) => (typeof p === 'string' ? p : p.command_line))].map((x) => String(x).trim()).filter(Boolean))]
  const net = [...new Set<string>([...(s.iocs?.ips || []), ...(s.iocs?.domains || []), ...(s.iocs?.urls || [])])]
  const drops = (s.files_dropped || s.extracted_files || []).map((f: any) => (typeof f === 'string' ? f : f.path || f.name)).filter(Boolean)
  const row = (g: any, i: number) => (
    <li key={i} className="flex items-start gap-2.5 py-1">
      <span className={cn('mt-[7px] size-1.5 shrink-0 rounded-full', SEV_DOT[g.sev])} />
      <span className="min-w-0 flex-1 text-sm text-foreground/90">{g.name}</span>
      <span className={cn('shrink-0 rounded-md px-1.5 py-0.5 text-[11px]', SEV_PILL[g.sev])}>{t.sev[g.sev]}</span>
    </li>
  )
  const H = ({ children, n }: { children: ReactNode; n?: number }) => <h4 className="mb-1.5 mt-4 flex items-center gap-2 text-sm font-medium first:mt-0">{children}{n != null && <span className="rounded-full bg-secondary px-1.5 text-[11px] font-normal tabular-nums text-muted-foreground">{n}</span>}</h4>
  return (
    <div className="mt-4 grid gap-6 lg:grid-cols-2">
      <div>
        {(s.environments || s.sandboxes || s.environment) && <p className="mb-3 text-xs text-muted-foreground">{[].concat(s.environments || s.sandboxes || s.environment).join(' · ')}</p>}
        <H n={sigs.length}>{t.signatures}</H>
        {!sigs.length ? <Empty t={t} /> : (
          <>
            <ul className="divide-y divide-border/50">{main.map(row)}</ul>
            {!!info.length && (
              <>
                <button type="button" onClick={() => setShowInfo((v) => !v)} className="mt-2 text-xs text-muted-foreground hover:text-foreground">{showInfo ? t.infoLess : `+ ${t.infoMore(info.length)}`}</button>
                {showInfo && <ul className="mt-1 divide-y divide-border/50">{info.map(row)}</ul>}
              </>
            )}
          </>
        )}
      </div>
      <div>
        <H n={attack.length}>{t.attack}</H>
        {attack.length ? (
          <ul className="space-y-1.5">
            {attack.slice(0, 30).map((a, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm">
                <span className="shrink-0 rounded-md bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-foreground/80">{a.id}</span>
                <span className="text-muted-foreground">{a.name}</span>
              </li>
            ))}
          </ul>
        ) : <Empty t={t} />}
        {!!procs.length && <><H n={procs.length}>{t.processes}</H><ul className="space-y-1">{procs.slice(0, 15).map((p) => <li key={p}><Mono>{p}</Mono></li>)}</ul></>}
        {!!net.length && <><H n={net.length}>{t.netContacts}</H><ul className="space-y-1">{net.slice(0, 15).map((p) => <li key={p}><Mono>{p}</Mono></li>)}</ul></>}
        {!!drops.length && <><H n={drops.length}>{t.dropped}</H><ul className="space-y-1">{drops.slice(0, 15).map((p: string) => <li key={p}><Mono>{p}</Mono></li>)}</ul></>}
      </div>
    </div>
  )
}


/** Live sandbox card: run this file yourself on our Windows VM (owner's liquid-metal button, lime crown). */
function LiveCard({ jobId }: { jobId: string }) {
  const nav = useNavigate()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [info, setInfo] = useState<{ seconds: number; left: number | null } | null>(null)
  useEffect(() => { scanApi.liveInfo().then(setInfo).catch(() => {}) }, [])
  const go = async () => {
    if (busy) return
    setErr(''); setBusy(true)
    try { const r = await scanApi.liveStart(jobId); nav(`/scan/live/${r.id}`) } catch (e) {
      const code = e instanceof ApiError ? e.code : ''
      setErr(code === 'vpn_blocked' ? '' : code === 'live_quota_exceeded' ? 'Bugünkü canlı oturum hakkın doldu, yarın yenilenir.' : code === 'live_unavailable' ? 'Canlı sandbox şu an bakımda, birazdan tekrar dene.' : 'Başlatılamadı, tekrar dene.')
      setBusy(false)
    }
  }
  return (
    <div className="relative mt-3 overflow-hidden rounded-2xl border border-[#d4ff3a]/25 bg-[radial-gradient(120%_140%_at_100%_0%,rgba(212,255,58,0.10),transparent_55%)] p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="rounded-full bg-[#d4ff3a] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-black">Yeni</span>
            <h4 className="text-[15px] font-semibold tracking-[-0.01em] text-white">Canlı sandbox</h4>
          </div>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-neutral-300">
            Dosyanı kendi Windows makinemizde, kendi ellerinle çalıştır. Tıkla, kur, menülerini gez; arka planda her süreç, bağlantı ve dosya kaydedilir ve bu rapora eklenir. İş bitince makine iz bırakmadan sıfırlanır.
          </p>
        </div>
        <LiquidMetalButton label={busy ? 'Açılıyor…' : 'Makinede aç'} width={168} onClick={go} disabled={busy || info?.left === 0}
          icon={busy ? <Loader className="size-4 animate-spin" /> : <MonitorPlay className="size-4" />} />
      </div>
      {err && <p className="mt-3 text-xs text-amber-400">{err}</p>}
    </div>
  )
}

/** "Why this verdict?": the score rules that fired, the evidence groups, and the false-positive report. */
function WhyBox({ rep, nameOf, canReport }: { rep: ScanReport; nameOf: (s: string) => string; canReport: boolean }) {
  const { t } = useScan()
  const computed = rep.job.ai?.computed
  const [fp, setFp] = useState(rep.fp_report?.status || null)
  const [open, setOpen] = useState(false)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  if (!computed?.reasons) return null
  const flagged = ['malicious', 'suspicious', 'pua'].includes(rep.job.verdict || '')
  const toneDot = { bad: 'bg-amber-500', warn: 'bg-amber-300', good: 'bg-emerald-400', info: 'bg-neutral-500' }
  const send = async () => {
    setBusy(true)
    try { await scanApi.reportFalsePositive(rep.job.id, note); setFp('open'); setOpen(false) } catch { /* keep the dialog open */ } finally { setBusy(false) }
  }
  return (
    <Box title={t.whyTitle} className="mt-4" action={canReport && flagged && !fp ? (
      <button type="button" onClick={() => setOpen(true)} className="press rounded-full border border-white/10 px-3 py-1.5 text-xs text-neutral-200 hover:bg-white/[0.06]">{t.fpReport}</button>
    ) : undefined}>
      {!!computed.reasons.length && (
        <ul className="space-y-2">
          {computed.reasons.map((r, i) => (
            <li key={i} className="flex gap-2.5 text-sm text-foreground/90">
              <span className={cn('mt-2 size-1.5 shrink-0 rounded-full', toneDot[r.tone] || toneDot.info)} />
              <span>{t.why[r.code]?.({ ...r, source: r.source ? nameOf(r.source) : r.source }) || r.code}</span>
            </li>
          ))}
        </ul>
      )}
      {!!computed.groups?.length && (
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {computed.groups.map((g) => (
            <div key={g.group} className="rounded-lg border border-border p-2.5">
              <div className="flex items-center justify-between text-xs"><span className="text-muted-foreground">{t.groupNames[g.group] || g.group}</span><span className="tabular-nums">{g.score}</span></div>
              <div className="mt-1.5 h-1 rounded-full bg-white/[0.06]"><div className={cn('h-1 rounded-full', g.score >= 70 ? 'bg-amber-500' : g.score >= 35 ? 'bg-amber-300' : 'bg-neutral-500')} style={{ width: `${g.score}%` }} /></div>
              <div className="mt-1.5 truncate text-[11px] text-muted-foreground">{g.sources.map((s) => `${nameOf(s.source)} ${s.score}`).join(' · ')}</div>
            </div>
          ))}
        </div>
      )}
      {fp && <p className="mt-4 text-xs text-muted-foreground">{fp === 'accepted' ? t.fpAccepted : fp === 'rejected' ? t.fpRejected : t.fpSent}</p>}
      {createPortal(<AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="scan-dark dark fixed inset-0 z-[100] grid place-items-center bg-black/70 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="fp-title">
            <motion.div initial={{ opacity: 0, y: 12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={SPRING} className="w-full max-w-md rounded-2xl border border-white/10 bg-card p-6 shadow-2xl">
              <h2 id="fp-title" className="text-lg font-semibold text-foreground">{t.fpTitle}</h2>
              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{t.fpBody}</p>
              <textarea value={note} onChange={(e) => setNote(e.target.value.slice(0, 500))} rows={4} placeholder={t.fpPlaceholder} autoFocus
                className="mt-4 w-full resize-none rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-white outline-none placeholder:text-neutral-600 focus:border-white/25" />
              <div className="mt-4 flex gap-2">
                <Button variant="secondary" className="h-11 flex-1" onClick={() => setOpen(false)}>{t.fpCancel}</Button>
                <Button className="h-11 flex-1" onClick={send} disabled={busy}>{busy ? <Loader className="size-4 animate-spin" /> : t.fpSend}</Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>, document.body)}
    </Box>
  )
}

/** Share switch for a report: public turns the /scan/r/<id> link on for everyone, without a key. */
function ShareButton({ id, initial }: { id: string; initial: boolean }) {
  const { t } = useScan()
  const [open, setOpen] = useState(false)
  const [on, setOn] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const ref = useRef<HTMLSpanElement>(null)
  useEffect(() => setOn(initial), [initial])
  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])
  const link = `${window.location.origin}/scan/r/${id}`
  const toggle = async () => {
    setBusy(true)
    try { setOn((await scanApi.share(id, !on)).public) } catch { /* keep the old state */ } finally { setBusy(false) }
  }
  const copy = () => { navigator.clipboard?.writeText(link).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }).catch(() => {}) }
  return (
    <span ref={ref} className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open}
        className="press flex items-center gap-1.5 rounded-full border border-white/10 px-3 py-1.5 text-xs text-neutral-200 hover:bg-white/[0.06]">
        {on ? <Globe className="size-3.5 text-emerald-400" /> : <Share2 className="size-3.5" />} {t.share}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, y: -6, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -6, scale: 0.98 }} transition={SPRING}
            className="absolute right-0 top-full z-50 mt-2 max-h-[80vh] w-[min(400px,calc(100vw-32px))] overflow-y-auto rounded-2xl border border-white/10 bg-card p-4 text-left shadow-2xl">
            <p className="text-sm font-semibold text-foreground">{t.shareTitle}</p>
            <button type="button" role="switch" aria-checked={on} onClick={toggle} disabled={busy}
              className="mt-3 flex w-full items-center gap-3 rounded-xl border border-white/10 p-3 text-left hover:bg-white/[0.04] disabled:opacity-60">
              {on ? <Globe className="size-4 shrink-0 text-emerald-400" /> : <Lock className="size-4 shrink-0 text-neutral-400" />}
              <span className="flex-1 text-[13px] text-foreground">{on ? t.sharePublic : t.sharePrivate}</span>
              <span className={cn('relative h-5 w-9 shrink-0 rounded-full transition-colors', on ? 'bg-emerald-500' : 'bg-white/15')}>
                <span className={cn('absolute top-0.5 size-4 rounded-full bg-white transition-all', on ? 'left-[18px]' : 'left-0.5')} />
              </span>
            </button>
            <p className="mt-2 text-[11.5px] leading-relaxed text-muted-foreground">{t.shareHint}</p>
            {on && (
              <>
              <div className="mt-3 flex items-center gap-2">
                <input readOnly value={link} onFocus={(e) => e.currentTarget.select()} className="h-9 min-w-0 flex-1 rounded-lg border border-white/10 bg-black/40 px-2.5 font-mono text-[11.5px] text-neutral-300 outline-none" />
                <button type="button" onClick={copy} className="press grid h-9 shrink-0 place-items-center rounded-lg bg-white px-3 text-[12px] font-semibold text-black">
                  {copied ? <span className="flex items-center gap-1"><Check className="size-3.5" /> {t.shareCopied}</span> : <span className="flex items-center gap-1"><Copy className="size-3.5" /> {t.shareCopy}</span>}
                </button>
              </div>
              <BadgeSnippets id={id} />
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </span>
  )
}

function ScanReportPage() {
  const { id = '' } = useParams()
  const { t, lang, num } = useScan()
  const info = useInfo()
  const [rep, setRep] = useState<ScanReport | null>(null)
  const [missing, setMissing] = useState(false)
  const [tab, setTab] = useState('overview')
  const [owner, setOwner] = useState(false) // any signed-in key holder can ask Nyx about their own report
  useEffect(() => { scanApi.session().then((s) => setOwner(!!s.authed)).catch(() => {}) }, [])
  // The "analysis finished" scene plays once per scan; afterwards Nyx stays perched on the button (or not, if dismissed).
  const askRef = useRef<HTMLAnchorElement>(null)
  const INTRO = `cg_nyx_intro_${id}`
  const [intro, setIntro] = useState<IntroState | 'new'>(() => { try { return (localStorage.getItem(INTRO) as IntroState) || 'new' } catch { return 'new' } })
  const introDone = useCallback((s: Exclude<IntroState, 'play'>) => { try { localStorage.setItem(INTRO, s) } catch { /* private mode */ } setIntro(s) }, [INTRO])

  useEffect(() => {
    let stop = false
    let timer = 0
    const load = () => scanApi.report(id).then((r) => {
      if (stop) return
      setRep(r)
      if (r.job.status === 'running') timer = window.setTimeout(load, 5000)
    }).catch(() => { if (!stop) setMissing(true) })
    load()
    return () => { stop = true; window.clearTimeout(timer) }
  }, [id])

  // The Token Tuzağı card polls on its own while its run goes on (the scan itself is long done by then).
  const reload = useCallback(() => { scanApi.report(id).then(setRep).catch(() => {}) }, [id])
  const names = useMemo(() => Object.fromEntries((info?.providers || []).map((p) => [p.id, p.name]).concat([['local', 'ClashGear static'], ['claude', 'Claude (AI)'], ['malpedia', 'Malpedia']])), [info])
  const nameOf = (s: string) => names[s] || s

  if (missing) return <Shell><Box><p className="text-sm">{t.notFound}</p><Link to="/scan/app" className="mt-3 inline-block text-sm text-primary">{t.back}</Link></Box></Shell>
  if (!rep) return <Shell><p className="text-sm text-muted-foreground">{t.loading}</p></Shell>

  const { job, results, children } = rep
  // The viewer's own report (or an owner key): share switch, Nyx and false-positive report; a shared link's visitors only read.
  const mine = owner && !!rep.mine
  const live = results.filter((r) => r.status !== 'disabled')
  const done = (r: ScanResult) => r.status === 'done' && r.summary
  const st = job.static || {}
  const ai = job.ai
  const computed = ai?.computed
  const running = job.status === 'running'
  const finishedCount = live.filter((r) => !['queued', 'running'].includes(r.status)).length

  // Layer timeline: done when every switched-on source of the layer has settled.
  const steps: TimelineStep[] = Array.from({ length: 10 }, (_, i) => {
    const n = i + 1
    const rs = results.filter((r) => r.layer === n && r.status !== 'disabled')
    const busy = rs.some((r) => r.status === 'queued' || r.status === 'running')
    const type: TimelineStep['type'] = !rs.length ? 'failed' : busy ? (running ? 'in progress' : 'open') : 'done'
    const hits = rs.filter((r) => r.status === 'done').length
    return {
      id: n,
      type,
      title: `${String(n).padStart(2, '0')} · ${t.layers[n][0]}`,
      activityTime: rs.length ? `${hits}/${rs.length}` : t.status.disabled,
      description: rs.length ? (
        <div className="flex flex-wrap gap-1">
          {rs.map((r) => <Chip key={r.source} tone={r.summary?.verdict === 'malicious' ? 'red' : undefined}>{nameOf(r.source)} · {r.status === 'done' && typeof r.summary?.score === 'number' ? r.summary.score : t.status[r.status]}</Chip>)}
        </div>
      ) : null,
    }
  })

  // Engine table: every engine verdict we got, detections first.
  const engines: { source: string; engine: string; result: string | null; bad: boolean }[] = []
  for (const r of results.filter(done)) {
    const s = r.summary
    if (Array.isArray(s.engines)) for (const e of s.engines) engines.push({ source: nameOf(r.source), engine: e.engine, result: e.result, bad: e.category === 'malicious' || e.category === 'suspicious' })
    else if (Array.isArray(s.detections)) for (const e of s.detections) engines.push({ source: nameOf(r.source), engine: e.engine, result: e.result, bad: true })
  }
  engines.sort((a, b) => Number(b.bad) - Number(a.bad))
  const detected = engines.filter((e) => e.bad).length

  const yara = results.filter(done).flatMap((r) => (r.summary.yara || []).map((y: any) => ({ ...y, source: nameOf(r.source) })))
  const configs = results.filter(done).flatMap((r) => r.summary.configs || [])
  const scripts = results.filter(done).flatMap((r) => (r.summary.scripts || []).map((s: any) => ({ ...s, source: nameOf(r.source) })))
  const iocItems = results.filter((r) => r.layer === 9 && done(r)).flatMap((r) => (r.summary.items || []).map((x: any) => ({ ...x, source: nameOf(r.source) })))
  const malpedia = results.find((r) => r.source === 'malpedia' && done(r))?.summary

  const headline = ai?.[lang === 'tr' ? 'headline_tr' : 'headline_en']
  const summary = ai?.[lang === 'tr' ? 'summary_tr' : 'summary_en']
  const findings = ai?.[lang === 'tr' ? 'key_findings_tr' : 'key_findings_en'] || []
  const recs = ai?.[lang === 'tr' ? 'recommendations_tr' : 'recommendations_en'] || []
  const aiState = results.find((r) => r.source === 'claude')

  const TABS = [
    { id: 'overview', label: t.tabs.overview },
    { id: 'av', label: `${t.tabs.av}${engines.length ? ` · ${detected}/${engines.length}` : ''}` },
    { id: 'intel', label: t.tabs.intel },
    { id: 'static', label: t.tabs.static },
    { id: 'unpack', label: `${t.tabs.unpack}${children.length ? ` · ${children.length}` : ''}` },
    { id: 'deobf', label: t.tabs.deobf },
    { id: 'sandbox', label: t.tabs.sandbox },
    { id: 'network', label: `${t.tabs.network}${iocItems.length ? ` · ${iocItems.length}` : ''}` },
  ]

  return (
    <Shell>
      <div className="mb-4 flex items-center justify-between gap-3">
        <Link to={mine ? '/scan/app' : '/scan'} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-4" /> {t.back}</Link>
        <div className="flex items-center gap-2">
          {!rep.mine && job.public && <span className="flex items-center gap-1.5 text-xs text-muted-foreground"><Globe className="size-3.5 text-emerald-400" /> {t.sharedBadge}</span>}
          {rep.mine && <ShareButton id={rep.share_root || job.id} initial={!!job.public} />}
          {mine && (
            <span className="relative">
              <Link ref={askRef} to={`/scan/chat?job=${job.id}&auto=1`} className="press flex items-center gap-1.5 rounded-full border border-white/10 px-3 py-1.5 text-xs text-neutral-200 hover:bg-white/[0.06]"><Sparkles className="size-3.5" /> {t.nudgeCta}</Link>
              {intro === 'perched' && <PerchedNyx onClick={() => askRef.current?.click()} />}
            </span>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[auto_1fr]">
        <Box className="flex flex-col items-center justify-center">
          {job.score != null ? <AnimatedRadialChart value={job.score} size={260} caption={t.score} /> : (
            <div className="flex h-[182px] w-[260px] flex-col items-center justify-center gap-3 text-muted-foreground"><Loader className="size-8 animate-spin" /><span className="text-xs uppercase tracking-widest">{t.running}</span></div>
          )}
          <VerdictPill v={job.verdict || (running ? null : 'unknown')} className="mt-2 px-4 py-1 text-sm" />
        </Box>
        <Box>
          <h1 className="break-all text-xl font-semibold">{job.file_name}</h1>
          <div className="mt-1 text-xs text-muted-foreground">{fmtSize(job.size)} · {st.type} {st.pe ? `· ${st.pe.arch} ${st.pe.dotnet ? '.NET' : ''}` : ''}</div>
          <dl className="mt-3 grid gap-1 text-xs">
            {(['sha256', 'sha1', 'md5'] as const).map((h) => <div key={h} className="flex gap-2"><dt className="w-14 shrink-0 uppercase text-muted-foreground">{h}</dt><dd><Mono>{job[h]}</Mono></dd></div>)}
          </dl>
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label={t.family} value={computed?.family || ai?.family || '—'} />
            <Stat label={t.detections} value={computed ? `${computed.detected}/${computed.engines}` : `${detected}/${engines.length}`} />
            <Stat label={t.sourcesDone} value={`${finishedCount}/${live.length}`} />
            <Stat label={t.entropy} value={st.entropy != null ? String(st.entropy) : '—'} />
          </div>
          <SourceCard source={(job as any).source} />
          {computed?.known_good && <p className="mt-3 inline-flex items-center gap-1 text-sm text-emerald-500"><BadgeCheck className="size-4" /> {t.knownGood}</p>}
          {computed?.warnings?.filter((w) => w.kind === 'seen_on_malicious_host').map((w) => (
            <div key={w.source} className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-400">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
              <div className="min-w-0">
                <p>{t.seenOnBadHost} ({nameOf(w.source)})</p>
                {w.urls.map((u) => <p key={u} className="mt-1 break-all font-mono text-[11px] text-amber-300/80">{u}</p>)}
              </div>
            </div>
          ))}
          {running && <p className="mt-3 flex items-start gap-2 rounded-lg border border-border bg-secondary/50 p-3 text-xs text-muted-foreground"><Loader className="mt-0.5 size-3.5 shrink-0 animate-spin" /> {t.runningHint}</p>}
        </Box>
      </div>
      {!running && <WhyBox rep={rep} nameOf={nameOf} canReport={mine} />}
      <div className="mt-4"><StealerCard results={results} /></div>

      <div className="mt-6"><AnimatedTabs tabs={TABS} activeTab={tab} onChange={setTab} /></div>

      <div className="mt-4 grid gap-4">
        {tab === 'overview' && (
          <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
            <Box title={<span className="flex items-center gap-2"><Sparkles className="size-4 text-primary" /> {t.aiTitle}</span>} action={ai?.confidence && <Chip>{t.confidence[ai.confidence]}</Chip>}>
              {summary ? (
                <div className="space-y-4 text-sm">
                  {headline && <p className="text-base font-semibold">{headline}</p>}
                  <p className="leading-relaxed text-muted-foreground">{summary}</p>
                  {!!findings.length && <div><h4 className="mb-1 font-medium">{t.findings}</h4><ul className="list-disc space-y-1 pl-5 text-muted-foreground">{findings.map((f, i) => <li key={i}>{f}</li>)}</ul></div>}
                  {!!ai?.capabilities?.length && <div className="flex flex-wrap gap-1">{ai.capabilities.map((c) => <Chip key={c}>{c}</Chip>)}</div>}
                  {!!recs.length && <div><h4 className="mb-1 font-medium">{t.recommendations}</h4><ul className="list-disc space-y-1 pl-5 text-muted-foreground">{recs.map((f, i) => <li key={i}>{f}</li>)}</ul></div>}
                </div>
              ) : <p className="text-sm text-muted-foreground">{running ? t.aiPending : `${t.aiSkipped}${aiState?.error ? ` (${t.errors[aiState.error] || aiState.error})` : ''}`}</p>}
            </Box>
            <Box title={t.pipeline}><ProcessTimeline steps={steps} /></Box>
            {!running && <div className="lg:col-span-2 grid gap-4 lg:grid-cols-[1.3fr_1fr]"><SimilarFiles jobId={job.id} canCompare={!!rep.mine || !!job.public} />{rep.watch && <WatchCard watch={rep.watch} />}</div>}
          </div>
        )}

        {tab === 'av' && (
          <Box title={`${t.tabs.av} · ${detected}/${engines.length}`}>
            {!engines.length ? <Empty t={t} /> : (
              <div className="max-h-[560px] overflow-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-card text-left text-xs text-muted-foreground"><tr><th className="py-2 pr-2">{t.engine}</th><th className="py-2 pr-2">{t.result}</th><th className="py-2">Source</th></tr></thead>
                  <tbody>{engines.map((e, i) => (
                    <tr key={i} className="border-t border-border"><td className="py-1.5 pr-2">{e.engine}</td><td className={cn('py-1.5 pr-2', e.bad ? 'text-red-500' : 'text-muted-foreground')}>{e.result || (e.bad ? '!' : '—')}</td><td className="py-1.5 text-xs text-muted-foreground">{e.source}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </Box>
        )}

        {tab === 'intel' && (
          <>
            {malpedia && (
              <Box title={t.family_info} action={<a href={malpedia.link} target="_blank" rel="noreferrer noopener" className="text-xs text-muted-foreground hover:text-foreground"><ExternalLink className="size-3.5" /></a>}>
                <p className="font-medium">{malpedia.common_name}</p>
                {!!malpedia.alt_names?.length && <p className="text-xs text-muted-foreground">{malpedia.alt_names.join(', ')}</p>}
                <p className="mt-2 text-sm text-muted-foreground">{malpedia.description}</p>
              </Box>
            )}
            {[2, 3, 4, 10].flatMap((n) => results.filter((r) => r.layer === n && r.status !== 'disabled' && r.source !== 'malpedia' && r.source !== 'claude')).map((r) => (
              <Box key={r.source}>
                <SourceHead r={r} name={nameOf(r.source)} />
                {done(r) && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {(r.summary.tags || []).slice(0, 15).map((x: string) => <Chip key={x}>{x}</Chip>)}
                    {r.summary.first_seen && <Chip>first seen {String(r.summary.first_seen).slice(0, 10)}</Chip>}
                    {r.summary.product && <Chip>{r.summary.product}</Chip>}
                    {typeof r.summary.malicious === 'number' && typeof r.summary.total === 'number' && <Chip tone={r.summary.malicious ? 'red' : undefined}>{r.summary.malicious}/{r.summary.total}</Chip>}
                  </div>
                )}
                {done(r) && <List items={r.summary.reports} render={(x) => <span className="text-muted-foreground">{x.name}</span>} />}
              </Box>
            ))}
          </>
        )}

        {tab === 'static' && (
          <div className="grid gap-4 lg:grid-cols-2">
            <Box title={t.file}>
              <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-sm">
                <dt className="text-muted-foreground">{t.type}</dt><dd>{st.type}</dd>
                <dt className="text-muted-foreground">{t.size}</dt><dd>{num(job.size)} B</dd>
                <dt className="text-muted-foreground">{t.entropy}</dt><dd>{st.entropy}</dd>
                <dt className="text-muted-foreground">SHA-512</dt><dd><Mono>{st.sha512}</Mono></dd>
                {st.pe && <>
                  <dt className="text-muted-foreground">Arch</dt><dd>{st.pe.arch} · {st.pe.bits}-bit · {st.pe.subsystem}{st.pe.dll ? ' · DLL' : ''}{st.pe.dotnet ? ' · .NET' : ''}</dd>
                  <dt className="text-muted-foreground">Compiled</dt><dd>{st.pe.compiled_at || '—'}</dd>
                  <dt className="text-muted-foreground">Entry</dt><dd><Mono>{st.pe.entry_point} ({st.pe.entry_section || '?'})</Mono></dd>
                  <dt className="text-muted-foreground">imphash</dt><dd><Mono>{st.pe.imphash || '—'}</Mono></dd>
                  <dt className="text-muted-foreground">Overlay</dt><dd>{num(st.pe.overlay_bytes)} B</dd>
                  <dt className="text-muted-foreground">Signed</dt><dd>{st.pe.signed ? '✓' : '—'}{st.pe.tls_callbacks ? ' · TLS callbacks' : ''}</dd>
                </>}
              </dl>
              {!!st.pe?.packer_hints?.length && <div className="mt-3"><h4 className="text-sm font-medium">{t.packers}</h4><div className="mt-1 flex flex-wrap gap-1">{st.pe.packer_hints.map((p: string) => <Chip key={p} tone="red">{p}</Chip>)}</div></div>}
              {!!st.pe?.suspicious_apis?.length && <div className="mt-3"><h4 className="text-sm font-medium">{t.suspiciousApis}</h4><div className="mt-1 flex flex-wrap gap-1">{st.pe.suspicious_apis.map((p: string) => <Chip key={p}>{p}</Chip>)}</div></div>}
            </Box>
            {st.pe && (
              <Box title={t.sections}>
                <table className="w-full text-sm">
                  <thead className="text-left text-xs text-muted-foreground"><tr><th className="py-1">Name</th><th>Raw</th><th>Virtual</th><th>{t.entropy}</th></tr></thead>
                  <tbody>{st.pe.sections.map((s: any) => (
                    <tr key={s.name + s.va} className="border-t border-border"><td className="py-1 tabular-nums text-xs">{s.name || '∅'}{s.exec ? ' x' : ''}{s.write ? 'w' : ''}</td><td>{num(s.rawSize)}</td><td>{num(s.vsize)}</td>
                      <td><div className="flex items-center gap-2"><div className="h-1.5 w-16 rounded bg-secondary"><div className={cn('h-1.5 rounded', s.entropy > 7.2 ? 'bg-red-500' : s.entropy > 6.5 ? 'bg-amber-500' : 'bg-emerald-500')} style={{ width: `${(s.entropy / 8) * 100}%` }} /></div><span className="tabular-nums text-xs">{s.entropy}</span></div></td></tr>
                  ))}</tbody>
                </table>
                <h4 className="mt-4 text-sm font-medium">{t.imports} · {st.pe.import_count}</h4>
                <List items={st.pe.imports} render={(x) => <span><Mono>{x.dll}</Mono> <span className="text-xs text-muted-foreground">({x.count})</span></span>} />
              </Box>
            )}
            <Box title={t.yara}>
              {!yara.length ? <Empty t={t} /> : <List items={yara} render={(y) => <span><Mono>{y.rule}</Mono> <span className="text-xs text-muted-foreground">· {y.source}{y.description ? ` · ${y.description}` : ''}</span></span>} />}
              {results.filter((r) => r.layer === 5 && r.status !== 'disabled').map((r) => <div key={r.source} className="mt-3"><SourceHead r={r} name={nameOf(r.source)} />{done(r) && <List items={r.summary.alerts} render={(a) => <span className="text-muted-foreground">{a.title}</span>} />}</div>)}
            </Box>
            <StaticEngines results={results} />
            <Box title={t.indicators}>
              {(['urls', 'ips', 'domains', 'registry', 'paths', 'keywords'] as const).map((k) => st.indicators?.[k]?.length ? (
                <div key={k} className="mb-3"><h4 className="text-xs uppercase text-muted-foreground">{k}</h4><List items={st.indicators[k].slice(0, 15)} render={(x) => <Mono>{x}</Mono>} /></div>
              ) : null)}
              {st.script_head && <pre className="mt-2 max-h-80 overflow-auto rounded-lg bg-secondary p-3 text-xs">{st.script_head}</pre>}
            </Box>
          </div>
        )}

        {tab === 'unpack' && (
          <>
            {results.filter((r) => r.layer === 6 && r.status !== 'disabled').map((r) => <Box key={r.source}><SourceHead r={r} name={nameOf(r.source)} /></Box>)}
            <Box title={t.children}>
              {!children.length ? <Empty t={t} /> : (
                <ul className="divide-y divide-border">{children.map((c) => (
                  <li key={c.id}><Link to={`/scan/r/${c.id}`} className="flex items-center gap-3 py-3 hover:opacity-80">
                    <PackageOpen className="size-4 text-muted-foreground" />
                    <div className="min-w-0 flex-1"><p className="truncate text-sm">{c.file_name}</p><Mono>{c.sha256}</Mono></div>
                    {c.status === 'running' ? <Loader className="size-4 animate-spin" /> : <VerdictPill v={c.verdict} />}
                  </Link></li>
                ))}</ul>
              )}
            </Box>
          </>
        )}

        {tab === 'deobf' && (
          <>
            {results.filter((r) => r.layer === 7 && r.status !== 'disabled').map((r) => (
              <Box key={r.source}>
                <SourceHead r={r} name={nameOf(r.source)} />
                {done(r) && <List items={r.summary.signals} render={(s) => <span className="text-muted-foreground">{s.name} <Chip>{s.severity}</Chip></span>} />}
              </Box>
            ))}
            <Box title={t.configs}>
              {!configs.length ? <Empty t={t} /> : configs.map((c, i) => <pre key={i} className="mb-3 max-h-80 overflow-auto rounded-lg bg-secondary p-3 text-xs">{JSON.stringify(c, null, 2)}</pre>)}
            </Box>
            <Box title={t.scripts}>
              {!scripts.length ? <Empty t={t} /> : scripts.map((s, i) => (
                <div key={i} className="mb-4"><p className="mb-1 text-xs text-muted-foreground">{s.source} · {s.name}</p><pre className="max-h-96 overflow-auto rounded-lg bg-secondary p-3 text-xs">{s.text}</pre></div>
              ))}
            </Box>
          </>
        )}

        {tab === 'sandbox' && <SystemChanges results={results} behaviour={(computed as any)?.behaviour} />}
        {tab === 'sandbox' && mine && !running && <LiveCard jobId={job.id} />}
        {tab === 'sandbox' && <TokenTrap jobId={job.id} result={results.find((r) => r.source === 'honey')} mine={mine} onChange={reload} />}
        {tab === 'sandbox' && (
          results.filter((r) => r.layer === 8 && r.status !== 'disabled' && r.source !== 'honey').length === 0 ? <Box><Empty t={t} /></Box> :
          results.filter((r) => r.layer === 8 && r.status !== 'disabled' && r.source !== 'honey').map((r) => (
            <Box key={r.source}>
              <SourceHead r={r} name={nameOf(r.source)} />
              {r.source === 'cape' && <p className="mt-2 text-xs text-muted-foreground">{r.status === 'done' ? 'ClashGear makinesinde (canlı oturum ya da Token Tuzağı) görülenler.' : 'Makinedeki çalıştırma sürüyor ya da sonucu işleniyor; bitince burada görünecek.'}</p>}
              {done(r) && !!r.summary.captured?.length && (
                <div className="mt-3">
                  <h4 className="mb-1.5 text-sm font-medium">Bıraktığı / indirdiği dosyalar <span className="text-xs font-normal text-muted-foreground">— her biri ayrıca analiz edildi</span></h4>
                  <ul className="space-y-1.5">
                    {r.summary.captured.map((c: any) => {
                      const kid = children.find((k) => k.id === c.job_id)
                      return (
                        <li key={c.sha256} className="flex flex-wrap items-center gap-2 text-xs">
                          {kid ? <Link to={`/scan/r/${kid.id}`} className="font-medium text-foreground hover:underline">{c.name}</Link> : <span className="font-medium">{c.name}</span>}
                          {kid?.verdict && <VerdictPill v={kid.verdict} />}
                          <span className="text-muted-foreground">{c.type}</span>
                          {c.path && <Mono>{c.path}</Mono>}
                        </li>
                      )
                    })}
                  </ul>
                </div>
              )}
              {done(r) && !r.summary.skipped && <SandboxDetail s={r.summary} />}
              {done(r) && <CapeExtras s={r.summary} />}
              {done(r) && r.summary.activity?.processes?.length > 0 && <CapeActivity a={r.summary.activity} />}
              {done(r) && r.summary.skipped && <p className="mt-2 text-xs text-muted-foreground">{r.summary.note || r.summary.skipped}</p>}
            </Box>
          ))
        )}

        {tab === 'network' && results.find((r) => r.source === 'link_rep' && r.summary?.screenshot) && (
          <Box title="İndirme linki · urlscan.io ekran görüntüsü">
            <a href={results.find((r) => r.source === 'link_rep')!.summary.items.find((x: any) => x.screenshot)?.link} target="_blank" rel="noreferrer noopener"><img src={`/api/scan/jobs/${job.id}/screenshot`} alt="" loading="lazy" className="max-h-80 rounded-lg border border-border" /></a>
          </Box>
        )}
        {tab === 'network' && (
          <Box title={t.iocs}>
            {!iocItems.length ? <Empty t={t} /> : (
              <table className="w-full text-sm">
                <tbody>{iocItems.map((x, i) => (
                  <tr key={i} className="border-t border-border first:border-t-0">
                    <td className="py-1.5 pr-2"><Mono>{x.ioc}</Mono></td>
                    <td className="py-1.5 pr-2 text-xs text-muted-foreground">{x.type}</td>
                    <td className="py-1.5 pr-2">{x.malicious ? <Chip tone="red">{x.family || x.threat || x.classification || `risk ${x.risk ?? x.confidence ?? ''}`}</Chip> : <Chip>{x.org || x.country || x.classification || 'ok'}</Chip>}</td>
                    <td className="py-1.5 text-xs text-muted-foreground">{x.source}</td>
                  </tr>
                ))}</tbody>
              </table>
            )}
          </Box>
        )}
      </div>
      {!running && job.verdict === 'malicious' && <p className="mt-6 flex items-center gap-2 text-sm text-red-500"><TriangleAlert className="size-4" /> {t.verdicts.malicious}: {computed?.family || ai?.family || ''}</p>}
      {!running && mine && intro === 'new' && <NyxIntro target={askRef} href={`/scan/chat?job=${job.id}&auto=1`} verdict={job.verdict} score={job.score} onDone={introDone} />}
    </Shell>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-background/50 p-3">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 truncate font-semibold">{value}</div>
    </div>
  )
}

function ScanDiffPage() {
  const { a = '', b = '' } = useParams()
  return (
    <Shell>
      <div className="mb-4"><Link to={`/scan/r/${b}`} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-4" /> Rapora dön</Link></div>
      <h1 className="mb-4 text-xl font-semibold">Sürüm karşılaştırması</h1>
      <DiffView a={a} b={b} />
    </Shell>
  )
}

export default function Scan({ view }: { view: 'landing' | 'app' | 'report' | 'diff' }) {
  if (view === 'diff') return <ScanDiffPage />
  if (view === 'app') return <ScanApp />
  if (view === 'report') return <ScanReportPage />
  return <ScanLanding />
}
