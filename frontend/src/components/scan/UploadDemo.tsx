// A looping, scripted "screen recording" of the product: a cursor drags a file into the drop zone, it
// uploads, the layers report in at random moments, the AI flags it, the cursor opens the report and
// the report is shown. Motion beats follow 21st.dev's "Drop File to Upload" video block (cursor in
// from bottom-left → drop zone highlight → file chip spring → progress → done), rebuilt with
// framer-motion so it needs no video runtime. Critically damped springs; it only plays while on
// screen, and reduced motion shows the report frame.
import { useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion, useInView, useReducedMotion } from 'framer-motion'
import { Check, File, ScanSearch, ShieldCheck, Sparkles, TriangleAlert, Upload } from 'lucide-react'
import { BorderBeam } from '@/components/ui/border-beam'
import { Alert, AlertContent, AlertDescription, AlertTitle } from '@/components/ui/notice-alert'
import { TextShimmer } from '@/components/ui/text-shimmer'
import { AnimatedRadialChart } from '@/components/ui/animated-radial-chart'
import { cn } from '@/lib/utils'
import { useScan } from '@/i18n/scan'

// step: 0 enter · 1 carry · 2 drop · 3 upload · 4 layers · 5 verdict · 6 move to button · 7 click · 8 report · 9 out
const STEPS = [700, 1300, 450, 1300, 2700, 1300, 1000, 380, 4600, 700]
const LAST = STEPS.length - 1
const MOVE = 6
const CLICK = 7
const REPORT = 8
const SPRING = { type: 'spring' as const, bounce: 0, duration: 0.5 }
const CURSOR: Record<number, [string, string]> = {
  0: ['6%', '94%'], 1: ['50%', '36%'], 2: ['50%', '36%'], 3: ['58%', '46%'], 4: ['88%', '58%'], 5: ['88%', '58%'], 6: ['84%', '87%'], 7: ['84%', '87%'], 8: ['66%', '70%'], 9: ['66%', '70%'],
}

// macOS arrow: black body inside a white rim, soft drop shadow; the tip is the hotspot.
function Pointer({ pressed }: { pressed: boolean }) {
  return (
    <motion.svg width="24" height="26" viewBox="0 0 24 26" style={{ originX: 0.2, originY: 0.1 }} animate={{ scale: pressed ? 0.88 : 1 }} transition={{ type: 'spring', bounce: 0, duration: 0.18 }}
      className="-ml-[5px] -mt-[3px] drop-shadow-[0_1.5px_2.5px_rgba(0,0,0,0.45)]">
      <path d="M5 3v19.6l4.7-4.4 3.1 7.1 3.6-1.6-3-6.9h6.6z" fill="#fff" strokeLinejoin="round" />
      <path d="M6.6 6.8v12.1l3.6-3.4 3.4 7.7 1-.45-3.35-7.6h5.05z" fill="#000" strokeLinejoin="round" />
    </motion.svg>
  )
}

// Each layer finishes at its own random moment inside the window, so no two runs look the same.
function randomTicks(n: number, span: number) {
  return Array.from({ length: n }, () => 150 + Math.random() * (span - 500)).sort((a, b) => a - b)
}

type DemoCase = ReturnType<typeof useScan>['t']['demo']['cases'][number]

const VerdictIcon = ({ c, size }: { c: DemoCase; size: number }) =>
  c.clean ? <ShieldCheck className="text-emerald-400" size={size} strokeWidth={2} /> : <TriangleAlert className="text-amber-500" size={size} strokeWidth={2} />

function ReportView({ c }: { c: DemoCase }) {
  const { t } = useScan()
  const tabs = Object.values(t.tabs).slice(0, 5)
  return (
    <motion.div key="report" initial={{ opacity: 0, scale: 0.985, filter: 'blur(8px)' }} animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }} exit={{ opacity: 0, filter: 'blur(6px)' }} transition={SPRING}
      className="absolute inset-0 flex flex-col p-5">
      <div className="flex items-center gap-3">
        <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-white/[0.06]"><File className="size-4 text-neutral-300" /></div>
        <div className="min-w-0">
          <p className="truncate tabular-nums text-[12.5px] text-neutral-100">{c.file}</p>
          <p className="truncate tabular-nums text-[10.5px] text-neutral-600">sha256 {c.hash} · {c.size}</p>
        </div>
      </div>
      <div className="mt-4 grid flex-1 grid-cols-[auto_1fr] items-center gap-5">
        <div className="flex flex-col items-center">
          <AnimatedRadialChart value={c.score} size={168} strokeWidth={12} caption={t.score} duration={1.2} showLabels={false} />
        </div>
        <div className="min-w-0">
          <Alert layout="row" className="w-fit rounded-lg bg-neutral-950/80 py-2" icon={<VerdictIcon c={c} size={14} />}>
            <p className="text-[12.5px] font-medium text-white">{c.flag} <span className="ml-1 text-neutral-500">· {c.family}</span></p>
          </Alert>
          <p className="mt-3 flex items-center gap-2 text-[10.5px] font-medium uppercase tracking-[0.12em] text-neutral-500"><Sparkles className="size-3.5" /> {t.aiTitle}</p>
          <p className="mt-1.5 text-[13px] font-medium leading-snug text-neutral-100">{c.headline}</p>
          <ul className="mt-2.5 space-y-1">
            {c.findings.map((f, i) => (
              <motion.li key={f} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ ...SPRING, delay: 0.5 + i * 0.12 }} className="flex items-start gap-2 text-[11.5px] leading-snug text-neutral-400">
                <span className="mt-[6px] size-1 shrink-0 rounded-full bg-neutral-500" /><span>{f}</span>
              </motion.li>
            ))}
          </ul>
        </div>
      </div>
      <div className="mt-3 flex gap-1 overflow-hidden border-t border-white/[0.06] pt-3">
        {tabs.map((x, i) => <span key={x} className={cn('whitespace-nowrap rounded-md px-2.5 py-1 text-[11px]', i === 0 ? 'bg-white/[0.08] text-white' : 'text-neutral-500')}>{x}</span>)}
      </div>
    </motion.div>
  )
}

export function UploadDemo({ className }: { className?: string }) {
  const { t } = useScan()
  const d = t.demo
  const reduce = useReducedMotion()
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { margin: '-15% 0px' })
  const [step, setStep] = useState(0)
  const [rows, setRows] = useState(0)
  const [progress, setProgress] = useState(0)
  const bodyRef = useRef<HTMLDivElement>(null)
  const openRef = useRef<HTMLSpanElement>(null)
  const [buttonAt, setButtonAt] = useState<[string, string] | null>(null)
  // a different sample file every run (never the same twice in a row)
  const [ci, setCi] = useState(() => Math.floor(Math.random() * d.cases.length))
  const c = d.cases[ci] ?? d.cases[0]

  // Once the verdict card has settled, measure where "Open report" really is, so the cursor lands
  // on it at any window size.
  useEffect(() => {
    if (step !== 5) return
    const id = window.setTimeout(() => {
      const body = bodyRef.current?.getBoundingClientRect(), btn = openRef.current?.getBoundingClientRect()
      // in % like every other cursor position, so the motion library animates between same units
      if (body && btn && body.width) setButtonAt([`${(((btn.left - body.left + btn.width * 0.45) / body.width) * 100).toFixed(2)}%`, `${(((btn.top - body.top + btn.height * 0.55) / body.height) * 100).toFixed(2)}%`])
    }, 650)
    return () => window.clearTimeout(id)
  }, [step])

  // Drive the script; pause when scrolled away. Reduced motion pins the report frame.
  useEffect(() => {
    if (reduce) { setStep(REPORT); setRows(d.rows.length + 1); setProgress(100); return }
    if (!inView) return
    const timer = window.setTimeout(() => {
      if (step === LAST) setCi((prev) => { let n = prev; while (d.cases.length > 1 && n === prev) n = Math.floor(Math.random() * d.cases.length); return n })
      setStep((s) => (s === LAST ? 0 : s + 1))
    }, STEPS[step])
    return () => window.clearTimeout(timer)
  }, [step, inView, reduce, d.rows.length, d.cases.length])

  useEffect(() => {
    if (reduce) return
    if (step === 0) { setRows(0); setProgress(0) }
    if (step === 3) {
      const start = performance.now()
      let raf = 0
      const tick = (now: number) => {
        const p = Math.min(1, (now - start) / (STEPS[3] - 150))
        setProgress(Math.round((1 - (1 - p) ** 2) * 100))
        if (p < 1) raf = requestAnimationFrame(tick)
      }
      raf = requestAnimationFrame(tick)
      return () => cancelAnimationFrame(raf)
    }
    if (step === 4) {
      setRows(0)
      const ids = randomTicks(d.rows.length + 1, STEPS[4]).map((at, i) => window.setTimeout(() => setRows(i + 1), at))
      return () => ids.forEach(clearTimeout)
    }
  }, [step, reduce, d.rows.length])

  const carrying = step <= 1
  const dropped = step >= 2
  const uploaded = step >= 4
  const verdict = step >= 5
  const report = step >= REPORT
  const [cx, cy] = (step === MOVE || step === CLICK) && buttonAt ? buttonAt : CURSOR[step]

  return (
    <div ref={ref} className={cn('relative', className)}>
      <div className="glass relative overflow-hidden rounded-2xl shadow-[0_40px_120px_-30px_rgba(0,0,0,0.9)]">
        <BorderBeam duration={10} />
        {/* app bar */}
        <div className="flex items-center gap-3 border-b border-white/[0.06] px-4 py-2.5">
          <ScanSearch className="size-4 text-neutral-300" />
          <span className="text-[12.5px] font-medium text-neutral-200">ClashGear Scan</span>
          <span className="text-neutral-600">/</span>
          <span className="text-[12.5px] text-neutral-500">{report ? t.finished : t.newScan}</span>
          <span className="ml-auto flex items-center gap-2 text-[11px] text-neutral-500">
            <span className={cn('size-1.5 rounded-full', report ? (c.clean ? 'bg-emerald-400' : 'bg-amber-500') : 'animate-pulse bg-white/70')} />
            {report ? c.flag : d.analyzing}
          </span>
        </div>

        <div ref={bodyRef} className="relative aspect-[16/12] sm:aspect-[16/11]">
          <AnimatePresence mode="wait" initial={false}>
            {report ? <ReportView key="report" c={c} /> : (
              <motion.div key="flow" exit={{ opacity: 0, filter: 'blur(6px)' }} transition={{ duration: 0.25 }} className="absolute inset-0 p-5">
                {/* drop zone → file row */}
                <motion.div layout transition={SPRING}
                  className={cn('relative flex items-center rounded-2xl border transition-colors duration-300',
                    uploaded ? 'gap-3 border-white/[0.08] bg-white/[0.03] p-3' : 'h-[46%] flex-col justify-center border-dashed',
                    !uploaded && (step === 1 || step === 2) ? 'border-white/40 bg-white/[0.06]' : !uploaded ? 'border-white/15' : '')}>
                  {!dropped && (
                    <>
                      <div className="mb-2 flex size-10 items-center justify-center rounded-full border border-white/10 bg-white/[0.04]"><Upload className="size-4 text-neutral-400" /></div>
                      <p className="text-sm font-medium text-neutral-200">{d.drop}</p>
                      <p className="mt-0.5 text-xs text-neutral-500">{d.hint}</p>
                    </>
                  )}
                  {dropped && (
                    <motion.div initial={{ scale: 1.06, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ type: 'spring', bounce: 0.25, duration: 0.45 }}
                      className={cn('flex w-full items-center gap-3', !uploaded && 'max-w-[80%] rounded-xl border border-white/10 bg-black/40 p-3')}>
                      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-white/[0.06]"><File className="size-4 text-neutral-300" /></div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate tabular-nums text-[12px] text-neutral-200">{c.file}</p>
                        <div className="mt-1.5 flex items-center gap-2">
                          <div className="h-1 flex-1 overflow-hidden rounded-full bg-white/10">
                            <div className="h-full rounded-full bg-white transition-[width] duration-100" style={{ width: `${progress}%` }} />
                          </div>
                          <span className="w-16 text-right text-[10px] tabular-nums text-neutral-500">{uploaded ? c.size : `${d.uploading} ${progress}%`}</span>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </motion.div>

                {/* layer results */}
                <AnimatePresence>
                  {uploaded && (
                    <motion.div key="rows" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-4">
                      <div className="mb-2 flex items-center justify-between text-[11px] uppercase tracking-[0.12em] text-neutral-500">
                        {verdict ? <span>{d.analyzing}</span> : <TextShimmer>{d.analyzing}</TextShimmer>}
                        <span className="tabular-nums">{Math.min(rows, d.rows.length)}/{d.rows.length}</span>
                      </div>
                      <ul className="space-y-1.5">
                        {d.rows.map(([name], i) => { const value = c.values[i] ?? ''; return (
                          <motion.li key={name} initial={false} animate={{ opacity: rows > i ? 1 : 0.25, filter: rows > i ? 'blur(0px)' : 'blur(2px)' }} transition={{ duration: 0.3 }}
                            className="flex items-center gap-3 text-[12.5px]">
                            <motion.span initial={false} animate={{ scale: rows > i ? [0.6, 1.12, 1] : 1 }} transition={{ duration: 0.35 }}
                              className={cn('flex size-4 shrink-0 items-center justify-center rounded-full', rows > i ? 'bg-white text-black' : 'border border-white/20')}>
                              {rows > i && <Check className="size-2.5" strokeWidth={3} />}
                            </motion.span>
                            <span className="text-neutral-300">{name}</span>
                            <span className={cn('ml-auto truncate pl-3 text-right', rows > i ? 'text-neutral-200' : 'text-neutral-500')}>{rows > i ? value : '—'}</span>
                          </motion.li>
                        ) })}
                        <li className="flex items-center gap-3 text-[12.5px]">
                          <Sparkles className="size-4 shrink-0 text-neutral-300" />
                          <span className="text-neutral-300">{d.ai}</span>
                          <span className="ml-auto pl-3">{verdict ? <span className="text-neutral-400">✓</span> : rows > d.rows.length ? <TextShimmer>{d.aiWriting}</TextShimmer> : <span className="text-neutral-500">—</span>}</span>
                        </li>
                      </ul>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* AI flag */}
                <AnimatePresence>
                  {verdict && (
                    <motion.div key="flag" initial={{ opacity: 0, y: 10, scale: 0.97, filter: 'blur(8px)' }} animate={{ opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }} transition={SPRING}
                      className="absolute inset-x-5 bottom-5">
                      <Alert
                        layout="complex"
                        size="lg"
                        className="rounded-xl bg-neutral-950/90 shadow-lg shadow-black/40 backdrop-blur-md"
                        icon={<VerdictIcon c={c} size={16} />}
                        action={<motion.span ref={openRef} animate={{ scale: step === CLICK ? 0.94 : 1, backgroundColor: step === CLICK ? '#d4d4d4' : step === MOVE ? '#f5f5f5' : '#ffffff' }} transition={{ duration: 0.12 }} className="inline-flex rounded-md px-3 py-1.5 text-xs font-semibold text-black">{d.open}</motion.span>}
                      >
                        <AlertContent>
                          <AlertTitle className="text-white">{c.flag} <span className="ml-1 tabular-nums text-xs font-normal text-neutral-500">{c.score}/100</span></AlertTitle>
                          <AlertDescription className="truncate text-xs">{c.family}</AlertDescription>
                        </AlertContent>
                      </Alert>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            )}
          </AnimatePresence>

          {/* cursor (+ the file it carries) */}
          {!reduce && (
            <motion.div className="pointer-events-none absolute z-20" initial={false} animate={{ left: cx, top: cy, opacity: step === LAST ? 0 : 1 }} transition={{ type: 'spring', bounce: 0, duration: step === 1 ? 1.1 : step === MOVE ? 0.6 : 0.8 }}>
              <AnimatePresence>
                {carrying && (
                  <motion.div key="chip" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }} transition={{ duration: 0.2 }}
                    className="absolute left-3 top-4 flex items-center gap-2 whitespace-nowrap rounded-lg border border-white/15 bg-neutral-900/90 px-2.5 py-1 tabular-nums text-[11px] text-neutral-200 shadow-xl">
                    <File className="size-3 shrink-0" /> {c.file}
                  </motion.div>
                )}
              </AnimatePresence>
              <Pointer pressed={step === 2 || step === CLICK} />
            </motion.div>
          )}
        </div>
      </div>
      <p className="mt-3 text-center text-[11px] text-neutral-600">{d.caption}</p>
    </div>
  )
}
