// "Ask Nyx": a scripted chat played in code (no video, nothing tied to scroll). A cursor drags a file
// into the chat box, types a question and sends it; Nyx, the AI analyst, runs through the layers and
// writes a detailed answer. Nyx's eyes follow the visitor's mouse, or the demo cursor while the
// mouse is still. It starts when the section comes into view, replays on demand and on its own
// after a pause, and with reduced motion shows the finished conversation.
import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { AnimatePresence, motion, useInView, useReducedMotion } from 'framer-motion'
import {
  Check, ChevronRight, Cpu, Eye, FileText, Fingerprint, Globe, KeyRound, Monitor, Network, PackageOpen, Pencil,
  RotateCcw, Search, ShieldCheck, Sparkles, Terminal, TriangleAlert,
} from 'lucide-react'
import { AiAvatar, type AvatarColor, type AvatarSize } from '@/components/ui/ai-avatar'
import { LiquidInput } from '@/components/ui/liquid-input'
import { Alert, AlertContent, AlertDescription, AlertTitle } from '@/components/ui/notice-alert'
import { TextShimmer } from '@/components/ui/text-shimmer'
import { cn } from '@/lib/utils'
import { useScan, type NyxCase, type NyxStep } from '@/i18n/scan'

type Pt = { x: number; y: number }
type Phase = 'idle' | 'enter' | 'drag' | 'drop' | 'focus' | 'click' | 'type' | 'aim' | 'press' | 'think' | 'answer' | 'done'
const SPRING = { type: 'spring' as const, bounce: 0, duration: 0.5 }

// macOS arrow: black body inside a white rim; the tip is the hotspot.
export function Pointer({ pressed }: { pressed: boolean }) {
  return (
    <motion.svg width="24" height="26" viewBox="0 0 24 26" style={{ originX: 0.2, originY: 0.1 }} animate={{ scale: pressed ? 0.88 : 1 }} transition={{ type: 'spring', bounce: 0, duration: 0.18 }}
      className="-ml-[5px] -mt-[3px] drop-shadow-[0_1.5px_2.5px_rgba(0,0,0,0.45)]">
      <path d="M5 3v19.6l4.7-4.4 3.1 7.1 3.6-1.6-3-6.9h6.6z" fill="#fff" />
      <path d="M6.6 6.8v12.1l3.6-3.4 3.4 7.7 1-.45-3.35-7.6h5.05z" fill="#000" />
    </motion.svg>
  )
}

/** An avatar whose eyes follow `target` (client coordinates), re-aimed on animation frames. */
export function LookingAvatar({ target, size, thinking, label, color }: { target: RefObject<(() => Pt | null) | null>; size: AvatarSize; thinking?: boolean; label: string; color?: AvatarColor }) {
  const ref = useRef<HTMLDivElement>(null)
  const [look, setLook] = useState<Pt>({ x: 0, y: 0 })
  const inView = useInView(ref)
  useEffect(() => {
    if (!inView) return
    let raf = 0
    let last = { x: 0, y: 0 }
    const tick = () => {
      const el = ref.current, t = target.current?.()
      if (el && t) {
        const r = el.getBoundingClientRect()
        const dx = t.x - (r.left + r.width / 2), dy = t.y - (r.top + r.height / 2)
        const d = Math.hypot(dx, dy) || 1
        const k = Math.min(1, d / 220) // close targets give a smaller glance
        const next = { x: (dx / d) * k, y: (dy / d) * k }
        if (Math.abs(next.x - last.x) > 0.04 || Math.abs(next.y - last.y) > 0.04) { last = next; setLook(next) }
      }
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [inView, target])
  return <div ref={ref} className="shrink-0"><AiAvatar size={size} look={look} thinking={thinking} label={label} color={color} /></div>
}

type WorkStep = readonly ['say', string] | readonly ['tool', string, string, string, number?, number?]
const TOOL_ICON: Record<string, typeof FileText> = {
  read: FileText, hash: Fingerprint, cpu: Cpu, unpack: PackageOpen, search: Search, wand: Sparkles,
  terminal: Terminal, globe: Globe, vm: Monitor, network: Network, key: KeyRound, edit: Pencil, eye: Eye,
}

/** Nyx's running log: narration lines and tool calls, then folded into one summary line. */
function WorkLog({ steps, started, sayWords, running, durs, live, collapsed, title, thinkingLabel, sec }: {
  steps: readonly WorkStep[]; started: number; sayWords: number; running: boolean; durs: number[]
  live: boolean; collapsed: boolean; title: string; thinkingLabel: string; sec: string
}) {
  const totalMs = durs.reduce((s, d) => s + (d || 0), 0)
  const fmt = (ms: number) => (ms / 1000).toFixed(1).replace('.', sec === 'sn' ? ',' : '.')
  if (collapsed) {
    return (
      <p className="flex items-center gap-2 text-[11.5px] text-neutral-500">
        <ChevronRight className="size-3.5 shrink-0" /> {title} · {steps.filter((s) => s[0] === 'tool').length} · {fmt(totalMs)} {sec}
      </p>
    )
  }
  return (
    <div className="space-y-1.5">
      {live && started === 0 && <TextShimmer className="text-[12px]">{thinkingLabel}</TextShimmer>}
      {steps.slice(0, started).map((s, i) => {
        const current = live && i === started - 1
        if (s[0] === 'say') {
          const text = current ? s[1].split(' ').slice(0, sayWords).join(' ') : s[1]
          return <p key={i} className="pt-0.5 text-[13px] leading-relaxed text-neutral-300">{text}</p>
        }
        const [, icon, label, detail, added, removed] = s
        const Icon = TOOL_ICON[icon] || Terminal
        const busy = current && running
        return (
          <motion.div key={i} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ type: 'spring', bounce: 0, duration: 0.3 }}
            className="flex min-w-0 items-center gap-2.5 rounded-lg bg-white/[0.035] px-2.5 py-1.5 text-[12px]">
            <Icon className={cn('size-3.5 shrink-0', busy ? 'text-neutral-200' : 'text-neutral-500')} />
            {busy ? <TextShimmer className="shrink-0 font-medium">{label}</TextShimmer> : <span className="shrink-0 font-medium text-neutral-200">{label}</span>}
            <span className="min-w-0 truncate text-neutral-500">{detail}</span>
            <span className="ml-auto flex shrink-0 items-center gap-2 pl-1 tabular-nums">
              {!!added && <span className="text-emerald-400/90">+{added}</span>}
              {!!removed && <span className="text-neutral-500">−{removed}</span>}
              {durs[i] ? <span className="text-neutral-600">{fmt(durs[i])} {sec}</span> : <span className="size-1.5 animate-pulse rounded-full bg-neutral-400" />}
            </span>
          </motion.div>
        )
      })}
    </div>
  )
}

/** The answer as blocks, with how many words each one streams (the verdict card counts as 4). */
function answerBlocks(c: NyxCase, todoTitle: string) {
  const blocks: { kind: 'h' | 'p' | 'li' | 'verdict' | 'h2' | 'todo'; text: string }[] = [
    { kind: 'h', text: c.headline },
    { kind: 'p', text: c.body },
    ...c.findings.map((text) => ({ kind: 'li' as const, text })),
    { kind: 'verdict', text: c.verdict },
    { kind: 'h2', text: todoTitle },
    ...c.todo.map((text) => ({ kind: 'todo' as const, text })),
  ]
  const words = blocks.map((b) => (b.kind === 'verdict' ? 4 : b.text.split(' ').length))
  return { blocks, words, total: words.reduce((s, n) => s + n, 0) }
}

/** A different index from `prev` (when there is more than one). */
const pickOther = (prev: number, n: number) => { let i = prev; while (n > 1 && i === prev) i = Math.floor(Math.random() * n); return i }

export function AiChatDemo() {
  const { t } = useScan()
  const a = t.ai
  const reduce = useReducedMotion()
  const sectionRef = useRef<HTMLElement>(null)
  const boxRef = useRef<HTMLDivElement>(null) // the chat window: cursor coordinates are % of it
  const inputRef = useRef<HTMLDivElement>(null)
  const textRef = useRef<HTMLDivElement>(null)
  const sendRef = useRef<HTMLSpanElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const cursorRef = useRef<HTMLDivElement>(null)
  const inView = useInView(sectionRef, { margin: '-20% 0px' })

  const [phase, setPhase] = useState<Phase>('idle')
  const [run, setRun] = useState(0)
  const [typed, setTyped] = useState('')
  const [attached, setAttached] = useState(false)
  const [sent, setSent] = useState(false)
  const [workIdx, setWorkIdx] = useState(0) // work steps started so far
  const [sayWords, setSayWords] = useState(0) // words of the current narration line
  const [running, setRunning] = useState(false) // current tool call still running
  const [durs, setDurs] = useState<number[]>([]) // how long each tool call took
  const [shown, setShown] = useState(0)
  const [cursor, setCursor] = useState<{ x: string; y: string; visible: boolean }>({ x: '92%', y: '108%', visible: false })

  // every run plays a different scenario: file, question, work log and answer
  const cases = useMemo<NyxCase[]>(() => [
    { file: t.demo.file, size: t.demo.size, question: a.question, clean: false, work: a.work as NyxStep[], headline: a.headline, body: a.body, findings: a.findings, verdict: a.verdict, family: a.family, todo: a.todo },
    ...a.cases,
  ], [a, t.demo])
  const [ci, setCi] = useState(() => Math.floor(Math.random() * 6))
  const ciRef = useRef(ci)
  const c = cases[ci % cases.length]
  const { blocks, words } = useMemo(() => answerBlocks(c, a.todoTitle), [c, a.todoTitle])

  // where Nyx looks: the visitor's mouse if it moved recently, otherwise the demo cursor
  const mouse = useRef<{ p: Pt; at: number }>({ p: { x: 0, y: 0 }, at: -1e9 })
  const lookTarget = useRef<(() => Pt | null) | null>(null)
  lookTarget.current = () => {
    if (performance.now() - mouse.current.at < 2500) return mouse.current.p
    const c = cursorRef.current?.getBoundingClientRect()
    if (c && cursor.visible) return { x: c.left, y: c.top }
    const s = scrollRef.current?.getBoundingClientRect()
    return s ? { x: s.left + s.width / 2, y: s.bottom } : null
  }
  useEffect(() => {
    const onMove = (e: PointerEvent) => { mouse.current = { p: { x: e.clientX, y: e.clientY }, at: performance.now() } }
    window.addEventListener('pointermove', onMove, { passive: true })
    return () => window.removeEventListener('pointermove', onMove)
  }, [])

  // centre of an element, as % of the chat window (same unit for every cursor position)
  const at = useCallback((el: Element | null, fx = 0.5, fy = 0.5) => {
    const box = boxRef.current?.getBoundingClientRect(), r = el?.getBoundingClientRect()
    if (!box || !r || !box.width) return { x: '50%', y: '50%' }
    return { x: `${(((r.left - box.left) + r.width * fx) / box.width) * 100}%`, y: `${(((r.top - box.top) + r.height * fy) / box.height) * 100}%` }
  }, [])

  const reset = useCallback(() => {
    setTyped(''); setAttached(false); setSent(false); setWorkIdx(0); setSayWords(0); setRunning(false); setDurs([]); setShown(0)
    setCursor({ x: '92%', y: '108%', visible: false })
    setPhase('idle')
  }, [])

  // the script
  useEffect(() => {
    if (reduce) {
      const sc = cases[ciRef.current % cases.length]
      setSent(true); setWorkIdx(sc.work.length); setDurs(sc.work.map(() => 900)); setShown(answerBlocks(sc, a.todoTitle).total); setPhase('done')
      return
    }
    if (!inView) return
    let alive = true
    const timers: number[] = []
    const wait = (ms: number) => new Promise<void>((r) => { timers.push(window.setTimeout(r, ms)) })
    // pick this run's scenario (never the one just shown) and play it start to finish
    const next = run === 0 ? ciRef.current % cases.length : pickOther(ciRef.current % cases.length, cases.length)
    ciRef.current = next
    setCi(next)
    const sc = cases[next]
    const scTotal = answerBlocks(sc, a.todoTitle).total
    ;(async () => {
      reset()
      await wait(900); if (!alive) return
      setPhase('enter'); setCursor({ x: '96%', y: '96%', visible: true })
      await wait(500); if (!alive) return
      setPhase('drag'); setCursor({ ...at(inputRef.current, 0.45, 0.45), visible: true })
      await wait(1150); if (!alive) return
      setPhase('drop'); setAttached(true)
      await wait(550); if (!alive) return
      setPhase('focus'); setCursor({ ...at(textRef.current, 0.28, 0.5), visible: true })
      await wait(750); if (!alive) return
      setPhase('click')
      await wait(180); if (!alive) return
      setPhase('type')
      for (let i = 1; i <= sc.question.length; i++) { setTyped(sc.question.slice(0, i)); await wait(34 + Math.random() * 40); if (!alive) return }
      await wait(300); if (!alive) return
      setPhase('aim'); setCursor({ ...at(sendRef.current, 0.5, 0.55), visible: true })
      await wait(800); if (!alive) return
      setPhase('press')
      await wait(220); if (!alive) return
      setSent(true); setTyped(''); setAttached(false)
      setPhase('think'); setCursor((c) => ({ ...c, x: '78%', y: '58%' }))
      await wait(700); if (!alive) return
      // Nyx works through the file: narration lines stream in word by word, tool calls run for a
      // random while and then settle with their duration
      for (let i = 0; i < sc.work.length; i++) {
        const step = sc.work[i]
        setWorkIdx(i + 1); setSayWords(0)
        if (step[0] === 'say') {
          const n = step[1].split(' ').length
          for (let k = 1; k <= n; k++) { setSayWords(k); await wait(45 + Math.random() * 60); if (!alive) return }
          await wait(380 + Math.random() * 380); if (!alive) return
        } else {
          setRunning(true)
          const took = 520 + Math.random() * 1050
          await wait(took); if (!alive) return
          setDurs((d) => { const next = d.slice(); next[i] = took; return next })
          setRunning(false)
          await wait(140 + Math.random() * 220); if (!alive) return
        }
      }
      await wait(450); if (!alive) return
      setPhase('answer'); setCursor((c) => ({ ...c, visible: false }))
      for (let i = 1; i <= scTotal; i++) { setShown(i); await wait(22 + Math.random() * 26); if (!alive) return }
      setPhase('done')
      await wait(11000); if (!alive) return
      setRun((n) => n + 1) // play again while it is still on screen
    })()
    return () => { alive = false; timers.forEach(clearTimeout) }
  }, [inView, run, reduce, a, cases, at, reset])

  // keep the newest line in view while the answer streams
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [shown, workIdx, sayWords, running, sent])

  // words visible per block
  let left = shown
  const visible = words.map((n) => { const v = Math.max(0, Math.min(n, left)); left -= n; return v })
  const cut = (text: string, n: number) => text.split(' ').slice(0, n).join(' ')

  const thinking = phase === 'think'
  const answering = phase === 'answer' || phase === 'done'

  return (
    <section ref={sectionRef} id="scene" aria-label={a.title} className="relative scroll-mt-24 py-24">
      <div className="mx-auto grid max-w-6xl items-center gap-12 px-5 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-neutral-500">{a.kicker}</p>
          <div className="mt-5 flex items-center gap-5">
            <LookingAvatar target={lookTarget} size="xl" thinking={thinking} label={a.name} />
            <div>
              <p className="text-2xl font-semibold tracking-[-0.02em] text-white">{a.name}</p>
              <p className="mt-1 flex items-center gap-2 text-sm text-neutral-400"><span className="size-1.5 rounded-full bg-emerald-400" /> {a.role}</p>
            </div>
          </div>
          <h2 className="mt-8 text-4xl font-semibold leading-[1.08] tracking-[-0.03em] text-white">{a.title}</h2>
          <p className="mt-4 max-w-md text-[15px] leading-relaxed text-neutral-400">{a.sub}</p>
          {!reduce && (
            <button type="button" onClick={() => setRun((n) => n + 1)} className="press mt-8 inline-flex items-center gap-2 rounded-xl border border-white/10 px-3.5 py-2 text-[13px] text-neutral-300 transition-colors hover:bg-white/[0.06] hover:text-white">
              <RotateCcw className="size-3.5" /> {a.replay}
            </button>
          )}
        </div>

        {/* the chat window */}
        <div ref={boxRef} className="glass relative rounded-3xl p-4 shadow-[0_40px_120px_-30px_rgba(0,0,0,0.9)] sm:p-5">
          <div className="flex items-center gap-3 border-b border-white/[0.06] pb-3.5">
            <LookingAvatar target={lookTarget} size="sm" thinking={thinking} label={a.name} />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-white">{a.name}</p>
              <p className="flex items-center gap-1.5 text-[11px] text-neutral-500"><span className="size-1.5 rounded-full bg-emerald-400" /> {a.online}</p>
            </div>
          </div>

          <div ref={scrollRef} className="h-[380px] space-y-4 overflow-hidden py-4 sm:h-[420px]">
            {/* welcome */}
            <div className="flex gap-3">
              <span className="mt-0.5 size-6 shrink-0 rounded-full" style={{ background: 'radial-gradient(circle at 50% 45%, #141a24 0%, #3a4a63 40%, #8fa6c8 70%, #e6edf7 100%)' }} />
              <p className="max-w-[85%] rounded-2xl rounded-tl-md bg-white/[0.05] px-3.5 py-2.5 text-[13.5px] leading-relaxed text-neutral-200">{a.welcome}</p>
            </div>

            {/* the visitor's message */}
            <AnimatePresence>
              {sent && (
                <motion.div key={`q${run}`} initial={{ opacity: 0, y: 10, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={SPRING} className="flex flex-col items-end gap-2">
                  <div className="flex items-center gap-2.5 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2">
                    <FileText className="size-4 shrink-0 text-neutral-400" />
                    <span className="text-xs text-neutral-200">{c.file}</span>
                    <span className="text-[11px] text-neutral-500">{c.size}</span>
                  </div>
                  <p className="max-w-[80%] rounded-2xl rounded-tr-md bg-white px-3.5 py-2.5 text-[13.5px] leading-relaxed text-black">{c.question}</p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Nyx: scanning, then the answer */}
            <AnimatePresence>
              {(thinking || answering) && (
                <motion.div key={`a${run}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={SPRING} className="flex gap-3">
                  <span className="mt-0.5 size-6 shrink-0 rounded-full" style={{ background: 'radial-gradient(circle at 50% 45%, #141a24 0%, #3a4a63 40%, #8fa6c8 70%, #e6edf7 100%)' }} />
                  <div className="min-w-0 max-w-[90%] flex-1 space-y-3 rounded-2xl rounded-tl-md bg-white/[0.05] px-3.5 py-3 text-[13.5px] leading-relaxed text-neutral-300">
                    <WorkLog steps={c.work} started={workIdx} sayWords={sayWords} running={running} durs={durs} live={thinking}
                      collapsed={answering} title={a.workTitle} thinkingLabel={a.thinking} sec={a.sec} />
                    {answering && blocks.map((b, i) => {
                      if (!visible[i]) return null
                      const text = cut(b.text, visible[i])
                      if (b.kind === 'h') return <p key={i} className="text-[14.5px] font-semibold leading-snug text-white">{text}</p>
                      if (b.kind === 'h2') return <p key={i} className="pt-1 font-semibold text-white">{text}</p>
                      if (b.kind === 'p') return <p key={i}>{text}</p>
                      if (b.kind === 'verdict') return (
                        <motion.div key={i} initial={{ opacity: 0, scale: 0.97, filter: 'blur(6px)' }} animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }} transition={SPRING}>
                          <Alert layout="complex" className="rounded-xl bg-neutral-950/80" icon={c.clean
                            ? <ShieldCheck className="text-emerald-400" size={16} strokeWidth={2} />
                            : <TriangleAlert className="text-amber-500" size={16} strokeWidth={2} />}>
                            <AlertContent>
                              <AlertTitle className="text-white">{b.text}</AlertTitle>
                              <AlertDescription className="text-xs">{c.family}</AlertDescription>
                            </AlertContent>
                          </Alert>
                        </motion.div>
                      )
                      return (
                        <p key={i} className="flex gap-2.5">
                          {b.kind === 'todo' ? <Check className="mt-[3px] size-3.5 shrink-0 text-neutral-200" strokeWidth={2.5} /> : <span className="mt-[9px] size-1 shrink-0 rounded-full bg-neutral-500" />}
                          <span>{text}</span>
                        </p>
                      )
                    })}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <LiquidInput ref={inputRef} textRef={textRef} sendRef={sendRef} value={typed} placeholder={a.placeholder}
            files={attached ? [{ name: c.file, size: c.size }] : []} focused={phase === 'click' || phase === 'type' || phase === 'aim' || phase === 'press'}
            dragOver={phase === 'drag'} sendPressed={phase === 'press'} modelLabel={a.model} dropHint={a.drop} />

          {/* demo cursor (+ the file it carries) */}
          {!reduce && (
            <motion.div ref={cursorRef} className="pointer-events-none absolute z-40" initial={false}
              animate={{ left: cursor.x, top: cursor.y, opacity: cursor.visible ? 1 : 0 }}
              transition={{ type: 'spring', bounce: 0, duration: phase === 'drag' ? 1.05 : 0.7 }}>
              <AnimatePresence>
                {(phase === 'enter' || phase === 'drag') && (
                  <motion.div key="chip" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }} transition={{ duration: 0.2 }}
                    className="absolute left-3 top-4 flex items-center gap-2 whitespace-nowrap rounded-lg border border-white/15 bg-neutral-900/90 px-2.5 py-1 text-[11px] text-neutral-200 shadow-xl">
                    <FileText className="size-3 shrink-0" /> {c.file}
                  </motion.div>
                )}
              </AnimatePresence>
              <Pointer pressed={phase === 'click' || phase === 'press'} />
            </motion.div>
          )}
        </div>
      </div>
    </section>
  )
}
