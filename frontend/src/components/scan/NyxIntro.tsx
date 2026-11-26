// "Analysis finished" scene on the report page, played once per scan:
// the page blurs, "Analiz bitti" wipes in, Nyx grows from a point and glances around, a speech bubble
// with a slowly turning lit border grows out of it and types its offer, a curling arrow draws itself to
// the "Nyx'e sor" button, and Nyx rides the arrow, shrinking, and perches on that button. The scene then
// holds (blurred, arrow and bubble in place) until the visitor either presses the button or "İlgilenmiyorum".
// Motion rules from the owner's higgsfield-motion-saas skill: nothing appears or leaves by opacity alone
// (grow, wipe, carry), soft in-scene curves (0.45–0.7 s, overshoot ≤2 %), the next move starts ≈0.45 into
// the current one, and the target button is carried above the blur as an identical copy at its exact rect.
// Note: framer-motion writes `transform` itself, so centring uses its x/y ('-50%'), never Tailwind translate.
import { useCallback, useEffect, useRef, useState, type RefObject } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { animate, motion, useMotionValue, useReducedMotion, useTransform } from 'framer-motion'
import { Sparkles } from 'lucide-react'
import { AiAvatar } from '@/components/ui/ai-avatar'
import { useScan } from '@/i18n/scan'

type Pt = { x: number; y: number }
const OUT3: [number, number, number, number] = [0.33, 1, 0.68, 1] // out(3)
const IN2: [number, number, number, number] = [0.55, 0, 1, 0.45] // in(2), exits
const SMOOTH: [number, number, number, number] = [0.65, 0, 0.35, 1]
const NYX_PX = 48 // AiAvatar "md"
const PERCH_SCALE = 0.45
const PERCH = NYX_PX * PERCH_SCALE
const PERCH_TOP = 16 // the perched Nyx starts this far above the button's top edge, overlapping it

export type IntroState = 'play' | 'perched' | 'dismissed'

/** Nyx perched on top of a button: centred on it, gently bobbing and looking around. */
function Perch({ onClick }: { onClick?: () => void }) {
  const [look, setLook] = useState<Pt>({ x: 0, y: 0.3 })
  useEffect(() => {
    const path = [{ x: -1, y: 0.2 }, { x: 0, y: 0.3 }, { x: 1, y: 0.2 }, { x: 0, y: 0.7 }]
    let i = 0
    const id = window.setInterval(() => { setLook(path[i++ % path.length]) }, 1800)
    return () => window.clearInterval(id)
  }, [])
  return (
    <motion.button type="button" onClick={onClick} aria-label="Nyx"
      className="pointer-events-auto absolute left-1/2 z-10" style={{ top: -PERCH_TOP, width: PERCH, height: PERCH, x: '-50%' }}
      animate={{ y: [0, -2, 0] }} transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}>
      <span className="block origin-top-left" style={{ transform: `scale(${PERCH_SCALE})` }}><AiAvatar size="md" look={look} label="Nyx" /></span>
    </motion.button>
  )
}

/** Where Nyx sits on the report's button once the scene is over. */
export function PerchedNyx({ onClick }: { onClick?: () => void }) {
  return <Perch onClick={onClick} />
}

export function NyxIntro({ target, href, verdict, score, onDone }: {
  target: RefObject<HTMLElement | null>
  href: string
  verdict: string | null
  score: number | null
  onDone: (s: Exclude<IntroState, 'play'>) => void
}) {
  const { t } = useScan()
  const reduce = useReducedMotion()
  const timers = useRef<number[]>([])
  const stops = useRef<{ stop: () => void }[]>([])
  const pathRef = useRef<SVGPathElement>(null)
  const [geo, setGeo] = useState<{ rect: DOMRect; nyx: Pt; d: string; tip: Pt; angle: number; perch: Pt; bubble: Pt } | null>(null)
  const [typed, setTyped] = useState(0)
  const [typed2, setTyped2] = useState(0)
  const [look, setLook] = useState<Pt>({ x: 0, y: 0 })
  const [showNo, setShowNo] = useState(false)
  const [perched, setPerched] = useState(false)
  const [leaving, setLeaving] = useState(false)

  const dim = useMotionValue(0)
  const blur = useMotionValue(0)
  const head = useMotionValue(0) // 0 hidden → 1 shown (clip wipe from below)
  const nyxS = useMotionValue(0.06)
  const nyxX = useMotionValue(0)
  const nyxY = useMotionValue(0)
  const bubble = useMotionValue(0)
  const bubble2 = useMotionValue(0) // the second bubble, opening downwards from the perched Nyx
  const arrowLen = useMotionValue(0)
  const arrowOff = useMotionValue(0)
  const tipS = useMotionValue(0)
  const [tipScale, setTipScale] = useState(0)
  useEffect(() => tipS.on('change', (v) => setTipScale(Math.max(0, v))), [tipS])
  const glow = useMotionValue(0)
  const navigate = useNavigate()

  const backdrop = useTransform(blur, (b) => `blur(${b}px) saturate(${1 - b / 40})`)
  const bg = useTransform(dim, (v) => `rgba(5,6,8,${0.55 * v})`)
  const headClip = useTransform(head, (h) => `inset(${(1 - h) * 100}% 0 0 0)`)
  const headY = useTransform(head, (h) => (1 - h) * 26)
  const ring = useTransform(glow, (g) => `0 0 0 ${2 + g * 5}px rgba(230,237,247,${0.16 + g * 0.3}), 0 0 ${18 + g * 30}px rgba(143,166,200,${0.3 * g + 0.15})`)

  const message = t.introAsk
  const message2 = t.introTell
  const clear = () => { timers.current.forEach(window.clearTimeout); timers.current = []; stops.current.forEach((s) => s.stop()); stops.current = [] }
  const at = (ms: number, fn: () => void) => { timers.current.push(window.setTimeout(fn, ms)) }
  const go = (mv: any, to: any, opts: any) => { stops.current.push(animate(mv, to, opts) as any) }

  // Geometry: the button's rect, Nyx's stage point, the bubble, the curling arrow and the perch point.
  useEffect(() => {
    window.scrollTo({ top: 0 })
    const el = target.current
    if (!el) { onDone('perched'); return }
    const rect = el.getBoundingClientRect()
    const vw = window.innerWidth, vh = window.innerHeight
    const narrow = vw < 640
    const nyx = { x: narrow ? 48 : vw / 2 - 150, y: Math.min(vh * 0.6, vh - 200) }
    const bubbleAt = { x: nyx.x + 30, y: nyx.y - 34 } // bubble's bottom-left corner
    const tip = { x: rect.left + rect.width / 2, y: rect.bottom + 12 }
    const s = { x: nyx.x + 40, y: nyx.y + 26 }
    const mid = { x: Math.min(vw - 60, (s.x + tip.x) / 2 + Math.min(180, vw * 0.14)), y: Math.max(tip.y + 120, (s.y + tip.y) / 2 + 90) }
    // a swoop under the bubble, a curl, then straight up into the button from below; on phones it climbs the right margin
    const d = narrow
      ? `M ${s.x} ${s.y} C ${s.x + 70} ${s.y + 150}, ${vw - 14} ${s.y + 90}, ${vw - 30} ${(s.y + tip.y) / 2} S ${tip.x} ${tip.y + 110}, ${tip.x} ${tip.y}`
      : `M ${s.x} ${s.y} C ${s.x + 110} ${s.y + 120}, ${mid.x + 110} ${mid.y + 110}, ${mid.x} ${mid.y} S ${tip.x} ${tip.y + 120}, ${tip.x} ${tip.y}`
    const perch = { x: rect.left + rect.width / 2, y: rect.top - PERCH_TOP + PERCH / 2 }
    setGeo({ rect, nyx, d, tip, angle: -90, perch, bubble: bubbleAt })
    nyxX.set(nyx.x); nyxY.set(nyx.y)
    if (reduce) onDone('perched')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Arrowhead direction = the path's tangent at the tip.
  useEffect(() => {
    const p = pathRef.current
    if (!geo || !p) return
    const L = p.getTotalLength(), a = p.getPointAtLength(L - 6), b = p.getPointAtLength(L)
    const angle = (Math.atan2(b.y - a.y, b.x - a.x) * 180) / Math.PI
    if (Math.abs(angle - geo.angle) > 0.5) setGeo({ ...geo, angle })
  }, [geo])

  // The timeline (ms). Each move overlaps the previous one at ≈0.45 of its length.
  useEffect(() => {
    if (!geo || reduce) return
    go(dim, 1, { duration: 0.5, ease: OUT3 }); go(blur, 10, { duration: 0.55, ease: OUT3 })
    at(150, () => go(head, 1, { duration: 0.6, ease: OUT3 }))
    at(420, () => go(nyxS, 1, { type: 'spring', stiffness: 210, damping: 21 }))
    ;[{ x: -1, y: 0 }, { x: 1, y: 0 }, { x: -0.6, y: -0.3 }].forEach((p, i) => at(900 + i * 380, () => setLook(p)))
    at(1250, () => go(bubble, 1, { duration: 0.5, ease: OUT3 }))
    const typeStart = 1500, perChar = 26
    for (let i = 1; i <= message.length; i++) at(typeStart + i * perChar, () => setTyped(i))
    const typedAt = typeStart + message.length * perChar
    // the arrow draws itself to the button; the carried button lights up as it arrives
    const arrow = typedAt + 250
    at(arrow, () => { setLook({ x: 1, y: -0.8 }); go(arrowLen, 1, { duration: 0.9, ease: SMOOTH }) })
    at(arrow + 700, () => { go(tipS, 1, { type: 'spring', stiffness: 380, damping: 26 }); go(glow, 1, { duration: 0.5, ease: OUT3 }) })
    // Nyx rides the arrow (starting ≈0.45 into the draw's tail), shrinking; the first bubble folds back
    // into its corner as Nyx leaves it; the arrow stays
    const ride = arrow + 1150
    at(ride, () => {
      go(bubble, 0, { duration: 0.35, ease: IN2 })
      const path = pathRef.current
      if (!path) return
      const L = path.getTotalLength()
      stops.current.push(animate(0, 1, {
        duration: 1.05, ease: SMOOTH,
        onUpdate: (v) => {
          const pt = path.getPointAtLength(v * L)
          nyxX.set(pt.x); nyxY.set(pt.y)
          nyxS.set(1 - (1 - 0.62) * v)
        },
      }) as any)
    })
    // hop from the tip onto the button and sit there
    const hop = ride + 1000
    at(hop, () => {
      const from = { x: geo.tip.x, y: geo.tip.y }, to = geo.perch
      stops.current.push(animate(0, 1, {
        duration: 0.5, ease: OUT3,
        onUpdate: (v) => {
          nyxX.set(from.x + (to.x - from.x) * v)
          nyxY.set(from.y + (to.y - from.y) * v - Math.sin(v * Math.PI) * 40)
          nyxS.set(0.62 + (PERCH_SCALE - 0.62) * v)
        },
      }) as any)
    })
    at(hop + 520, () => setPerched(true))
    // seated, Nyx opens a second bubble downwards and says what happens next
    const tell = hop + 700
    at(tell, () => go(bubble2, 1, { duration: 0.5, ease: OUT3 }))
    const tellType = tell + 220
    for (let i = 1; i <= message2.length; i++) at(tellType + i * 22, () => setTyped2(i))
    at(tellType + message2.length * 22 - 150, () => setShowNo(true))
    return clear
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [geo?.d])

  // "İlgilenmiyorum": the arrow retracts into the button, the bubble folds back to its corner, Nyx shrinks away, the blur lifts.
  const dismiss = useCallback(() => {
    if (leaving) return
    setLeaving(true)
    clear()
    setShowNo(false)
    go(arrowOff, 1, { duration: 0.45, ease: IN2 }); go(arrowLen, 0, { duration: 0.45, ease: IN2 }); go(tipS, 0, { duration: 0.3, ease: IN2 })
    go(bubble, 0, { duration: 0.35, ease: IN2 })
    go(bubble2, 0, { duration: 0.35, ease: IN2 })
    go(head, 0, { duration: 0.4, ease: IN2 })
    go(nyxS, 0, { duration: 0.35, ease: IN2 })
    go(glow, 0, { duration: 0.4, ease: IN2 })
    at(200, () => { go(dim, 0, { duration: 0.45, ease: OUT3 }); go(blur, 0, { duration: 0.45, ease: OUT3 }) })
    at(680, () => onDone('dismissed'))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [leaving, onDone])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') dismiss() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [dismiss])

  if (!geo || reduce) return null
  const { rect } = geo
  const shown = message.slice(0, typed)
  const bubbleW = Math.min(300, window.innerWidth - geo.bubble.x - 16)
  // second bubble: its right edge stops just left of the arrow's tip, under the button
  const tellRight = Math.min(rect.right, geo.tip.x - 36)
  const tellWidth = Math.max(200, Math.min(300, tellRight - 12))
  const tell = { left: Math.max(12, tellRight - tellWidth), width: Math.min(tellWidth, tellRight - 12) }
  return (
    <div className="fixed inset-0 z-[60]" role="dialog" aria-modal="true" aria-label={t.introDone}>
      <motion.div className="absolute inset-0" style={{ backdropFilter: backdrop, WebkitBackdropFilter: backdrop, background: bg }} />

      {/* "Analiz bitti" wipes in from below */}
      <motion.div className="pointer-events-none absolute inset-x-0 px-6 text-center" style={{ top: window.innerWidth < 640 ? Math.max(rect.bottom + 150, geo.nyx.y - 250) : Math.max(130, geo.nyx.y - 300), clipPath: headClip, y: headY }}>
        <p className="text-[13px] font-medium uppercase tracking-[0.2em] text-neutral-400">{verdict ? `${t.verdicts[verdict] || verdict}${score != null ? ` · ${score}/100` : ''}` : ''}</p>
        <p className="mt-2 text-[40px] font-semibold leading-none tracking-[-0.03em] text-white sm:text-[56px]">{t.introDone}</p>
      </motion.div>

      {/* the curling arrow: soft gradient stroke, a light running along it, a filled rounded head */}
      <svg className="pointer-events-none absolute inset-0 h-full w-full overflow-visible">
        <defs>
          <linearGradient id="nyx-arrow" gradientUnits="userSpaceOnUse" x1={geo.nyx.x} y1={geo.nyx.y} x2={geo.tip.x} y2={geo.tip.y}>
            <stop offset="0" stopColor="#8fa6c8" stopOpacity="0.15" />
            <stop offset="0.45" stopColor="#b9c7dc" stopOpacity="0.7" />
            <stop offset="1" stopColor="#f2f6fb" stopOpacity="1" />
          </linearGradient>
          <filter id="nyx-glow" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="3" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        </defs>
        <motion.path ref={pathRef} d={geo.d} fill="none" stroke="url(#nyx-arrow)" strokeWidth={2.6} strokeLinecap="round" filter="url(#nyx-glow)"
          style={{ pathLength: arrowLen, pathOffset: arrowOff }} />
        {/* a short highlight that keeps running along the drawn arrow */}
        {perched && !leaving && (
          <path d={geo.d} fill="none" stroke="#ffffff" strokeOpacity={0.85} strokeWidth={2.6} strokeLinecap="round" pathLength={1}
            strokeDasharray="0.06 0.94" className="nyx-arrow-run" />
        )}
        {/* plain SVG transform (rotation about the tip itself); framer would rotate SVG groups about their box centre */}
        <g transform={`translate(${geo.tip.x} ${geo.tip.y}) rotate(${geo.angle}) scale(${tipScale})`}>
          <path d="M 2 0 L -11 -7.5 Q -8 0 -11 7.5 Z" fill="#f2f6fb" stroke="#f2f6fb" strokeWidth={2} strokeLinejoin="round" filter="url(#nyx-glow)" />
        </g>
      </svg>

      {/* the target button, carried above the blur at its exact rect, live once Nyx sits on it */}
      <motion.div className="absolute" style={{ left: rect.left, top: rect.top, width: rect.width, height: rect.height }}>
        <motion.div className="h-full w-full rounded-full" style={{ boxShadow: ring }}>
          <Link to={href} onClick={() => onDone('perched')}
            className="flex h-full w-full items-center justify-center gap-1.5 rounded-full border border-white/20 bg-neutral-900 text-xs text-neutral-100 hover:bg-neutral-800">
            <Sparkles className="size-3.5" /> {t.nudgeCta}
          </Link>
        </motion.div>
        {perched && !leaving && <Perch onClick={() => { onDone('perched'); navigate(href) }} />}
      </motion.div>

      {/* the speech bubble: grows from Nyx's corner, a lit border turning slowly around it */}
      <motion.div className="absolute origin-bottom-left" style={{ left: geo.bubble.x, top: geo.bubble.y, width: bubbleW, y: '-100%', scale: bubble }}>
        <div className="nyx-bubble relative rounded-[18px] rounded-bl-md p-px">
          <div aria-hidden className="nyx-bubble-ring pointer-events-none absolute inset-0 rounded-[18px] rounded-bl-md" />
          <div className="relative rounded-[17px] rounded-bl-[5px] bg-neutral-950/95 px-4 py-3 shadow-[0_20px_60px_-20px_rgba(0,0,0,0.9)]">
            <p className="text-[15px] font-medium leading-relaxed text-neutral-100">
              {shown}{typed < message.length && <span className="ml-0.5 inline-block h-[1em] w-[2px] translate-y-[2px] animate-pulse bg-neutral-300" />}
            </p>
          </div>
        </div>
      </motion.div>

      {/* the second bubble: opens downwards under the perched Nyx, left of the arrow's tip */}
      <motion.div className="absolute origin-top-right" style={{ top: rect.bottom + 12, left: tell.left, width: tell.width, scale: bubble2 }}>
        <div className="nyx-bubble relative rounded-[18px] rounded-tr-md p-px">
          <div aria-hidden className="nyx-bubble-ring pointer-events-none absolute inset-0 rounded-[18px] rounded-tr-md" />
          <div className="relative rounded-[17px] rounded-tr-[5px] bg-neutral-950/95 px-4 py-3 shadow-[0_20px_60px_-20px_rgba(0,0,0,0.9)]">
            <p className="min-h-[44px] text-[14px] leading-relaxed text-neutral-100">
              {message2.slice(0, typed2)}{typed2 > 0 && typed2 < message2.length && <span className="ml-0.5 inline-block h-[1em] w-[2px] translate-y-[2px] animate-pulse bg-neutral-300" />}
            </p>
          </div>
        </div>
        {showNo && (
          <motion.button type="button" initial={{ clipPath: 'inset(0 100% 0 0)' }} animate={{ clipPath: 'inset(0 0% 0 0)' }} transition={{ duration: 0.45, ease: OUT3 }}
            onClick={dismiss} className="mt-2 block rounded-full px-3 py-1.5 text-[12.5px] text-neutral-400 hover:bg-white/[0.06] hover:text-neutral-100">{t.nudgeNo}</motion.button>
        )}
      </motion.div>

      {/* Nyx (centred on its point with framer's own x/y) — it rides the arrow, then sits on the button */}
      {!perched && (
        <motion.div className="pointer-events-none absolute left-0 top-0" style={{ x: nyxX, y: nyxY }}>
          <motion.div style={{ x: '-50%', y: '-50%', scale: nyxS }}>
            <AiAvatar size="md" look={look} label="Nyx" />
          </motion.div>
        </motion.div>
      )}
    </div>
  )
}
