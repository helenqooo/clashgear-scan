// Interactive glass prism: a white beam comes in from the right, refracts through a real-time 3D
// glass prism and fans out into a soft rainbow; the mouse steers the light and tilts the view.
// The metaphor for the page: one file goes in, ten layers come out.
// Interaction model after vercel-labs/vgpu (MIT, Copyright (c) Vercel, Inc.) interaction.ts.
import { useEffect, useRef } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { MousePointer2 } from 'lucide-react'
import { useScan } from '@/i18n/scan'
import { WAVES, iorAt, lambdaAt, lamp, makeTriangle, traceWave, edgeOf, type Path } from './prism/optics'
import { bloom, makeMotes, paintLight } from './prism/light'
import { createGlass, webgl2Available, type GlassLayout } from './prism/glass'

const BG: [number, number, number] = [16 / 255, 16 / 255, 16 / 255] // page background, so the section is seamless

export function PrismSection() {
  const { t } = useScan()
  const p = t.prism
  const reduce = useReducedMotion()
  const stageRef = useRef<HTMLDivElement>(null)
  const glRef = useRef<HTMLCanvasElement>(null)
  const fxRef = useRef<HTMLCanvasElement>(null)
  const copyRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const stage = stageRef.current!, glCanvas = glRef.current!, fx = fxRef.current!, copy = copyRef.current!
    const fxCtx = fx.getContext('2d')!
    const light = document.createElement('canvas')
    const lightCtx = light.getContext('2d')!
    const has3d = webgl2Available()
    const glass = has3d ? createGlass(glCanvas, fx, BG) : null
    fx.style.display = has3d ? 'none' : 'block'
    glCanvas.style.display = has3d ? 'block' : 'none'

    const motes = makeMotes(70)
    let layout: GlassLayout & { mobile: boolean; ldpr: number } = { W: 1, H: 1, dpr: 1, cx: 0, cy: 0, S: 100, mobile: false, ldpr: 1 }

    const computeLayout = () => {
      const r = stage.getBoundingClientRect()
      const W = Math.max(1, r.width), H = Math.max(1, r.height)
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5) // glass is soft; 1.5× keeps it light on retina
      const mobile = W < 820
      let S: number, cx: number, cy: number
      if (!mobile) { S = Math.min(W * 0.36, H * 0.62); cx = W * 0.66; cy = H * 0.53 }
      else {
        const copyBottom = copy.getBoundingClientRect().bottom - r.top
        S = Math.min(W * 0.72, H * 0.4, 400); cx = W / 2
        cy = Math.max(copyBottom + 30 + S * 0.62, (copyBottom + 30 + H) / 2)
      }
      // The light is fully blurred before anyone sees it, so half resolution looks the same and costs a quarter.
      const ldpr = (mobile ? Math.min(dpr, 1.5) : dpr) * 0.5
      layout = { W, H, dpr, cx, cy, S, mobile, ldpr }
      for (const c of [light, fx]) { c.width = Math.round(W * ldpr); c.height = Math.round(H * ldpr) }
      glass?.resize(layout)
    }

    // pointer -> aim (lamp) and orbit (camera), eased per 60 Hz frame
    const aim = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 }
    const orbit = { x: 0, y: 0, tx: 0, ty: 0 }
    let lastMove = -Infinity
    const wander = { x: 0, y: 0, tilt: 0, pitch: 0, next: 0 } // idle target offset (px) and tilt
    const float = { x: 0, y: 0, bob: 0 } // eased offset actually applied
    const onPointer = (cx: number, cy: number) => {
      const r = stage.getBoundingClientRect()
      const nx = Math.min(1, Math.max(0, (cx - r.left) / r.width)), ny = Math.min(1, Math.max(0, (cy - r.top) / r.height))
      aim.tx = nx; aim.ty = ny
      if (!layout.mobile) { orbit.tx = nx * 2 - 1; orbit.ty = ny * 2 - 1 }
      lastMove = performance.now()
    }
    const onMove = (e: PointerEvent) => { if (e.isPrimary) onPointer(e.clientX, e.clientY) }
    const onDown = (e: PointerEvent) => onPointer(e.clientX, e.clientY)
    const onTouch = (e: TouchEvent) => { const tch = e.touches[0]; if (tch) onPointer(tch.clientX, tch.clientY) }
    const onLeave = () => { orbit.tx = 0; orbit.ty = 0 }
    window.addEventListener('pointermove', onMove, { passive: true })
    window.addEventListener('pointerdown', onDown, { passive: true })
    window.addEventListener('touchmove', onTouch, { passive: true })
    document.documentElement.addEventListener('pointerleave', onLeave)

    let raf = 0, last = performance.now(), visible = true, inView = false
    const frame = (now: number) => {
      raf = 0
      const dt = Math.min(0.1, (now - last) / 1000)
      last = now
      const L = layout
      // idle (no pointer for 4 s) or phone: the light stays put and the prism itself floats,
      // drifting to a new random spot every few seconds with a slow tilt and a gentle bob, as if it
      // hung in the air (never with reduced motion). A pointer move brings it back home.
      const idle = !reduce && (L.mobile || now - lastMove > 4000)
      if (idle) {
        if (now >= wander.next) {
          wander.x = (Math.random() * 2 - 1) * L.S * 0.07
          wander.y = (Math.random() * 2 - 1) * L.S * 0.08
          wander.tilt = (Math.random() * 2 - 1) * 0.8
          wander.pitch = (Math.random() * 2 - 1) * 0.6
          wander.next = now + 2600 + Math.random() * 2600
        }
        if (!L.mobile) { orbit.tx = wander.tilt; orbit.ty = wander.pitch }
      } else { wander.next = 0; wander.x = 0; wander.y = 0 }
      const kf = 1 - Math.pow(1 - 0.02, dt * 60)
      float.x += (wander.x - float.x) * kf; float.y += (wander.y - float.y) * kf
      float.bob += ((idle ? 1 : 0) - float.bob) * kf
      const kl = 1 - Math.pow(1 - 0.12, dt * 60), kc = 1 - Math.pow(1 - (idle ? 0.02 : 0.08), dt * 60)
      aim.x += (aim.tx - aim.x) * kl; aim.y += (aim.ty - aim.y) * kl
      orbit.x += (orbit.tx - orbit.x) * kc; orbit.y += (orbit.ty - orbit.y) * kc

      const px = L.cx + float.x
      const py = L.cy + float.y + Math.sin(now / 1000 * 1.15) * L.S * 0.014 * float.bob
      glass?.place(px, py)
      glass?.aim(orbit.x, orbit.y)
      const tri = makeTriangle(px, py, L.S)
      const far = 1.5 * Math.hypot(L.W, L.H)
      const { src, dir, entry } = lamp(tri, aim.x, aim.y, far)
      const waves: Path[][] = []
      for (let i = 0; i < WAVES; i++) waves.push(traceWave(tri, src, dir, iorAt(lambdaAt(i)), far))

      for (const m of motes) { m.t -= m.speed * dt * 0.25; if (m.t < 0) { m.t += 1; m.off = Math.random() * 2 - 1 } }
      const s = L.ldpr
      const map = glass ? (q: [number, number]): [number, number] => { const v = glass.project(q[0], q[1]); return [v[0] * s, v[1] * s] } : (q: [number, number]): [number, number] => [q[0] * s, q[1] * s]
      lightCtx.clearRect(0, 0, light.width, light.height)
      paintLight({ ctx: lightCtx, waves, tri, src, entry, motes, time: now / 1000, scale: s, mobile: L.mobile, map })
      bloom(fxCtx, light, s)
      if (glass) glass.render()
      else {
        // 2D fallback: a thin outline where the glass would be
        fxCtx.strokeStyle = 'rgba(255,255,255,0.35)'; fxCtx.lineWidth = 1 * s
        fxCtx.beginPath()
        for (let k = 0; k < 3; k++) { const [a] = edgeOf(tri, k); const m = map(a); if (k === 0) fxCtx.moveTo(m[0], m[1]); else fxCtx.lineTo(m[0], m[1]) }
        fxCtx.closePath(); fxCtx.stroke()
      }
      if (visible && inView) raf = requestAnimationFrame(frame)
    }
    const kick = () => { if (!raf && visible && inView) { last = performance.now(); raf = requestAnimationFrame(frame) } }

    let rt = 0
    const onResize = () => { clearTimeout(rt); rt = window.setTimeout(() => { computeLayout(); kick() }, 60) }
    window.addEventListener('resize', onResize)
    const io = new IntersectionObserver(([e]) => { inView = !!e?.isIntersecting; kick() }, { rootMargin: '120px' })
    io.observe(stage)
    const onVis = () => { visible = document.visibilityState === 'visible'; kick() }
    document.addEventListener('visibilitychange', onVis)
    computeLayout()
    document.fonts?.ready.then(() => { computeLayout(); kick() }).catch(() => {})
    kick()

    return () => {
      cancelAnimationFrame(raf)
      clearTimeout(rt)
      io.disconnect()
      window.removeEventListener('resize', onResize)
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerdown', onDown)
      window.removeEventListener('touchmove', onTouch)
      document.documentElement.removeEventListener('pointerleave', onLeave)
      document.removeEventListener('visibilitychange', onVis)
      glass?.dispose()
    }
  }, [reduce])

  return (
    <section id="prism" aria-label={p.title} className="relative isolate overflow-hidden bg-[#101010] max-[819px]:min-h-[max(100svh,720px)] min-[820px]:min-h-[100svh]">
      <div ref={stageRef} aria-hidden className="absolute inset-0 -z-10 touch-pan-y">
        <canvas ref={glRef} className="absolute inset-0 block h-full w-full" />
        <canvas ref={fxRef} className="absolute inset-0 block h-full w-full mix-blend-screen" />
      </div>
      <div className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-[#101010] to-transparent" />
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-[#101010] to-transparent" />
      <div className="pointer-events-none mx-auto flex max-w-6xl flex-col px-5 max-[819px]:pt-20 min-[820px]:min-h-[100svh] min-[820px]:justify-center">
        <motion.div ref={copyRef} initial={{ opacity: 0, y: 14, filter: 'blur(8px)' }} whileInView={{ opacity: 1, y: 0, filter: 'blur(0px)' }} viewport={{ once: true, margin: '-20% 0px' }}
          transition={{ type: 'spring', bounce: 0, duration: 0.7 }}
          // Difference blending makes the copy adapt to the light behind it: white on the dark room,
          // the inverse colour (and so always contrasting) where the rainbow crosses the text.
          className="pointer-events-auto max-w-md mix-blend-difference">
          <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-neutral-300">{p.kicker}</p>
          <h2 className="mt-3 whitespace-pre-line text-4xl font-semibold leading-[1.08] tracking-[-0.03em] text-white sm:text-5xl">{p.title}</h2>
          <p className="mt-5 text-[15px] font-medium leading-relaxed text-neutral-200">{p.body}</p>
          <p className="mt-6 inline-flex items-center gap-2 rounded-full border border-white/40 px-3 py-1 text-xs text-neutral-200">
            <MousePointer2 className="size-3.5 shrink-0" /> {p.hint}
          </p>
        </motion.div>
      </div>
    </section>
  )
}
