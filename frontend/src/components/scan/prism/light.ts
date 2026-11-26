// Paints the traced light into an offscreen canvas (additive), then blooms it into the canvas the
// glass samples. Everything is soft: the composite has no unblurred pass.
import { PALETTE, WAVES, edgeOf, type Path, type Tri, type V2 } from './optics'

export type Mote = { t: number; off: number; speed: number; phase: number; r: number }
export const makeMotes = (n = 70): Mote[] =>
  Array.from({ length: n }, () => ({ t: Math.random(), off: Math.random() * 2 - 1, speed: 0.02 + Math.random() * 0.05, phase: Math.random() * Math.PI * 2, r: 0.5 + Math.random() * 1.1 }))

const rgba = (c: [number, number, number], a: number) => `rgba(${c[0]},${c[1]},${c[2]},${Math.max(0, Math.min(1, a))})`

function fadeGradient(ctx: CanvasRenderingContext2D, a: V2, b: V2, rgb: [number, number, number], alpha: number) {
  const g = ctx.createLinearGradient(a[0], a[1], b[0], b[1])
  g.addColorStop(0, rgba(rgb, alpha))
  g.addColorStop(0.3, rgba(rgb, alpha * 0.75))
  g.addColorStop(0.7, rgba(rgb, alpha * 0.25))
  g.addColorStop(1, rgba(rgb, 0))
  return g
}

export function paintLight(opts: {
  ctx: CanvasRenderingContext2D
  waves: Path[][]
  tri: Tri
  src: V2
  entry: V2
  motes: Mote[]
  time: number
  scale: number // device px per CSS px
  mobile: boolean
  map: (p: V2) => V2 // plane point (CSS px) -> canvas point (device px)
}) {
  const { ctx, waves, tri, src, entry, motes, time, scale, mobile, map } = opts
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  ctx.lineCap = 'round'
  ctx.lineJoin = 'round'

  // incoming white beam
  const A = map(src), B = map(entry)
  const k = mobile ? 0.8 : 1
  ctx.strokeStyle = 'rgba(255,255,255,0.3)'; ctx.lineWidth = 12 * k * scale
  ctx.beginPath(); ctx.moveTo(A[0], A[1]); ctx.lineTo(B[0], B[1]); ctx.stroke()
  ctx.strokeStyle = 'rgba(255,255,255,1)'; ctx.lineWidth = 4.5 * k * scale
  ctx.beginPath(); ctx.moveTo(A[0], A[1]); ctx.lineTo(B[0], B[1]); ctx.stroke()

  // dust drifting along the beam, spread wider away from the prism
  const dx = src[0] - entry[0], dy = src[1] - entry[1]
  const len = Math.hypot(dx, dy) || 1
  const px = -dy / len, py = dx / len
  for (const m of motes) {
    const along = m.t * Math.min(len, 900)
    const spread = 4 + m.t * 70
    const p = map([entry[0] + (dx / len) * along + px * m.off * spread, entry[1] + (dy / len) * along + py * m.off * spread])
    const a = (0.3 + 0.7 * (0.5 + 0.5 * Math.sin(time * 2.2 + m.phase))) * 0.75
    ctx.fillStyle = `rgba(255,255,255,${a})`
    ctx.beginPath(); ctx.arc(p[0], p[1], m.r * scale, 0, Math.PI * 2); ctx.fill()
  }

  // group every wavelength's segments by path key
  const groups = new Map<string, (Path | undefined)[]>()
  waves.forEach((paths, wi) => {
    for (const p of paths) {
      let g = groups.get(p.key)
      if (!g) { g = new Array(WAVES); groups.set(p.key, g) }
      if (!g[wi]) g[wi] = p
    }
  })

  for (const g of groups.values()) {
    const maxSeg = g.reduce((m, p) => Math.max(m, p ? p.segs.length : 0), 0)
    for (let j = 1; j < maxSeg; j++) {
      // bands between neighbouring wavelengths
      for (let i = 0; i < WAVES - 1; i++) {
        const s0 = g[i]?.segs[j], s1 = g[i + 1]?.segs[j]
        if (!s0 || !s1) continue
        const a0 = map(s0.a), b0 = map(s0.b), a1 = map(s1.a), b1 = map(s1.b)
        const e = (s0.e + s1.e) / 2
        const alpha = e * (s0.inside ? 0.5 : 0.78)
        const c = PALETTE[i].vivid
        ctx.fillStyle = s0.out ? fadeGradient(ctx, a0, b0, c, alpha) : rgba(c, alpha)
        ctx.beginPath(); ctx.moveTo(a0[0], a0[1]); ctx.lineTo(b0[0], b0[1]); ctx.lineTo(b1[0], b1[1]); ctx.lineTo(a1[0], a1[1]); ctx.closePath(); ctx.fill()
      }
      // white-balanced core lines
      for (let i = 0; i < WAVES; i++) {
        const s = g[i]?.segs[j]
        if (!s) continue
        const a = map(s.a), b = map(s.b)
        const pal = PALETTE[i]
        const alpha = pal.weight * s.e * 2.2
        ctx.strokeStyle = s.out ? fadeGradient(ctx, a, b, pal.core, alpha) : rgba(pal.core, alpha)
        ctx.lineWidth = (s.inside ? 4 : 3.4) * scale
        ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke()
      }
    }
  }

  // glints where the beam crosses a face (middle wavelength only)
  const mid = waves[WAVES >> 1] || []
  const seen = new Set<string>()
  for (const p of mid) {
    for (const s of p.segs) {
      if (s.out) continue
      const pt = s.b
      const key = `${Math.round(pt[0])},${Math.round(pt[1])}`
      if (seen.has(key)) continue
      seen.add(key)
      let face = 0, best = Infinity
      for (let f = 0; f < 3; f++) {
        const [u, v] = edgeOf(tri, f)
        const ex = v[0] - u[0], ey = v[1] - u[1]
        const tt = Math.max(0, Math.min(1, ((pt[0] - u[0]) * ex + (pt[1] - u[1]) * ey) / (ex * ex + ey * ey)))
        const d = Math.hypot(u[0] + ex * tt - pt[0], u[1] + ey * tt - pt[1])
        if (d < best) { best = d; face = f }
      }
      const [u, v] = edgeOf(tri, face)
      const c = map(pt), U = map(u), Vv = map(v)
      const rg = ctx.createRadialGradient(c[0], c[1], 0, c[0], c[1], 0.2 * tri.S * scale)
      rg.addColorStop(0, 'rgba(255,255,255,0.9)')
      rg.addColorStop(1, 'rgba(255,255,255,0)')
      ctx.strokeStyle = rg; ctx.lineWidth = 2 * scale
      ctx.beginPath(); ctx.moveTo(U[0], U[1]); ctx.lineTo(Vv[0], Vv[1]); ctx.stroke()
      ctx.fillStyle = '#fff'
      ctx.beginPath(); ctx.arc(c[0], c[1], 2.6 * scale, 0, Math.PI * 2); ctx.fill()
    }
  }
  ctx.restore()
}

// Canvas filters are missing in some browsers (older Safari); detect once.
let filterOk: boolean | null = null
const canFilter = (ctx: CanvasRenderingContext2D) => {
  if (filterOk === null) { ctx.filter = 'blur(2px)'; filterOk = ctx.filter === 'blur(2px)'; ctx.filter = 'none' }
  return filterOk
}
const smalls: HTMLCanvasElement[] = []

/** Soft bloom of `src` into `dst`: three blurred passes, no sharp one. */
export function bloom(dst: CanvasRenderingContext2D, src: HTMLCanvasElement, scale: number) {
  const W = dst.canvas.width, H = dst.canvas.height
  dst.clearRect(0, 0, W, H)
  dst.globalCompositeOperation = 'lighter'
  const passes: [number, number, number][] = [[34, 0.6, 16], [12, 0.9, 6], [3.2, 1, 2]]
  if (canFilter(dst)) {
    for (const [r, a] of passes) { dst.filter = `blur(${r * scale}px)`; dst.globalAlpha = a; dst.drawImage(src, 0, 0) }
    dst.filter = 'none'
  } else {
    passes.forEach(([, a, div], i) => {
      const c = (smalls[i] ||= document.createElement('canvas'))
      const w = Math.max(1, Math.round(W / div)), h = Math.max(1, Math.round(H / div))
      if (c.width !== w || c.height !== h) { c.width = w; c.height = h }
      const cx = c.getContext('2d')!
      cx.clearRect(0, 0, w, h)
      cx.imageSmoothingEnabled = true
      cx.drawImage(src, 0, 0, w, h)
      dst.imageSmoothingEnabled = true
      dst.globalAlpha = a
      dst.drawImage(c, 0, 0, W, H)
    })
  }
  dst.globalAlpha = 1
  dst.globalCompositeOperation = 'source-over'
}
