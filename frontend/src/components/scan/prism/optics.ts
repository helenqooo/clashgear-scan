// 2D spectral ray tracing on the plane through the middle of the glass prism (y points down, CSS px).
// Cauchy dispersion, vector Snell refraction, unpolarised Fresnel split and total internal
// reflection; rays are grouped by their path so neighbouring wavelengths can be filled as a band.

export type V2 = [number, number]
export type Tri = { pts: [V2, V2, V2]; normals: [V2, V2, V2]; S: number; cx: number; cy: number }
export type Seg = { a: V2; b: V2; e: number; inside: boolean; out: boolean }
export type Path = { key: string; segs: Seg[] }

export const WAVES = 72
const LMIN = 410, LMAX = 695

const sub = (a: V2, b: V2): V2 => [a[0] - b[0], a[1] - b[1]]
const dot = (a: V2, b: V2) => a[0] * b[0] + a[1] * b[1]
const add = (a: V2, b: V2, k = 1): V2 => [a[0] + b[0] * k, a[1] + b[1] * k]
const norm = (a: V2): V2 => { const l = Math.hypot(a[0], a[1]) || 1; return [a[0] / l, a[1] / l] }

export const lambdaAt = (i: number) => LMIN + ((LMAX - LMIN) * i) / (WAVES - 1)
// Cauchy: n(λ) = 1.2 + 0.1/λ² with λ in µm.
export const iorAt = (nm: number) => 1.2 + 0.1 / (nm / 1000) ** 2

// Piecewise visible-spectrum approximation, 0..1 per channel.
function spectrum(nm: number): [number, number, number] {
  let r = 0, g = 0, b = 0
  if (nm < 440) { r = -(nm - 440) / 60; b = 1 }
  else if (nm < 490) { g = (nm - 440) / 50; b = 1 }
  else if (nm < 510) { g = 1; b = -(nm - 510) / 20 }
  else if (nm < 580) { r = (nm - 510) / 70; g = 1 }
  else if (nm < 645) { r = 1; g = -(nm - 645) / 65 }
  else r = 1
  // fade at the ends of the visible range
  const f = nm < 420 ? 0.3 + (0.7 * (nm - 380)) / 40 : nm > 680 ? 0.3 + (0.7 * (700 - nm)) / 20 : 1
  return [Math.max(0, r * f), Math.max(0, g * f), Math.max(0, b * f)]
}

/** vivid colour for band fills, and a white-balanced colour + weight for core lines (all lines sum to white). */
export const PALETTE = (() => {
  const raw = Array.from({ length: WAVES }, (_, i) => spectrum(lambdaAt(i)))
  const sum = raw.reduce((s, c) => [s[0] + c[0], s[1] + c[1], s[2] + c[2]], [0, 0, 0])
  return raw.map((c) => {
    const wb: [number, number, number] = [c[0] / sum[0], c[1] / sum[1], c[2] / sum[2]]
    const w = Math.max(wb[0], wb[1], wb[2]) || 1e-6
    return {
      vivid: c.map((x) => Math.round(Math.min(1, x * 1.15) * 255)) as [number, number, number],
      core: wb.map((x) => Math.round((x / w) * 255)) as [number, number, number],
      weight: w,
    }
  })
})()

export function makeTriangle(cx: number, cy: number, S: number): Tri {
  const R = S / Math.sqrt(3)
  const top: V2 = [cx, cy - R], right: V2 = [cx + S / 2, cy + R / 2], left: V2 = [cx - S / 2, cy + R / 2]
  const pts: [V2, V2, V2] = [top, right, left]
  const edges: [V2, V2][] = [[top, right], [right, left], [left, top]]
  const normals = edges.map(([a, b]) => {
    const d = sub(b, a)
    let n: V2 = norm([d[1], -d[0]])
    const mid: V2 = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2]
    if (dot(n, sub(mid, [cx, cy])) < 0) n = [-n[0], -n[1]]
    return n
  }) as [V2, V2, V2]
  return { pts, normals, S, cx, cy }
}

export const edgeOf = (t: Tri, k: number): [V2, V2] => [t.pts[k], t.pts[(k + 1) % 3]]

function hit(t: Tri, o: V2, d: V2, skip: number): { k: number; s: number; p: V2 } | null {
  let best: { k: number; s: number; p: V2 } | null = null
  for (let k = 0; k < 3; k++) {
    if (k === skip) continue
    const [a, b] = edgeOf(t, k)
    const e = sub(b, a)
    const den = d[0] * e[1] - d[1] * e[0]
    if (Math.abs(den) < 1e-9) continue
    const w = sub(a, o)
    const s = (w[0] * e[1] - w[1] * e[0]) / den
    const u = (w[0] * d[1] - w[1] * d[0]) / den
    if (s > 1e-4 && u >= 0 && u <= 1 && (!best || s < best.s)) best = { k, s, p: add(o, d, s) }
  }
  return best
}

/** Traces one wavelength; returns its paths keyed by the sequence of interactions. */
export function traceWave(t: Tri, src: V2, dir: V2, n: number, far: number): Path[] {
  const out: Path[] = []
  const go = (o: V2, d: V2, e: number, inside: boolean, key: string, segs: Seg[], skip: number, depth: number) => {
    const h = hit(t, o, d, skip)
    if (!h) { out.push({ key: key || 'miss', segs: [...segs, { a: o, b: add(o, d, far), e, inside, out: true }] }); return }
    const seg: Seg = { a: o, b: h.p, e, inside, out: false }
    const path = [...segs, seg]
    if (depth >= 7) { out.push({ key, segs: path }); return }
    const nOut = t.normals[h.k]
    const nf: V2 = inside ? [-nOut[0], -nOut[1]] : nOut // faces the incoming ray
    const n1 = inside ? n : 1, n2 = inside ? 1 : n
    const eta = n1 / n2
    const cosi = -dot(nf, d)
    const sin2t = eta * eta * (1 - cosi * cosi)
    const refl = norm(add(d, nf, 2 * cosi))
    if (sin2t > 1) { // total internal reflection
      go(h.p, refl, e, inside, `${key}R${h.k}`, path, h.k, depth + 1)
      return
    }
    const cost = Math.sqrt(1 - sin2t)
    const tr = norm(add([d[0] * eta, d[1] * eta], nf, eta * cosi - cost))
    const rs = ((n1 * cosi - n2 * cost) / (n1 * cosi + n2 * cost)) ** 2
    const rp = ((n1 * cost - n2 * cosi) / (n1 * cost + n2 * cosi)) ** 2
    const R = (rs + rp) / 2
    if (e * (1 - R) > 0.08) go(h.p, tr, e * (1 - R), !inside, `${key}T${h.k}`, path, h.k, depth + 1)
    if (e * R > 0.12) go(h.p, refl, e * R, inside, `${key}R${h.k}`, path, h.k, depth + 1)
  }
  go(src, dir, 1, false, '', [], -1, 0)
  return out
}

/** Lamp from the right: incidence from pointer height, entry point along the right face from pointer x. */
export function lamp(t: Tri, ax: number, ay: number, far: number): { src: V2; dir: V2; entry: V2 } {
  const inc = ay < 0.5 ? -35 + (60 + 35) * (ay / 0.5) : 60 + 15 * ((ay - 0.5) / 0.5)
  const a = (inc * Math.PI) / 180
  const inward: V2 = [-t.normals[0][0], -t.normals[0][1]]
  const dir: V2 = norm([inward[0] * Math.cos(a) - inward[1] * Math.sin(a), inward[0] * Math.sin(a) + inward[1] * Math.cos(a)])
  const [p, q] = edgeOf(t, 0)
  const k = 0.08 + 0.84 * ax
  const entry: V2 = [p[0] + (q[0] - p[0]) * k, p[1] + (q[1] - p[1]) * k]
  return { src: add(entry, dir, -far), dir, entry }
}
