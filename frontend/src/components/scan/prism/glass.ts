// The 3D glass prism. Approach and constants ported from vercel-labs/vgpu (MIT License,
// Copyright (c) Vercel, Inc.), apps/docs/app/[lang]/(home)/components/prism-background:
// a filleted triangular prism, five ideal planes for refraction, an analytic studio environment,
// back faces into a half-float target, then front faces that refract into that target.
import * as THREE from 'three'
import { mergeVertices } from 'three/examples/jsm/utils/BufferGeometryUtils.js'

const GLSL_COMMON = /* glsl */ `
vec3 srgbToLinear(vec3 c) { return mix(c / 12.92, pow((c + 0.055) / 1.055, vec3(2.4)), step(0.04045, c)); }
vec3 linearToSrgb(vec3 c) { c = max(c, 0.0); return mix(c * 12.92, 1.055 * pow(c, vec3(1.0 / 2.4)) - 0.055, step(0.0031308, c)); }
float lum(vec3 c) { return dot(c, vec3(0.2126, 0.7152, 0.0722)); }
float panel(vec3 d, vec3 c, vec2 size, float feather) {
  float k = dot(d, c);
  if (k <= 0.0) return 0.0;
  vec3 t = normalize(cross(abs(c.y) > 0.9 ? vec3(1.0, 0.0, 0.0) : vec3(0.0, 1.0, 0.0), c));
  vec3 b = cross(c, t);
  vec2 uv = vec2(dot(d, t), dot(d, b)) / k;
  vec2 q = abs(uv) - size * 0.5;
  float dist = max(q.x, q.y);
  return 1.0 - smoothstep(-feather, feather, dist);
}
// Analytic studio (after vgpu environment.wgsl): dark room, darker back wall, lighter floor, three softboxes.
vec3 studio(vec3 d) {
  d = normalize(d);
  vec3 c = vec3(0.010);
  c = mix(c, vec3(0.016), smoothstep(0.0, -0.6, d.y));
  c *= mix(1.0, 0.6, smoothstep(0.0, -1.0, d.z));
  c += panel(d, normalize(vec3(-0.82, 0.08, 0.57)), vec2(1.35, 1.1), 0.22) * vec3(0.82, 0.84, 0.88) * 0.011;
  c += panel(d, normalize(vec3(0.0, -0.707, 0.707)), vec2(0.38, 0.62), 0.18) * vec3(1.0, 0.97, 0.91) * 0.22;
  c += panel(d, normalize(vec3(0.612, 0.354, 0.707)), vec2(0.5, 0.16), 0.035) * vec3(0.76, 0.88, 1.0) * 20.0;
  c = c / (1.0 + c);
  c = pow(c, vec3(1.0 / 2.2));
  return srgbToLinear(c) * 2.3;
}
`

const GLSL_PLANES = /* glsl */ `
uniform vec4 uPlanes[5]; // xyz outward normal, w offset
float exitPlane(vec3 p, vec3 dir, int skip, out int which) {
  float best = 1e9; which = -1;
  for (int i = 0; i < 5; i++) {
    if (i == skip) continue;
    float den = dot(uPlanes[i].xyz, dir);
    if (den > 1e-4) {
      float t = (uPlanes[i].w - dot(uPlanes[i].xyz, p)) / den;
      if (t > 0.01 && t < best) { best = t; which = i; }
    }
  }
  return best;
}
`

const VERT = /* glsl */ `
varying vec3 vWorld;
varying vec3 vNormal;
void main() {
  vec4 w = modelMatrix * vec4(position, 1.0);
  vWorld = w.xyz;
  vNormal = normalize(mat3(modelMatrix) * normal);
  gl_Position = projectionMatrix * viewMatrix * w;
}`

const BACK_FRAG = /* glsl */ `
uniform float uIor;
uniform float uF0;
uniform float uRefl;
varying vec3 vWorld;
varying vec3 vNormal;
${GLSL_COMMON}
${GLSL_PLANES}
void main() {
  vec3 V = normalize(vWorld - cameraPosition);
  vec3 N = normalize(vNormal);           // outward
  vec3 dir = V;
  vec3 p = vWorld;
  vec3 nIn = -N;                         // faces the ray coming from inside
  int skip = -1;
  float w = 1.0;
  vec3 col = vec3(0.0);
  bool escaped = false;
  for (int b = 0; b < 3; b++) {
    vec3 t = refract(dir, nIn, uIor);
    float cosi = clamp(dot(-dir, nIn), 0.0, 1.0);
    float F = uF0 + (1.0 - uF0) * pow(1.0 - cosi, 5.0);
    if (dot(t, t) > 0.0) {
      // leaves the glass: the studio seen through it, plus the inner reflection's escape
      col += studio(t) * (1.0 - F);
      w = F;
      escaped = true;
      break;
    }
    dir = reflect(dir, nIn);              // total internal reflection
    int which;
    float d = exitPlane(p, dir, skip, which);
    if (which < 0) break;
    p += dir * d;
    nIn = -uPlanes[which].xyz;
    skip = which;
  }
  float weight = escaped ? w : 1.0;
  gl_FragColor = vec4(col * uRefl * weight, weight * 0.5);
}`

const FRONT_FRAG = /* glsl */ `
uniform sampler2D tScene;
uniform mat4 uViewProj;
uniform float uIor;
uniform float uF0;
uniform float uRefl;
uniform vec3 uAbsorb;
varying vec3 vWorld;
varying vec3 vNormal;
${GLSL_COMMON}
${GLSL_PLANES}
void main() {
  vec3 V = normalize(vWorld - cameraPosition);
  vec3 N = normalize(vNormal);
  float facing = clamp(dot(-V, N), 0.0, 1.0);
  float F = uF0 + (1.0 - uF0) * pow(1.0 - facing, 5.0);
  vec3 env = studio(reflect(V, N));
  vec3 T = refract(V, N, 1.0 / uIor);
  if (dot(T, T) == 0.0) T = reflect(V, N);
  int which;
  float dist = exitPlane(vWorld, T, -1, which);
  if (which < 0) dist = 0.0;
  vec3 exitP = vWorld + T * dist;
  vec4 clip = uViewProj * vec4(exitP, 1.0);
  vec2 uv = clip.xy / clip.w * 0.5 + 0.5;
  vec3 trans = texture2D(tScene, clamp(uv, 0.001, 0.999)).rgb * exp(-uAbsorb * dist);
  vec3 col = trans * (1.0 - F) + env * uRefl * F;
  col += smoothstep(0.5, 0.82, lum(env)) * clamp(uRefl * 0.4, 0.0, 0.7) * (0.65 + 0.35 * pow(1.0 - facing, 1.5));
  vec3 over = max(col - 0.8, 0.0);
  col = min(col, 0.8) + over / (1.0 + over * 5.0);   // soft shoulder
  gl_FragColor = vec4(linearToSrgb(col), 1.0);
}`

const QUAD_VERT = /* glsl */ `varying vec2 vUv; void main() { vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }`
const BG_FRAG = /* glsl */ `
uniform sampler2D tLight; uniform vec3 uBg; varying vec2 vUv;
${GLSL_COMMON}
void main() {
  vec4 L = texture2D(tLight, vUv);
  vec3 s = 1.0 - (1.0 - uBg) * (1.0 - L.rgb * L.a);
  gl_FragColor = vec4(srgbToLinear(s), 1.0);
}`
const COPY_FRAG = /* glsl */ `
uniform sampler2D tScene; varying vec2 vUv;
${GLSL_COMMON}
void main() { gl_FragColor = vec4(linearToSrgb(texture2D(tScene, vUv).rgb), 1.0); }`

/** Filleted triangular prism, apex up, centred, z ∈ [-depth/2, depth/2]. */
function prismGeometry(S: number) {
  const depth = (S * 0.3) / 0.57
  const fillet = Math.max(1.5, (S * 0.008) / 0.57)
  const r = S / (2 * Math.sqrt(3)) - fillet // inradius of the inner contour; the bevel grows it back
  const R = 2 * r
  const corners = [0, 1, 2].map((i) => { const a = Math.PI / 2 + (i * 2 * Math.PI) / 3; return new THREE.Vector2(Math.cos(a) * R, Math.sin(a) * R) })
  const cr = fillet * 2 // corner rounding of the contour
  const shape = new THREE.Shape()
  corners.forEach((c, i) => {
    const prev = corners[(i + 2) % 3], next = corners[(i + 1) % 3]
    const a = c.clone().add(prev.clone().sub(c).setLength(cr * 1.7))
    const b = c.clone().add(next.clone().sub(c).setLength(cr * 1.7))
    if (i === 0) shape.moveTo(a.x, a.y)
    else shape.lineTo(a.x, a.y)
    shape.quadraticCurveTo(c.x, c.y, b.x, b.y)
  })
  shape.closePath()
  let geo: THREE.BufferGeometry = new THREE.ExtrudeGeometry(shape, {
    depth: depth - 2 * fillet, bevelEnabled: true, bevelThickness: fillet, bevelSize: fillet, bevelSegments: 4, curveSegments: 4, steps: 1,
  })
  geo.translate(0, 0, -(depth - 2 * fillet) / 2)
  geo.deleteAttribute('normal')
  geo.deleteAttribute('uv')
  geo = mergeVertices(geo, 1e-3)
  geo.computeVertexNormals()
  // Ideal planes (outward normal, offset): right, base, left sides, then front and back caps.
  const inr = S / (2 * Math.sqrt(3))
  const c30 = Math.cos(Math.PI / 6), s30 = Math.sin(Math.PI / 6)
  const planes = [
    new THREE.Vector4(c30, s30, 0, inr),
    new THREE.Vector4(0, -1, 0, inr),
    new THREE.Vector4(-c30, s30, 0, inr),
    new THREE.Vector4(0, 0, 1, depth / 2),
    new THREE.Vector4(0, 0, -1, depth / 2),
  ]
  return { geo, planes, depth }
}

export type GlassLayout = { W: number; H: number; dpr: number; cx: number; cy: number; S: number }

export function createGlass(canvas: HTMLCanvasElement, lightCanvas: HTMLCanvasElement, bg: [number, number, number]) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false, powerPreference: 'high-performance' })
  renderer.autoClear = false
  renderer.outputColorSpace = THREE.LinearSRGBColorSpace
  renderer.toneMapping = THREE.NoToneMapping

  const camera = new THREE.PerspectiveCamera(48, 1, 1, 10000)
  const lightTex = new THREE.CanvasTexture(lightCanvas)
  lightTex.colorSpace = THREE.NoColorSpace
  lightTex.minFilter = THREE.LinearFilter
  lightTex.generateMipmaps = false

  const rt = new THREE.WebGLRenderTarget(2, 2, { type: THREE.HalfFloatType, depthBuffer: true })
  const quadGeo = new THREE.PlaneGeometry(2, 2)
  const quadCam = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1)
  const bgMat = new THREE.ShaderMaterial({ vertexShader: QUAD_VERT, fragmentShader: BG_FRAG, uniforms: { tLight: { value: lightTex }, uBg: { value: new THREE.Vector3(...bg) } }, depthTest: false, depthWrite: false })
  const copyMat = new THREE.ShaderMaterial({ vertexShader: QUAD_VERT, fragmentShader: COPY_FRAG, uniforms: { tScene: { value: rt.texture } }, depthTest: false, depthWrite: false })
  const bgScene = new THREE.Scene(); bgScene.add(new THREE.Mesh(quadGeo, bgMat))
  const copyScene = new THREE.Scene(); copyScene.add(new THREE.Mesh(quadGeo, copyMat))

  const ior = 1.645
  const f0 = ((ior - 1) / (ior + 1)) ** 2
  const common = () => ({ uIor: { value: ior }, uF0: { value: f0 }, uRefl: { value: 2.14 }, uPlanes: { value: [] as THREE.Vector4[] } })
  const backMat = new THREE.ShaderMaterial({ vertexShader: VERT, fragmentShader: BACK_FRAG, uniforms: common(), side: THREE.BackSide, transparent: true, depthWrite: false,
    blending: THREE.CustomBlending, blendSrc: THREE.OneFactor, blendDst: THREE.OneMinusSrcAlphaFactor })
  const frontMat = new THREE.ShaderMaterial({ vertexShader: VERT, fragmentShader: FRONT_FRAG, side: THREE.FrontSide,
    uniforms: { ...common(), tScene: { value: rt.texture }, uViewProj: { value: new THREE.Matrix4() }, uAbsorb: { value: new THREE.Vector3(1, 1, 0.54) } } })
  const backScene = new THREE.Scene(), frontScene = new THREE.Scene()
  let backMesh: THREE.Mesh | null = null, frontMesh: THREE.Mesh | null = null
  let lastS = 0

  function setPrism(S: number) {
    if (Math.abs(S - lastS) < 0.5) return
    lastS = S
    backMesh?.geometry.dispose()
    if (backMesh) backScene.remove(backMesh)
    if (frontMesh) frontScene.remove(frontMesh)
    const { geo, planes } = prismGeometry(S)
    backMesh = new THREE.Mesh(geo, backMat)
    frontMesh = new THREE.Mesh(geo, frontMat)
    backScene.add(backMesh); frontScene.add(frontMesh)
    backMat.uniforms.uPlanes.value = planes
    frontMat.uniforms.uPlanes.value = planes
    const k = 0.57 / S // absorption is given per 0.57-unit side
    frontMat.uniforms.uAbsorb.value.set(1 * k, 1 * k, 0.54 * k)
  }

  let L: GlassLayout = { W: 1, H: 1, dpr: 1, cx: 0, cy: 0, S: 100 }
  function resize(l: GlassLayout) {
    L = l
    renderer.setPixelRatio(l.dpr)
    renderer.setSize(l.W, l.H, false)
    rt.setSize(Math.round(l.W * l.dpr), Math.round(l.H * l.dpr))
    camera.aspect = l.W / l.H
    camera.setViewOffset(l.W, l.H, l.W / 2 - l.cx, l.H / 2 - l.cy, l.W, l.H)
    setPrism(l.S)
  }

  /** Moves the prism on screen (idle floating) without rebuilding anything. */
  function place(cx: number, cy: number) {
    L = { ...L, cx, cy }
    camera.setViewOffset(L.W, L.H, L.W / 2 - cx, L.H / 2 - cy, L.W, L.H)
  }

  /** Orbit (±3.5°) around the prism and keep it at its layout position. */
  function aim(ox: number, oy: number) {
    const D = (L.H / 2) / Math.tan((24 * Math.PI) / 180)
    const yaw = (ox * 3.5 * Math.PI) / 180, pitch = (-oy * 3.5 * Math.PI) / 180
    camera.position.set(D * Math.sin(yaw) * Math.cos(pitch), D * Math.sin(pitch), D * Math.cos(yaw) * Math.cos(pitch))
    camera.lookAt(0, 0, 0)
    camera.updateMatrixWorld()
    camera.updateProjectionMatrix()
  }

  const tmp = new THREE.Vector3()
  /** Plane point (layout CSS px, y down) -> screen CSS px through the current camera. */
  function project(px: number, py: number): [number, number] {
    tmp.set(px - L.cx, -(py - L.cy), 0).project(camera)
    return [(tmp.x * 0.5 + 0.5) * L.W, (1 - (tmp.y * 0.5 + 0.5)) * L.H]
  }

  function render() {
    lightTex.needsUpdate = true
    frontMat.uniforms.uViewProj.value.multiplyMatrices(camera.projectionMatrix, camera.matrixWorldInverse)
    renderer.setRenderTarget(rt)
    renderer.setClearColor(0x000000, 1)
    renderer.clear()
    renderer.render(bgScene, quadCam)
    renderer.render(backScene, camera)
    renderer.setRenderTarget(null)
    renderer.clear()
    renderer.render(copyScene, quadCam)
    renderer.clearDepth()
    renderer.render(frontScene, camera)
  }

  function dispose() {
    backMesh?.geometry.dispose()
    ;[bgMat, copyMat, backMat, frontMat].forEach((m) => m.dispose())
    quadGeo.dispose()
    lightTex.dispose()
    rt.dispose()
    renderer.dispose()
  }

  return { resize, place, aim, project, render, dispose }
}

export function webgl2Available() {
  try { return !!document.createElement('canvas').getContext('webgl2') } catch { return false }
}
