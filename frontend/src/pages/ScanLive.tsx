import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import * as G from 'guacamole-common-js'
import { ArrowLeft, Loader, MonitorPlay, Square, TriangleAlert } from 'lucide-react'
import { BrandMark } from '@/components/ui/brand'
import { cn } from '@/lib/utils'
import { scanApi, type LiveState } from '@/lib/scanApi'

// The package ships its namespace as the default export; the typings describe it as named exports.
const Guacamole = ((G as unknown as { default?: typeof G }).default ?? G) as typeof G

const fmt = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

/** Live sandbox: the user's file runs in our CAPE VM (interactive mode) and they drive the desktop here. */
export default function ScanLive() {
  const { lid = '' } = useParams()
  const [st, setSt] = useState<LiveState | null>(null)
  const [err, setErr] = useState('')
  const [conn, setConn] = useState<'idle' | 'connecting' | 'open' | 'closed'>('idle')
  const [left, setLeft] = useState<number | null>(null)
  const screenRef = useRef<HTMLDivElement>(null)
  const clientRef = useRef<G.Client | null>(null)

  // Poll the session until the VM runs, then keep polling slowly for the end.
  useEffect(() => {
    let stop = false
    let timer = 0
    const tick = () => scanApi.liveStatus(lid).then((s) => {
      if (stop) return
      setSt(s)
      setLeft(s.left)
      timer = window.setTimeout(tick, s.status === 'running' ? 10_000 : 2_000)
    }).catch(() => { if (!stop) setErr('Oturum bulunamadı ya da süresi doldu.') })
    tick()
    return () => { stop = true; window.clearTimeout(timer) }
  }, [lid])

  useEffect(() => {
    if (left == null || st?.status !== 'running') return
    const t = window.setInterval(() => setLeft((x) => (x == null ? x : Math.max(0, x - 1))), 1000)
    return () => window.clearInterval(t)
  }, [st?.status, left == null])

  // Connect once, with the first token. Every status poll brings a fresh token (new IV); keying the
  // connection on it reconnected the screen every 10 s, so the token is read through a ref instead.
  const tokenRef = useRef<string | null>(null)
  if (st?.token && !tokenRef.current) tokenRef.current = st.token
  const ready = st?.status === 'running' && !!tokenRef.current
  // A real drop (network, phone sleeping) reconnects with a fresh token while the session still runs.
  const [attempt, setAttempt] = useState(0)
  const endedRef = useRef(false)
  const reconnect = () => {
    if (endedRef.current) return
    window.setTimeout(() => scanApi.liveStatus(lid).then((s) => {
      setSt(s)
      if (s.status !== 'running' || !s.token) return
      tokenRef.current = s.token
      setAttempt((a) => a + 1)
    }).catch(() => {}), 1500)
  }
  useEffect(() => {
    if (!ready || clientRef.current || !screenRef.current) return
    const token = tokenRef.current as string
    const host = screenRef.current
    const tunnel = new Guacamole.WebSocketTunnel(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/scan/live/ws`)
    const client = new Guacamole.Client(tunnel)
    clientRef.current = client
    const display = client.getDisplay()
    const el = display.getElement()
    host.innerHTML = ''
    host.appendChild(el)
    const fit = () => {
      const w = display.getWidth(), h = display.getHeight()
      if (w && h) display.scale(Math.min(host.clientWidth / w, host.clientHeight / h))
    }
    display.onresize = fit
    window.addEventListener('resize', fit)
    let dropped = false
    const drop = () => {
      if (dropped) return
      dropped = true
      setConn('connecting')
      clientRef.current = null
      reconnect()
    }
    client.onstatechange = (s: number) => { if (s === 3) setConn('open'); else if (s === 5) drop(); else setConn('connecting') }
    client.onerror = drop
    setConn('connecting')
    client.connect(`token=${encodeURIComponent(token)}`)

    const mouse = new Guacamole.Mouse(el)
    mouse.onEach(['mousedown', 'mouseup', 'mousemove'], (e) => client.sendMouseState((e as G.Mouse.Event).state, true))
    const touch = new Guacamole.Mouse.Touchscreen(el)
    touch.onEach(['mousedown', 'mouseup', 'mousemove'], (e) => client.sendMouseState((e as G.Mouse.Event).state, true))
    const keyboard = new Guacamole.Keyboard(document)
    keyboard.onkeydown = (k) => { client.sendKeyEvent(1, k); return false }
    keyboard.onkeyup = (k) => client.sendKeyEvent(0, k)

    return () => {
      dropped = true // our own teardown is not a drop
      window.removeEventListener('resize', fit)
      keyboard.onkeydown = null
      keyboard.onkeyup = null
      client.disconnect()
      if (clientRef.current === client) clientRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, attempt])

  const stop = async () => {
    endedRef.current = true
    clientRef.current?.disconnect()
    await scanApi.liveStop(lid).catch(() => {})
    setSt((s) => (s ? { ...s, status: 'ended' } : s))
  }

  const ended = st?.status === 'ended' || left === 0
  endedRef.current = ended
  const label = !st ? 'Bağlanıyor…' : st.status === 'queued' ? 'Sırada: sandbox başka bir analizle meşgul' : st.status === 'starting' ? 'Makine açıldı, dosyan masaüstüne yerleştirilip çalıştırılıyor…'
    : ended ? 'Oturum bitti' : conn === 'open' ? 'Canlı' : 'Ekrana bağlanıyor…'

  return (
    <div className="scan-dark dark flex h-[100dvh] flex-col bg-[#0a0a0a] text-foreground">
      <header className="flex h-12 shrink-0 items-center gap-3 border-b border-white/[0.06] px-3">
        <Link to={st ? `/scan/r/${st.job_id}` : '/scan/app'} className="press flex items-center gap-1.5 rounded-lg px-2 py-1 text-sm text-neutral-400 hover:bg-white/[0.06] hover:text-white"><ArrowLeft className="size-4" /> Rapor</Link>
        <span className="flex items-center gap-2 text-sm font-semibold"><BrandMark size={18} /> Canlı sandbox</span>
        <span className={cn('ml-1 flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs', conn === 'open' && !ended ? 'bg-emerald-500/15 text-emerald-400' : 'bg-white/[0.06] text-neutral-400')}>
          {conn === 'open' && !ended ? <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" /> : !ended && <Loader className="size-3 animate-spin" />}
          {label}
        </span>
        <span className="ml-auto tabular-nums text-sm text-neutral-400">{left != null && !ended ? fmt(left) : ''}</span>
        {!ended && st && <button type="button" onClick={stop} className="press flex items-center gap-1.5 rounded-lg bg-white/[0.08] px-3 py-1.5 text-xs font-semibold hover:bg-white/[0.12]"><Square className="size-3.5" /> Bitir</button>}
      </header>
      <main className="relative min-h-0 flex-1">
        <div ref={screenRef} className={cn('absolute inset-0 grid place-items-center overflow-hidden', (ended || conn !== 'open') && 'opacity-30')} tabIndex={0} />
        {(err || ended || st?.status !== 'running') && (
          <div className="absolute inset-0 grid place-items-center p-6">
            <div className="max-w-md text-center">
              {err ? <TriangleAlert className="mx-auto size-8 text-amber-400" /> : ended ? <MonitorPlay className="mx-auto size-8 text-neutral-400" /> : <Loader className="mx-auto size-8 animate-spin text-neutral-400" />}
              <p className="mt-4 text-sm text-neutral-300">{err || (ended ? 'Makine kapatıldı. CAPE gördüklerini işliyor; bu oturumda yaptıkların sandbox raporuna eklenir.' : label)}</p>
              {!err && !ended && <p className="mt-2 text-xs text-neutral-500">Dosyan otomatik çalıştırılacak. Makinede tıklayabilir, yazı yazabilir, açılan pencereleri kullanabilirsin. Her şey izleniyor; oturum bitince makine sıfırlanır.</p>}
              {(err || ended) && st && <Link to={`/scan/r/${st.job_id}`} className="mt-5 inline-block rounded-xl bg-white px-4 py-2 text-sm font-semibold text-black">Rapora dön</Link>}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
