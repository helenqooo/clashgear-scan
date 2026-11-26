import { useMemo, type ReactNode } from 'react'
import { ChevronRight, Cpu, FileMinus, FilePen, FileSearch, Globe, KeyRound, Play, TriangleAlert, Terminal, Lock } from 'lucide-react'
import { cn } from '@/lib/utils'

// What each process did in our CAPE VM (backend: providers/sandbox.js capeActivity).
type Proc = {
  pid: number; ppid: number; name: string; path: string; command_line: string; started: string[]; flags: string[]; source?: 'sysmon'
  files: { written: string[]; deleted: string[]; read: string[] }
  registry: { written: { key: string; data: string }[]; deleted: string[]; read: string[] }
  network: { dns: string[]; connections: string[]; urls: string[] }
}
export type CapeActivityData = {
  unmonitored?: { path: string; pid: number; kernel?: boolean }[]
  processes: Proc[]; commands: string[]; mutexes: string[]; services: string[]
  dns: { name: string; type: string; answers: string[] }[]
  http: { method: string; url: string; host: string; ua: string; status: string | number }[]
  connections: string[]
}

const FLAG: Record<string, string> = {
  remote_thread: 'Başka bir süreçte thread başlattı',
  wrote_other_process: 'Başka bir sürecin belleğine yazdı',
  hook: 'Sistem çapında kanca (hook) kurdu',
  tampering: 'Süreç görüntüsünü değiştirdi (hollowing/tampering)',
}

// Windows' own background services that CAPE also sees during a run; not started by the sample.
const BACKGROUND = /^(svchost|dllhost|wmiprvse|wmiadap|tiworker|trustedinstaller|slui|sppsvc|searchindexer|searchprotocolhost|searchfilterhost|wuauclt|musnotification|compattelrunner|taskhostw|backgroundtaskhost|runtimebroker|smartscreen|sihclient|mpcmdrun|msmpeng|nissrv|consent|werfault|wermgr|audiodg|ctfmon|sdclt)\.exe$/i

const Mono = ({ children }: { children: ReactNode }) => <span className="break-all font-mono text-[12px] text-foreground/85">{children}</span>

function Fold({ icon: Icon, title, items, tone, open, render }: {
  icon: typeof FilePen; title: string; items: unknown[]; tone?: 'warn'; open?: boolean; render?: (x: any) => ReactNode
}) {
  if (!items.length) return null
  return (
    <details open={open} className="group rounded-lg border border-white/[0.06] bg-white/[0.02]">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-[13px] [&::-webkit-details-marker]:hidden">
        <ChevronRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-open:rotate-90" />
        <Icon className={cn('size-3.5 shrink-0', tone === 'warn' ? 'text-amber-400' : 'text-muted-foreground')} />
        <span className={tone === 'warn' ? 'text-amber-300' : 'text-foreground/90'}>{title}</span>
        <span className="ml-auto rounded-full bg-secondary px-1.5 text-[11px] tabular-nums text-muted-foreground">{items.length}</span>
      </summary>
      <ul className="space-y-1 border-t border-white/[0.06] px-3 py-2">
        {items.map((x, i) => <li key={i}>{render ? render(x) : <Mono>{String(x)}</Mono>}</li>)}
      </ul>
    </details>
  )
}

export function CapeActivity({ a }: { a: CapeActivityData }) {
  // Order processes as a tree: each one after its parent, indented by depth.
  const rows = useMemo(() => {
    const byParent = new Map<number, Proc[]>()
    const pids = new Set(a.processes.map((p) => p.pid))
    for (const p of a.processes) {
      const k = pids.has(p.ppid) ? p.ppid : -1
      byParent.set(k, [...(byParent.get(k) || []), p])
    }
    const out: { p: Proc; depth: number }[] = []
    const walk = (k: number, depth: number) => { for (const p of byParent.get(k) || []) { out.push({ p, depth }); walk(p.pid, depth + 1) } }
    walk(-1, 0)
    return out
  }, [a.processes])
  const main = rows.filter(({ p }) => !BACKGROUND.test(p.name))
  const background = rows.filter(({ p }) => BACKGROUND.test(p.name))

  const card = ({ p, depth }: { p: Proc; depth: number }) => {
    const changes = p.files.written.length + p.files.deleted.length + p.registry.written.length + p.registry.deleted.length
    return (
      <div key={p.pid} className="rounded-xl border border-border bg-card/60 p-3" style={{ marginLeft: Math.min(depth, 4) * 18 }}>
        <div className="flex flex-wrap items-center gap-2">
          {depth > 0 && <span className="text-muted-foreground">↳</span>}
          <span className="text-sm font-semibold">{p.name}</span>
          {/^explorer\.exe$/i.test(p.name) && <span className="text-[11px] text-muted-foreground">masaüstü · oturumdaki tıklamalar burada</span>}
          <span className="text-[11px] text-muted-foreground">PID {p.pid}</span>
          {p.source === 'sysmon' && <span className="rounded-full bg-[#d4ff3a]/15 px-2 py-0.5 text-[11px] text-[#d4ff3a]" title="İzleme modülü bu sürecin içine giremedi; bilgiler Windows çekirdek kayıtlarından (Sysmon)">çekirdek kaydı</span>}
          {!!changes && <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-300">{changes} değişiklik</span>}
          {p.flags.map((f) => <span key={f} className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] text-amber-300"><TriangleAlert className="size-3" />{FLAG[f] || f}</span>)}
        </div>
        {p.command_line && <p className="mt-1.5"><Mono>{p.command_line}</Mono></p>}
        <div className="mt-2.5 space-y-1.5">
          <Fold icon={Play} title="Başlattığı süreçler / komutlar" items={p.started} open />
          <Fold icon={FilePen} title="Yazdığı ya da oluşturduğu dosyalar" items={p.files.written} tone="warn" open />
          <Fold icon={FileMinus} title="Sildiği / taşıdığı dosyalar" items={p.files.deleted} tone="warn" open />
          <Fold icon={KeyRound} title="Değiştirdiği kayıt defteri değerleri" items={p.registry.written} tone="warn" open
            render={(x: { key: string; data: string }) => <><Mono>{x.key}</Mono>{x.data && <span className="ml-1.5 text-[11px] text-muted-foreground">= {x.data}</span>}</>} />
          <Fold icon={KeyRound} title="Sildiği kayıt defteri anahtarları" items={p.registry.deleted} tone="warn" open />
          <Fold icon={Globe} title="Ağ: çözdüğü adresler, bağlantılar, URL'ler" items={[...p.network.dns.map((d) => `DNS  ${d}`), ...p.network.connections.map((c) => `TCP  ${c}`), ...p.network.urls.map((u) => `URL  ${u}`)]} open />
          <Fold icon={FileSearch} title="Okuduğu dosyalar" items={p.files.read} />
          <Fold icon={KeyRound} title="Okuduğu kayıt defteri değerleri" items={p.registry.read} />
        </div>
      </div>
    )
  }

  return (
    <div className="mt-5 space-y-5">
      {a.unmonitored?.map((u) => (
        <div key={u.pid} className="flex items-start gap-2.5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-400" />
          <p><span className="font-semibold">{u.path.split('\\').pop()}</span> çalıştırıldı (PID {u.pid}) ama izleme modülü sürecin içine giremedi; VMProtect/Themida gibi korumalar bunu bilerek engeller.{' '}
            {u.kernel
              ? 'Yaptıkları Windows çekirdeğinin kayıtlarından (Sysmon) toplandı ve aşağıda "çekirdek kaydı" etiketiyle görünüyor: başlattığı süreçler, oluşturduğu/sildiği dosyalar, kayıt defteri değişiklikleri, DNS ve bağlantılar. Okuduğu dosyalar gibi ayrıntılar bu yoldan görünmez.'
              : 'Bu süreçte yaptıkları aşağıdaki listede yer almaz; süreç dışındaki izler (alt süreçler, ağ trafiği, bıraktığı dosyalar) yine görünür.'}</p>
        </div>
      ))}
      <div>
        <h4 className="mb-2 flex items-center gap-2 text-sm font-medium"><Cpu className="size-4 text-muted-foreground" /> Süreçler ve yaptıkları <span className="rounded-full bg-secondary px-1.5 text-[11px] font-normal tabular-nums text-muted-foreground">{main.length}</span></h4>
        <div className="space-y-3">{main.map(card)}</div>
        {!!background.length && (
          <details className="group mt-3">
            <summary className="flex cursor-pointer list-none items-center gap-2 text-xs text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
              <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" /> Arka plan Windows süreçleri ({background.length}) — dosyanla ilgisiz, sistemin kendi işleri
            </summary>
            <div className="mt-2 space-y-3 opacity-80">{background.map(({ p }) => card({ p, depth: 0 }))}</div>
          </details>
        )}
      </div>

      {(!!a.dns.length || !!a.http.length || !!a.connections.length) && (
        <div>
          <h4 className="mb-2 flex items-center gap-2 text-sm font-medium"><Globe className="size-4 text-muted-foreground" /> Ağ trafiği</h4>
          <div className="space-y-1.5">
            <Fold icon={Globe} title="DNS sorguları" items={a.dns} open render={(d: CapeActivityData['dns'][number]) => <><Mono>{d.name}</Mono><span className="ml-1.5 text-[11px] text-muted-foreground">{d.type} → {d.answers.join(', ') || '—'}</span></>} />
            <Fold icon={Globe} title="HTTP / HTTPS istekleri" items={a.http} open render={(h: CapeActivityData['http'][number]) => <><span className="mr-1.5 text-[11px] font-semibold text-muted-foreground">{h.method || 'GET'}</span><Mono>{h.url}</Mono>{h.ua && <span className="ml-1.5 text-[11px] text-muted-foreground">({h.ua})</span>}</>} />
            <Fold icon={Globe} title="Bağlantı kurduğu adresler" items={a.connections} />
          </div>
        </div>
      )}

      {(!!a.commands.length || !!a.mutexes.length || !!a.services.length) && (
        <div className="space-y-1.5">
          <Fold icon={Terminal} title="Çalıştırılan komutlar" items={a.commands} open />
          <Fold icon={Cpu} title="Oluşturduğu / başlattığı servisler" items={a.services} tone="warn" open />
          <Fold icon={Lock} title="Mutex'ler" items={a.mutexes} />
        </div>
      )}
    </div>
  )
}
