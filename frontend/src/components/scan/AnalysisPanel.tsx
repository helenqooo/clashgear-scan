// The analysis side of the Nyx chat: every source's results for one scan, sorted so nobody has to
// untangle them: categories (detections, behaviour, network, C2, file system & registry, static,
// payloads) → sub-categories (processes, commands, ATT&CK…), and behaviour additionally split per
// sandbox service, since each sandbox ran the file on its own. Each row keeps the sources that
// reported it. It refreshes while the scan runs, so categories fill in as services finish.
import { useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import {
  Activity, Binary, ChevronRight, Cpu, FileStack, Globe, Loader, Radio, ShieldAlert, TriangleAlert,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ScanReport } from '@/lib/scanApi'

type Tone = 'bad' | 'warn' | 'ok'
type Row = { text: string; sub?: string; tone?: Tone; sources: string[] }
type Sub = { title: string; rows: Row[] }
type Section = { title?: string; badge?: { text: string; tone?: Tone }; subs: Sub[] }
type Category = { id: string; title: string; icon: typeof Activity; sections: Section[]; empty: string }

const str = (x: any): string => {
  if (x == null) return ''
  if (typeof x === 'string') return x
  return x.command_line || x.name || x.key || x.path || x.url || x.ioc || x.value || JSON.stringify(x)
}

/** Ordered sub-categories; a row added twice gains the second source instead of repeating. */
function section(order: string[]) {
  const subs = new Map<string, Map<string, Row>>(order.map((o) => [o, new Map()]))
  return {
    add(sub: string, text: string, source: string, extra: Partial<Row> = {}) {
      const t = String(text ?? '').trim()
      if (!t) return
      if (!subs.has(sub)) subs.set(sub, new Map())
      const m = subs.get(sub)!
      const k = t.toLowerCase()
      const r = m.get(k)
      if (r) { if (!r.sources.includes(source)) r.sources.push(source); if (extra.tone === 'bad') r.tone = 'bad' }
      else m.set(k, { text: t, sources: [source], ...extra })
    },
    subs: (): Sub[] => [...subs.entries()].map(([title, m]) => ({ title, rows: [...m.values()] })).filter((s) => s.rows.length),
  }
}

const SEV = (raw: any) => String(raw ?? '').replace(/^IMPACT_SEVERITY_/i, '').toLowerCase()
const VERDICT: Record<string, { text: string; tone?: Tone }> = {
  malicious: { text: 'Zararlı', tone: 'bad' }, suspicious: { text: 'Şüpheli', tone: 'warn' }, pua: { text: 'Hile aracı / PUA', tone: 'warn' }, clean: { text: 'Temiz', tone: 'ok' }, unknown: { text: 'Bilinmiyor' },
}

export function aggregate(rep: ScanReport, nameOf: (s: string) => string): Category[] {
  const done = rep.results.filter((r) => r.status === 'done' && r.summary && !r.summary.skipped)
  const st = rep.job.static || {}
  const det = section(['Antivirüs motorları', 'Tespit edilen isimler', 'Aile', 'YARA kuralları', 'Uyarılar'])
  const net = section(['IP adresleri', 'Alan adları', 'URL\'ler', 'İtibar kontrolü', 'Dosyanın içinde geçenler'])
  const c2 = section(['Zararlı yapılandırması', 'C2 adresleri', 'Dağıtıldığı adresler'])
  const fs = section(['Bırakılan dosyalar', 'Kayıt defteri', 'Mutex', 'Dosyanın içinde geçen yollar', 'Dosyanın içinde geçen kayıt anahtarları'])
  const stat = section(['Genel', 'Paketleme', 'Şüpheli API\'ler', 'Şüpheli kelimeler'])
  const pay = section(['Açılan (unpack) dosyalar', 'Çıkarılan / dump dosyalar', 'Çözülmüş script\'ler'])
  const behaviour: Section[] = [] // one section per sandbox service

  const computed = rep.job.ai?.computed
  if (computed?.family) det.add('Aile', computed.family, 'ClashGear', { tone: 'bad' })
  for (const w of computed?.warnings || []) det.add('Uyarılar', 'Kötü amaçlı bir sunucuda dağıtılırken görüldü', nameOf(w.source), { tone: 'warn', sub: w.urls.join(' · ') })

  for (const r of done) {
    const s = r.summary, src = nameOf(r.source)
    // detections
    if (typeof s.total === 'number' && s.total > 0) det.add('Antivirüs motorları', `${src}: ${s.malicious || 0}/${s.total} motor zararlı dedi`, src, { tone: s.malicious ? 'bad' : 'ok' })
    for (const d of (s.detections || []).slice(0, 15)) det.add('Tespit edilen isimler', `${d.engine}: ${d.result}`, src, { tone: 'bad' })
    for (const y of s.yara || []) det.add('YARA kuralları', y.rule, src, { sub: y.description || y.source, tone: 'warn' })
    if (s.family && s.verdict !== 'clean' && r.layer !== 9) det.add('Aile', s.family, src, { tone: 'bad' })

    // behaviour: everything a sandbox saw, kept per service
    if (r.layer === 8) {
      const b = section(['Oluşturulan süreçler', 'Çalıştırılan komutlar', 'MITRE ATT&CK teknikleri', 'Davranış imzaları'])
      for (const p of s.processes_created || []) b.add('Oluşturulan süreçler', str(p), src)
      for (const p of s.processes || []) if (typeof p === 'string' || p.command_line) b.add('Oluşturulan süreçler', str(p), src)
      for (const c of s.command_executions || []) b.add('Çalıştırılan komutlar', str(c), src)
      for (const a of s.attack || []) b.add('MITRE ATT&CK teknikleri', `${a.id} ${a.name || ''}`, src, { sub: a.tactic, tone: 'warn' })
      for (const g of s.signatures || []) {
        const sev = SEV(g.severity ?? g.threat_level_human)
        if (/^(info|informative|0|)$/.test(sev)) continue // informational noise
        b.add('Davranış imzaları', str(g), src, { sub: sev, tone: /high|critical|malicious/.test(sev) ? 'bad' : 'warn' })
      }
      const env = [].concat(s.sandboxes || s.environments || s.environment || []).join(' · ')
      const subs = b.subs()
      if (subs.length) behaviour.push({ title: src + (env ? ` · ${env}` : ''), badge: VERDICT[s.verdict], subs })
    }

    // network
    for (const ip of s.iocs?.ips || []) net.add('IP adresleri', ip, src)
    for (const d of s.iocs?.domains || []) net.add('Alan adları', d, src)
    for (const u of s.iocs?.urls || []) net.add('URL\'ler', u, src)
    if (r.layer === 9) for (const it of s.items || []) net.add('İtibar kontrolü', it.ioc, src, { sub: `${it.type}${it.malicious ? ` · ${it.malicious} kötü` : ' · temiz'}${it.country ? ` · ${it.country}` : ''}`, tone: it.malicious ? 'bad' : undefined })
    // C2 / communication
    for (const cf of s.configs || []) c2.add('Zararlı yapılandırması', cf.family ? `${cf.family} config` : 'Yapılandırma', src, { sub: JSON.stringify(Object.fromEntries(Object.entries(cf).filter(([k]) => !['source', 'family'].includes(k)))).slice(0, 400), tone: 'bad' })
    for (const x of s.c2 || []) c2.add('C2 adresleri', x.ioc, src, { sub: `${x.type}${x.confidence ? ` · güven ${x.confidence}` : ''}`, tone: 'bad' })
    for (const u of s.urls || []) c2.add('Dağıtıldığı adresler', str(u), src, { sub: u.status, tone: 'warn' })
    // file system & registry (sandbox side)
    for (const f of s.files_dropped || []) fs.add('Bırakılan dosyalar', str(f), src, { sub: f.sha256 ? `${f.sha256.slice(0, 16)}…` : undefined })
    for (const k of s.registry_set || []) fs.add('Kayıt defteri', str(k), src, { sub: typeof k === 'object' && k.value ? `= ${String(k.value).slice(0, 80)}` : undefined })
    for (const m of s.mutexes || []) fs.add('Mutex', str(m), src)
    // payloads
    for (const f of s.extracted_files || []) pay.add('Çıkarılan / dump dosyalar', str(f), src, { sub: f.sha256 ? f.sha256.slice(0, 16) : f.threat_level })
    for (const f of [...(s.dumped_files || []), ...(s.payloads || [])]) pay.add('Çıkarılan / dump dosyalar', str(f), src, { sub: f.sha256 ? f.sha256.slice(0, 16) : undefined })
    for (const sc of s.scripts || []) pay.add('Çözülmüş script\'ler', sc.name || 'script', src)
  }

  // static
  const pe = st.pe
  if (pe) {
    stat.add('Genel', `${pe.arch} · ${pe.bits}-bit · ${pe.subsystem || ''}${pe.dll ? ' · DLL' : ''}${pe.dotnet ? ' · .NET' : ''}`, 'ClashGear')
    stat.add('Genel', `Giriş noktası ${pe.entry_point} (${pe.entry_section || '?'})`, 'ClashGear')
    if (pe.compiled_at) stat.add('Genel', `Derlenme tarihi ${pe.compiled_at.slice(0, 10)}`, 'ClashGear')
    stat.add('Genel', pe.signed ? 'Dijital imzalı' : 'İmzasız', 'ClashGear', { tone: pe.signed ? 'ok' : undefined })
    for (const p of pe.packer_hints || []) stat.add('Paketleme', `Paketleyici: ${p}`, 'ClashGear', { tone: 'warn' })
    for (const s of pe.high_entropy_sections || []) stat.add('Paketleme', `Yüksek entropili bölüm: ${s}`, 'ClashGear', { tone: 'warn' })
    if (pe.overlay_bytes) stat.add('Paketleme', `Dosya sonuna eklenmiş veri (overlay): ${pe.overlay_bytes} bayt`, 'ClashGear', { tone: 'warn' })
    for (const a of pe.suspicious_apis || []) stat.add('Şüpheli API\'ler', a, 'ClashGear', { tone: 'warn' })
  }
  if (st.entropy != null) stat.add('Genel', `Entropi ${st.entropy}`, 'ClashGear')
  const ind = st.indicators || {}
  for (const u of ind.urls || []) net.add('Dosyanın içinde geçenler', u, 'Stringler', { sub: 'URL' })
  for (const d of ind.ips || []) net.add('Dosyanın içinde geçenler', d, 'Stringler', { sub: 'IP' })
  for (const d of ind.domains || []) net.add('Dosyanın içinde geçenler', d, 'Stringler', { sub: 'alan adı' })
  for (const k of ind.registry || []) fs.add('Dosyanın içinde geçen kayıt anahtarları', k, 'Stringler')
  for (const p of ind.paths || []) fs.add('Dosyanın içinde geçen yollar', p, 'Stringler')
  for (const k of ind.keywords || []) stat.add('Şüpheli kelimeler', k, 'Stringler', { tone: 'warn' })
  for (const c of rep.children) pay.add('Açılan (unpack) dosyalar', c.file_name, 'Unpack', { sub: `${c.verdict ?? 'taranıyor'}${c.score != null ? ` · ${c.score}` : ''}`, tone: c.verdict === 'malicious' ? 'bad' : undefined })

  const one = (s: ReturnType<typeof section>): Section[] => (s.subs().length ? [{ subs: s.subs() }] : [])
  return [
    { id: 'det', title: 'Tespitler', icon: ShieldAlert, sections: one(det), empty: 'Henüz tespit yok.' },
    { id: 'beh', title: 'Davranış analizi', icon: Activity, sections: behaviour, empty: 'Sandbox davranışı henüz gelmedi.' },
    { id: 'net', title: 'Ağ bağlantıları', icon: Globe, sections: one(net), empty: 'Ağ göstergesi yok.' },
    { id: 'c2', title: 'İletişim · C2', icon: Radio, sections: one(c2), empty: 'C2 / yapılandırma bulunmadı.' },
    { id: 'fs', title: 'Dosya sistemi · Kayıt defteri', icon: FileStack, sections: one(fs), empty: 'Dosya / kayıt defteri izi yok.' },
    { id: 'stat', title: 'Statik analiz', icon: Cpu, sections: one(stat), empty: 'Statik bilgi yok.' },
    { id: 'pay', title: 'Açılan dosyalar · Payload', icon: Binary, sections: one(pay), empty: 'Açılan dosya yok.' },
  ]
}

const TONE: Record<string, string> = { bad: 'text-amber-400', warn: 'text-amber-200/80', ok: 'text-emerald-400' }
const BADGE: Record<string, string> = { bad: 'bg-amber-500/15 text-amber-400', warn: 'bg-amber-300/10 text-amber-200', ok: 'bg-emerald-500/10 text-emerald-400' }
const count = (c: Category) => c.sections.reduce((n, s) => n + s.subs.reduce((m, x) => m + x.rows.length, 0), 0)
const hasBad = (c: Category) => c.sections.some((s) => s.subs.some((x) => x.rows.some((r) => r.tone === 'bad')))

function SubList({ sub }: { sub: Sub }) {
  const [open, setOpen] = useState(true)
  const [all, setAll] = useState(false)
  const rows = all ? sub.rows : sub.rows.slice(0, 8)
  return (
    <div className="pb-1">
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-1.5 px-9 py-1 text-left">
        <ChevronRight className={cn('size-3 shrink-0 text-muted-foreground/60 transition-transform duration-150', open && 'rotate-90')} />
        <span className="text-[10.5px] font-medium uppercase tracking-[0.1em] text-muted-foreground">{sub.title}</span>
        <span className="text-[10.5px] tabular-nums text-muted-foreground/50">{sub.rows.length}</span>
      </button>
      {open && (
        <div className="ml-[42px] border-l border-border/60 pl-3 pr-4">
          {rows.map((r) => (
            <div key={r.text} className="py-1">
              <p className={cn('break-all font-mono text-[11.5px] leading-[17px] text-foreground/85', r.tone && TONE[r.tone])}>{r.text}</p>
              <p className="mt-0.5 truncate text-[10.5px] text-muted-foreground/60">{[r.sub, r.sources.join(', ')].filter(Boolean).join(' · ')}</p>
            </div>
          ))}
          {sub.rows.length > 8 && <button type="button" onClick={() => setAll((a) => !a)} className="py-1 text-[11px] text-muted-foreground hover:text-foreground">{all ? 'Daha az göster' : `+${sub.rows.length - 8} daha`}</button>}
        </div>
      )}
    </div>
  )
}

function CategoryBlock({ c, running }: { c: Category; running: boolean }) {
  const [open, setOpen] = useState(c.id === 'det' || c.id === 'beh')
  const Icon = c.icon
  const n = count(c)
  return (
    <div className="border-b border-border/60 last:border-0">
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left hover:bg-foreground/[0.03]">
        <ChevronRight className={cn('size-3.5 shrink-0 text-muted-foreground transition-transform duration-150', open && 'rotate-90')} />
        <Icon className="size-4 shrink-0 text-muted-foreground" />
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-foreground">{c.title}</span>
        {running && !n ? <Loader className="size-3.5 animate-spin text-muted-foreground" /> : (
          <span className={cn('rounded-full px-2 py-0.5 text-[11px] tabular-nums', hasBad(c) ? 'bg-amber-500/15 text-amber-400' : 'bg-foreground/[0.06] text-muted-foreground')}>{n}</span>
        )}
      </button>
      {open && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="pb-2">
          {!n && <p className="px-9 pb-1 text-[12px] text-muted-foreground/60">{running ? 'Servisler çalışıyor…' : c.empty}</p>}
          {c.sections.map((s, i) => (
            <div key={s.title || i} className={cn(s.title && 'mt-1')}>
              {s.title && (
                <div className="flex items-center gap-2 px-9 pb-0.5 pt-1.5">
                  <span className="min-w-0 truncate text-[12px] font-medium text-foreground/90">{s.title}</span>
                  {s.badge && <span className={cn('shrink-0 rounded-md px-1.5 py-px text-[10.5px]', s.badge.tone ? BADGE[s.badge.tone] : 'bg-foreground/[0.06] text-muted-foreground')}>{s.badge.text}</span>}
                </div>
              )}
              {s.subs.map((sub) => <SubList key={sub.title} sub={sub} />)}
            </div>
          ))}
        </motion.div>
      )}
    </div>
  )
}

export function AnalysisPanel({ rep, nameOf, header }: { rep: ScanReport; nameOf: (s: string) => string; header?: ReactNode }) {
  const running = rep.job.status === 'running'
  const live = rep.results.filter((r) => r.status !== 'disabled')
  const settled = live.filter((r) => !['queued', 'running'].includes(r.status)).length
  const v = rep.job.verdict
  const cats = aggregate(rep, nameOf)
  return (
    <div className="flex min-h-0 flex-col">
      {header}
      <div className="px-3 pb-3">
        <div className="rounded-xl border border-border bg-background/40 p-3">
          <p className="truncate text-[13px] font-medium text-foreground">{rep.job.file_name}</p>
          <p className="mt-0.5 truncate font-mono text-[10.5px] text-muted-foreground/60">{rep.job.sha256}</p>
          <div className="mt-2.5 flex items-center gap-2 text-[12px]">
            {running ? (
              <>
                <Loader className="size-3.5 animate-spin text-blue-400" />
                <span className="text-muted-foreground">Taranıyor</span>
                <span className="relative h-1 flex-1 overflow-hidden rounded-full bg-muted"><span className="absolute inset-y-0 left-0 rounded-full bg-blue-400 transition-[width] duration-500" style={{ width: `${live.length ? (settled / live.length) * 100 : 0}%` }} /></span>
                <span className="tabular-nums text-muted-foreground">{settled}/{live.length}</span>
              </>
            ) : (
              <>
                {v === 'malicious' || v === 'suspicious' ? <TriangleAlert className="size-3.5 text-amber-400" /> : <span className={cn('size-2 rounded-full', v === 'clean' ? 'bg-emerald-400' : 'bg-muted-foreground')} />}
                <span className="font-medium text-foreground">{VERDICT[v || 'unknown']?.text || 'Bilinmiyor'}</span>
                <span className="tabular-nums text-muted-foreground">{rep.job.score ?? '—'}/100</span>
                <span className="ml-auto text-muted-foreground/60">{settled}/{live.length} kaynak</span>
              </>
            )}
          </div>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto border-t border-border/60">
        {cats.map((c) => <CategoryBlock key={c.id} c={c} running={running} />)}
      </div>
    </div>
  )
}
