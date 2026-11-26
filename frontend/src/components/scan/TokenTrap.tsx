// Token Tuzağı card on the report's Sandbox tab (backend: src/scan/honey.js). Before a run: what it is and a
// button. While it runs: the three phases. After: the plain-language chains ("Discord token'ını OKUDU → ZIP'LEDİ →
// api.telegram.org adresine GÖNDERDİ") and the evidence behind each step.
import { useEffect, useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { ArrowRight, Bot, ClipboardPaste, Eye, FileArchive, Fingerprint, Loader, Send, Siren, Webhook } from 'lucide-react'
import { LiquidMetalButton } from '@/components/ui/liquid-metal-button'
import { ApiError } from '@/lib/api'
import { scanApi, type ScanResult } from '@/lib/scanApi'
import { cn } from '@/lib/utils'

const KIND: Record<string, string> = {
  discord: 'Discord token', browser_passwords: 'Kayıtlı şifreler', browser_cookies: 'Tarayıcı çerezleri', wallet: 'Kripto cüzdanları',
  telegram: 'Telegram oturumu', roblox: 'Roblox çerezi', steam: 'Steam oturumu', browser_key: 'Tarayıcı anahtarı', trap: 'Tuzak şifresi', clipboard: 'Pano',
}
const spring = { type: 'spring', stiffness: 260, damping: 30 } as const

type Step = { step: 'read' | 'packed' | 'sent'; by?: string[]; archive?: boolean; file?: string; to?: string[]; proof?: 'content' | 'connection' }
type Chain = { kind: string; strong: boolean; steps: Step[]; text: string }

const fmtDate = (t: number) => new Date(t).toLocaleString('tr-TR', { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })
const ago = (ms: number) => {
  const d = Math.floor(ms / 86_400_000), h = Math.floor((ms % 86_400_000) / 3_600_000)
  return d ? `${d} gün${h ? ` ${h} saat` : ''}` : h ? `${h} saat` : `${Math.max(1, Math.round(ms / 60_000))} dakika`
}

function Mono({ children }: { children: ReactNode }) {
  return <code className="break-all rounded bg-white/[0.05] px-1.5 py-0.5 font-mono text-[11px] text-neutral-300">{children}</code>
}

function StepPill({ s }: { s: Step }) {
  const weak = s.step === 'sent' && s.proof === 'connection'
  const icon = s.step === 'read' ? <Eye className="size-3.5" /> : s.step === 'packed' ? <FileArchive className="size-3.5" /> : <Send className="size-3.5" />
  const word = s.step === 'read' ? 'Okudu' : s.step === 'packed' ? (s.archive ? "Zip'ledi" : 'Paketledi') : weak ? 'Bağlandı' : 'Gönderdi'
  const sub = s.step === 'read' ? s.by?.join(', ') : s.step === 'packed' ? s.file : s.to?.join(', ')
  return (
    <span className={cn('inline-flex max-w-full items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs',
      weak ? 'border-dashed border-amber-300/40 text-amber-200/90' : 'border-amber-400/40 bg-amber-400/[0.08] text-amber-200')}>
      {icon}<span className="font-semibold uppercase tracking-wide">{word}</span>
      {sub && <span className="truncate font-mono text-[11px] text-neutral-300">{sub}</span>}
    </span>
  )
}

function ChainRow({ c, i }: { c: Chain; i: number }) {
  return (
    <motion.li initial={{ y: 10, filter: 'blur(6px)' }} animate={{ y: 0, filter: 'blur(0px)' }} transition={{ ...spring, delay: 0.06 * i }}
      className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-md bg-white/[0.06] px-2 py-1 text-xs font-medium text-white">{KIND[c.kind] || c.kind}</span>
        {c.steps.map((s, j) => (
          <span key={j} className="flex items-center gap-2">
            <ArrowRight className="size-3.5 text-neutral-500" /><StepPill s={s} />
          </span>
        ))}
      </div>
      <p className="mt-2 text-[13px] leading-relaxed text-neutral-300">{c.text}</p>
    </motion.li>
  )
}

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-white/[0.06] p-3">
      <h5 className="mb-2 flex items-center gap-2 text-[13px] font-medium text-white">{icon}{title}</h5>
      <div className="space-y-1.5 text-xs text-neutral-300">{children}</div>
    </div>
  )
}

function Running({ h }: { h: any }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(t) }, [])
  const total = (h?.seconds || 180) + 90
  const el = h?.started_at ? Math.max(0, (now - h.started_at) / 1000) : 0
  const phase = h?.status === 'queued' ? 0 : el < (h?.seconds || 180) ? 1 : 2
  const steps = ['Sahte hesaplar yerleştiriliyor', 'Dosya çalışıyor, her dokunuş kaydediliyor', 'Paketler ve trafik taranıyor']
  return (
    <div className="mt-4">
      <div className="h-1 overflow-hidden rounded-full bg-white/[0.06]">
        <motion.div className="h-full rounded-full bg-amber-300/80" animate={{ width: `${Math.min(96, (el / total) * 100)}%` }} transition={{ duration: 0.6 }} />
      </div>
      <ul className="mt-3 space-y-1.5">
        {steps.map((s, i) => (
          <li key={s} className={cn('flex items-center gap-2 text-sm', i < phase ? 'text-neutral-500' : i === phase ? 'text-white' : 'text-neutral-600')}>
            {i === phase ? <Loader className="size-3.5 animate-spin" /> : <span className={cn('size-1.5 rounded-full', i < phase ? 'bg-amber-300' : 'bg-neutral-700')} />}{s}
          </li>
        ))}
      </ul>
    </div>
  )
}

export function TokenTrap({ jobId, result, mine, onChange }: { jobId: string; result?: ScanResult; mine: boolean; onChange: () => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [left, setLeft] = useState<number | null | undefined>(undefined)
  const status = result && result.status !== 'disabled' ? result.status : null
  const h = result?.summary?.honey
  const running = status === 'running' || status === 'queued'

  useEffect(() => { if (mine && !running) scanApi.honeyInfo().then((i) => setLeft(i.available ? i.left : 0)).catch(() => {}) }, [mine, running])
  // The report page stops polling once the scan is done; a trap run keeps going after that.
  useEffect(() => {
    if (!running) return
    const t = window.setInterval(onChange, 8000)
    return () => window.clearInterval(t)
  }, [running, onChange])

  if (!status && !mine) return null
  const go = async () => {
    if (busy) return
    setErr(''); setBusy(true)
    try { await scanApi.honeyStart(jobId); onChange() } catch (e) {
      const code = e instanceof ApiError ? e.code : ''
      setErr(code === 'vpn_blocked' ? '' : code === 'honey_quota_exceeded' ? 'Bugünkü tuzak hakkın doldu, yarın yenilenir.' : code === 'honey_unavailable' ? 'Tuzak makinesi şu an bakımda, birazdan tekrar dene.' : 'Başlatılamadı, tekrar dene.')
    } finally { setBusy(false) }
  }

  const done = status === 'done' && h
  const used: { at: number; country?: string; pass_ok?: boolean }[] = h?.used || []
  const touched = !!(h?.reads?.length || h?.packed?.length || h?.sent?.length || h?.clipboard?.length)
  return (
    <div className="relative mt-3 overflow-hidden rounded-2xl border border-amber-300/20 bg-[radial-gradient(120%_140%_at_100%_0%,rgba(252,211,77,0.08),transparent_55%)] p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="rounded-full bg-amber-300 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-black">Yeni</span>
            <h4 className="text-[15px] font-semibold tracking-[-0.01em] text-white">Token Tuzağı</h4>
          </div>
          {!done && (
            <p className="mt-2 max-w-xl text-sm leading-relaxed text-neutral-300">
              Dosya, sahte ama gerçekçi hesaplarla dolu bir Windows profilinde çalışır: Discord token'ı, tarayıcıda kayıtlı şifreler ve çerezler,
              Steam, Telegram, kripto cüzdanları, panoda bir kripto adresi. Hepsi bu çalıştırmaya özel üretilir. Dosya bunlara dokunursa
              neyi okuduğunu, paketlediğini ve nereye gönderdiğini kanıtıyla gösteririz.
            </p>
          )}
        </div>
        {!status && mine && (
          <LiquidMetalButton label={busy ? 'Kuruluyor…' : 'Tuzağı kur'} width={168} onClick={go} disabled={busy || left === 0}
            icon={busy ? <Loader className="size-4 animate-spin" /> : <Fingerprint className="size-4" />} />
        )}
      </div>
      {!status && mine && left === 0 && <p className="mt-3 text-xs text-neutral-500">Bugünkü tuzak hakkın doldu, yarın yenilenir.</p>}
      {err && <p className="mt-3 text-xs text-amber-400">{err}</p>}
      {running && <Running h={h} />}
      {status === 'error' && <p className="mt-3 text-sm text-neutral-400">Tuzak çalıştırması tamamlanamadı ({result?.error}).{mine ? ' Tekrar denemek için sayfayı yenileyip yeniden kur.' : ''}</p>}

      {done && (
        <div className="mt-3 space-y-3">
          {used.length > 0 && (
            <motion.div initial={{ y: 8, filter: 'blur(6px)' }} animate={{ y: 0, filter: 'blur(0px)' }} transition={spring}
              className="flex items-start gap-3 rounded-xl border border-amber-400/40 bg-amber-400/[0.08] p-3">
              <Siren className="mt-0.5 size-4 shrink-0 text-amber-300" />
              <div className="text-sm text-amber-100">
                <p className="font-semibold">Çalınan bilgi sonradan denendi.</p>
                <p className="mt-1 text-amber-100/80">Tuzaktaki panel şifresi {used.length} kez denendi; ilki çalıştırmadan {ago(used[0].at - (h.finished_at || used[0].at))} sonra
                  {used[0].country ? ` (${used[0].country})` : ''}, {fmtDate(used[0].at)}. Yani çalınan veri gerçekten birine ulaştı.</p>
              </div>
            </motion.div>
          )}
          <p className={cn('text-sm font-medium', h.proof ? 'text-amber-300' : touched ? 'text-amber-200/90' : 'text-neutral-300')}>
            {h.proof ? 'Kanıtlandı: bu dosya hesap bilgisi çalıyor.' : touched ? 'Sahte hesaplarımıza dokundu.' : 'Sahte hesaplara dokunmadı.'}
          </p>
          {!touched && (
            <p className="text-xs leading-relaxed text-neutral-500">
              Bu, dosyanın temiz olduğunu kanıtlamaz: bazı zararlılar dakikalarca bekler, bir komut bekler ya da sanal makineyi fark edip susar.
            </p>
          )}
          {!!h.chains?.length && <ul className="space-y-2">{h.chains.map((c: Chain, i: number) => <ChainRow key={`${c.kind}${i}`} c={c} i={i} />)}</ul>}

          <div className="grid gap-2 sm:grid-cols-2">
            {!!h.reads?.length && (
              <Section icon={<Eye className="size-3.5 text-amber-300" />} title="Okudu">
                {h.reads.map((r: any) => (
                  <div key={r.kind}><span className="text-white">{KIND[r.kind] || r.kind}</span>{r.processes?.length ? <> · {r.processes.join(', ')}</> : null}
                    <div className="mt-0.5 space-y-0.5">{r.files.slice(0, 3).map((f: string) => <div key={f}><Mono>{f}</Mono></div>)}</div>
                  </div>
                ))}
              </Section>
            )}
            {!!h.packed?.length && (
              <Section icon={<FileArchive className="size-3.5 text-amber-300" />} title="Paketledi">
                {h.packed.map((p: any) => (
                  <div key={p.file}><Mono>{p.file}</Mono><div className="mt-0.5 text-neutral-400">{p.archive ? 'Arşiv, içinde: ' : 'İçinde: '}{p.values.join(', ')}</div></div>
                ))}
              </Section>
            )}
            {!!h.sent?.length && (
              <Section icon={<Send className="size-3.5 text-amber-300" />} title="Gönderdi">
                {h.sent.map((s: any, i: number) => (
                  <div key={i}><span className="text-white">{s.host}</span>{s.port ? `:${s.port}` : ''}{s.decrypted ? ' · HTTPS, makinenin TLS anahtarıyla çözüldü' : s.tls ? ' · TLS' : ' · şifresiz'}
                    <div className="mt-0.5 text-neutral-400">{s.values.join(', ')}{s.encodings?.length ? ` (${s.encodings.join(', ')})` : ''}</div>
                    {s.path && <div className="mt-0.5"><Mono>{s.method ? `${s.method} ` : ''}{s.path}</Mono></div>}
                  </div>
                ))}
              </Section>
            )}
            {!!h.uploads?.length && (
              <Section icon={<Send className="size-3.5 text-amber-200/70" />} title="Büyük ihtimalle gönderdi">
                <p className="text-neutral-500">Yemlere dokunduktan sonra şu adreslere veri yolladı; şifreli olduğu için içerik görülemedi.</p>
                {h.uploads.map((u: any) => <div key={u.host + u.port}><span className="text-white">{u.host}</span>:{u.port} · {u.kb} KB{u.exfil_api ? ' · dosya/sohbet API\'si' : ''}</div>)}
              </Section>
            )}
            {!!h.clipboard?.length && (
              <Section icon={<ClipboardPaste className="size-3.5 text-amber-300" />} title="Panodaki adresi değiştirdi">
                {h.clipboard.map((c: any, i: number) => <div key={i}><Mono>{c.expected}</Mono> → <Mono>{c.got}</Mono> · {c.after_s} sn</div>)}
              </Section>
            )}
            {!!(h.endpoints?.webhooks?.length || h.endpoints?.bots?.length) && (
              <Section icon={<Webhook className="size-3.5 text-amber-300" />} title="Saldırganın adresleri">
                {h.endpoints.webhooks.map((w: string) => <div key={w} className="flex items-center gap-1.5"><Webhook className="size-3 text-neutral-500" /><Mono>{w}</Mono></div>)}
                {h.endpoints.bots.map((b: string) => <div key={b} className="flex items-center gap-1.5"><Bot className="size-3 text-neutral-500" /><Mono>Telegram bot {b}</Mono></div>)}
                {!!h.endpoints.chat_ids?.length && <div className="text-neutral-400">Sohbet: {h.endpoints.chat_ids.join(', ')}</div>}
              </Section>
            )}
          </div>
          <p className="text-[11px] leading-relaxed text-neutral-500">
            Yemler sahteydi ve yalnızca bu çalıştırma için üretildi, gerçek bir hesaba ait değil. Okuma kaydı: {h.audit ? 'Windows denetim günlüğü (koruma atlatılsa da çalışır)' : 'yalnızca CAPE izi'}.
            {h.trap_url ? ' Yemlerden biri bizim tuzak giriş sayfamızın şifresi: biri onu denerse burada görünür.' : ''}
          </p>
        </div>
      )}
    </div>
  )
}
