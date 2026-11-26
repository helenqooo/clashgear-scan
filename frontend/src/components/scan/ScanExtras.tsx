// Scan extras (2026-11-16): our static engines (YARA / capa / FLOSS / DIE / PyInstaller / macros / APK), the
// stealer config card, link + hash sources, similar files, version diff, the 1/3/7-day re-checks, the
// "what it changed on the system" card and forum badges.

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Check, Copy, Fingerprint, GitCompare, History, Link2, Radar, ShieldAlert, Smartphone, Wrench } from 'lucide-react'
import { scanApi, type ScanResult, type SimilarFile } from '@/lib/scanApi'
import { useScan } from '@/i18n/scan'
import { cn } from '@/lib/utils'

const Mono = ({ children, className }: { children: ReactNode; className?: string }) => <span className={cn('break-all font-mono text-[12px] text-foreground/85', className)}>{children}</span>
const Chip = ({ children, tone }: { children: ReactNode; tone?: 'warn' | 'bad' | 'good' }) => (
  <span className={cn('inline-block rounded-md px-2 py-0.5 text-xs',
    tone === 'bad' ? 'bg-orange-500/10 text-orange-400' : tone === 'warn' ? 'bg-amber-500/10 text-amber-400' : tone === 'good' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-secondary text-muted-foreground')}>{children}</span>
)
function Card({ title, icon, children, action, className }: { title: ReactNode; icon?: ReactNode; children: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <section className={cn('rounded-2xl border border-border bg-card p-5', className)}>
      <div className="mb-3 flex items-center justify-between gap-2"><h3 className="flex items-center gap-2 font-semibold">{icon}{title}</h3>{action}</div>
      {children}
    </section>
  )
}
const useL = () => { const { lang } = useScan(); return (tr: string, en: string) => (lang === 'tr' ? tr : en) }

const VERDICT_TR: Record<string, [string, string]> = {
  clean: ['Temiz', 'Clean'], malicious: ['Zararlı', 'Malicious'], suspicious: ['Şüpheli', 'Suspicious'], pua: ['Hile aracı / PUA', 'Hack tool / PUA'], unknown: ['Bilinmiyor', 'Unknown'],
}
function VerdictTag({ v }: { v?: string | null }) {
  const { lang } = useScan()
  if (!v) return null
  const tone = v === 'malicious' ? 'bad' : v === 'clean' ? 'good' : v === 'unknown' ? undefined : 'warn'
  return <Chip tone={tone}>{VERDICT_TR[v]?.[lang === 'tr' ? 0 : 1] || v}</Chip>
}

/* ------------------------------------------------------------------ static engines */

export const staticOf = (results: ScanResult[]) => results.find((r) => r.source === 'cgstatic' && r.status === 'done')?.summary || null

const TACTIC_TR: Record<string, string> = {
  'Execution': 'Çalıştırma', 'Persistence': 'Kalıcılık', 'Privilege Escalation': 'Yetki yükseltme', 'Defense Evasion': 'Savunmadan kaçınma',
  'Credential Access': 'Kimlik bilgisi erişimi', 'Discovery': 'Keşif', 'Lateral Movement': 'Yanal hareket', 'Collection': 'Veri toplama',
  'Command and Control': 'Komuta-kontrol', 'Exfiltration': 'Veri sızdırma', 'Impact': 'Etki', 'Initial Access': 'İlk erişim',
}

export function StaticEngines({ results }: { results: ScanResult[] }) {
  const L = useL()
  const { lang } = useScan()
  const r = results.find((x) => x.source === 'cgstatic')
  const s = r?.summary
  const [showAll, setShowAll] = useState(false)
  if (!r || r.status === 'disabled') return null
  if (!s) return (
    <Card title={L('ClashGear statik motorlar', 'ClashGear static engines')} icon={<Wrench className="size-4 text-muted-foreground" />}>
      <p className="text-sm text-muted-foreground">{r.status === 'running' || r.status === 'queued' ? L('YARA, capa ve FLOSS çalışıyor (büyük dosyalarda 2-4 dakika)…', 'YARA, capa and FLOSS are running (2-4 minutes on big files)…') : r.error === 'no_sample' ? L('Dosyanın kendisi yok (yalnızca hash).', 'No sample (hash only).') : L('Çalıştırılamadı', 'Could not run') + (r.error ? ` (${r.error})` : '')}</p>
    </Card>
  )
  const caps: any[] = s.capa?.capabilities || []
  const attack: Record<string, { id: string; name: string }[]> = s.capa?.attack || {}
  const decoded: string[] = [...(s.floss?.decoded || []), ...(s.floss?.stack || []), ...(s.floss?.tight || [])]
  const capsShown = showAll ? caps : caps.slice(0, 24)
  return (
    <>
      <Card title={L('Tanıma (Detect It Easy)', 'Identification (Detect It Easy)')} icon={<Fingerprint className="size-4 text-muted-foreground" />}>
        {!s.die?.length ? <p className="text-sm text-muted-foreground">—</p> : <ul className="space-y-1">{s.die.map((d: any, i: number) => <li key={i} className="text-sm"><span className="text-muted-foreground">{d.type}:</span> {d.name}{d.version ? ` ${d.version}` : ''}</li>)}</ul>}
        <dl className="mt-3 grid grid-cols-[70px_1fr] gap-x-3 gap-y-1 text-xs">
          <dt className="text-muted-foreground">ssdeep</dt><dd><Mono>{s.fuzzy?.ssdeep || '—'}</Mono></dd>
          <dt className="text-muted-foreground">TLSH</dt><dd><Mono>{s.fuzzy?.tlsh || '—'}</Mono></dd>
        </dl>
        {s.pyinstaller && (
          <div className="mt-4 border-t border-border pt-3">
            <h4 className="text-sm font-medium">PyInstaller · Python {s.pyinstaller.python || '?'}</h4>
            <p className="mt-1 text-xs text-muted-foreground">{L('Ana betikler', 'Entry scripts')}: {(s.pyinstaller.scripts || []).filter((x: string) => !/^pyi(boot|_rth)/.test(x)).join(', ') || '—'} · {s.pyinstaller.modules} {L('modül', 'modules')}{s.pyinstaller.encrypted_pyz ? ` · ${L('şifreli PYZ', 'encrypted PYZ')}` : ''}</p>
            {!!s.pyinstaller.notable_modules?.length && <div className="mt-2 flex flex-wrap gap-1">{s.pyinstaller.notable_modules.map((m: string) => <Chip key={m} tone={/cookie|webhook|crypt|telegram|telebot|discord|pynput|keyboard|ImageGrab|pyperclip|pytransform|pyarmor/i.test(m) ? 'warn' : undefined}>{m}</Chip>)}</div>}
          </div>
        )}
        {s.office && (
          <div className="mt-4 border-t border-border pt-3">
            <h4 className="text-sm font-medium">{L('Office makroları', 'Office macros')}</h4>
            {!s.office.macros ? <p className="mt-1 text-xs text-muted-foreground">{L('Makro yok.', 'No macros.')}</p> : (
              <div className="mt-1 space-y-1.5 text-xs">
                {!!s.office.autoexec?.length && <p><span className="text-amber-400">{L('Açılınca çalışan', 'Runs on open')}:</span> {s.office.autoexec.join(', ')}</p>}
                {!!s.office.suspicious?.length && <p><span className="text-amber-400">{L('Şüpheli', 'Suspicious')}:</span> {s.office.suspicious.join(', ')}</p>}
                {!!s.office.iocs?.length && <p><span className="text-muted-foreground">IOC:</span> <Mono>{s.office.iocs.join(' · ')}</Mono></p>}
              </div>
            )}
          </div>
        )}
      </Card>

      <Card title={<>capa · {L('yetenekler', 'capabilities')}{s.capa?.count ? ` · ${s.capa.count}` : ''}</>} icon={<Radar className="size-4 text-muted-foreground" />}>
        {!s.capa ? <p className="text-sm text-muted-foreground">{L('Bu dosya türünde çalışmaz.', 'Not for this file type.')}</p>
          : s.capa.status !== 'done' ? <p className="text-sm text-muted-foreground">{s.capa.status === 'timeout' ? L('Zaman aşımı (çok büyük dosya).', 'Timed out (very large file).') : s.capa.reason === 'packed' ? L('Dosya paketli; capa paketli kodu okuyamaz (açılmış alt dosyalara bakın).', 'Packed; capa cannot read packed code (see the unpacked children).') : L('capa bu dosyayı okuyamadı.', 'capa could not read this file.')}</p>
          : (
            <>
              {!!Object.keys(attack).length && (
                <div className="mb-3 space-y-1.5">
                  {Object.entries(attack).map(([tac, list]) => (
                    <div key={tac} className="flex flex-wrap items-center gap-1 text-xs">
                      <span className="w-40 shrink-0 text-muted-foreground">{lang === 'tr' ? TACTIC_TR[tac] || tac : tac}</span>
                      {list.map((a) => <a key={a.id} href={`https://attack.mitre.org/techniques/${a.id.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener" title={a.name}><Chip>{a.id} {a.name.split(' / ')[0]}</Chip></a>)}
                    </div>
                  ))}
                </div>
              )}
              <ul className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-2">{capsShown.map((c) => <li key={c.name} className="truncate" title={c.namespace}>{c.name}</li>)}</ul>
              {caps.length > 24 && <button type="button" onClick={() => setShowAll((x) => !x)} className="mt-2 text-xs text-muted-foreground hover:text-foreground">{showAll ? L('Daha az', 'Less') : L(`Tümü (${caps.length})`, `All (${caps.length})`)}</button>}
            </>
          )}
      </Card>

      {s.floss && (
        <Card title={<>FLOSS · {L('gizlenmiş stringler', 'obfuscated strings')}{decoded.length ? ` · ${decoded.length}` : ''}</>} icon={<Wrench className="size-4 text-muted-foreground" />}>
          {s.floss.status !== 'done' ? <p className="text-sm text-muted-foreground">{L('FLOSS bu dosyada çalışamadı.', 'FLOSS could not run on this file.')}</p>
            : !decoded.length ? <p className="text-sm text-muted-foreground">{L('Çalışma anında çözülen ya da yığında kurulan string bulunmadı.', 'No decoded or stack-built strings found.')}</p>
              : <div className="max-h-72 overflow-auto rounded-lg bg-secondary/60 p-3"><ul className="space-y-0.5">{decoded.slice(0, 200).map((x, i) => <li key={i}><Mono>{x}</Mono></li>)}</ul></div>}
        </Card>
      )}
      {s.apk && <ApkCard apk={s.apk} />}
    </>
  )
}

function ApkCard({ apk }: { apk: any }) {
  const L = useL()
  return (
    <Card title={L('Android paketi', 'Android package')} icon={<Smartphone className="size-4 text-muted-foreground" />} className="lg:col-span-2">
      <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{L('Uygulama', 'App')}</dt><dd>{apk.app_name || '—'} <span className="text-xs text-muted-foreground">v{apk.version || '?'}</span></dd>
        <dt className="text-muted-foreground">{L('Paket', 'Package')}</dt><dd><Mono>{apk.package}</Mono></dd>
        <dt className="text-muted-foreground">SDK</dt><dd>min {apk.min_sdk || '?'} · target {apk.target_sdk || '?'}</dd>
        <dt className="text-muted-foreground">{L('Bileşenler', 'Components')}</dt><dd>{apk.activities} activity · {apk.services} service · {apk.receivers} receiver · {apk.dex_count} dex</dd>
        {!!apk.frameworks?.length && <><dt className="text-muted-foreground">{L('Altyapı', 'Frameworks')}</dt><dd className="flex flex-wrap gap-1">{apk.frameworks.map((f: string) => <Chip key={f} tone={/Mod Menu|Frida/.test(f) ? 'warn' : undefined}>{f}</Chip>)}</dd></>}
        {apk.certificates?.[0] && <><dt className="text-muted-foreground">{L('İmza', 'Signer')}</dt><dd className="text-xs">{apk.certificates[0].subject}{apk.certificates[0].debug && <span className="ml-2"><Chip tone="warn">{L('debug sertifikası', 'debug certificate')}</Chip></span>}</dd></>}
      </dl>
      {!!apk.dangerous?.length && (
        <div className="mt-3">
          <h4 className="text-sm font-medium">{L('Hassas izinler', 'Sensitive permissions')}</h4>
          <div className="mt-1 flex flex-wrap gap-1">{apk.dangerous.map((p: string) => <Chip key={p} tone={/ACCESSIBILITY|DEVICE_ADMIN|SMS|NOTIFICATION_LISTENER|INSTALL_PACKAGES/.test(p) ? 'bad' : 'warn'}>{p}</Chip>)}</div>
        </div>
      )}
      {!!apk.native_libs?.length && <p className="mt-3 text-xs text-muted-foreground">{L('Yerel kütüphaneler', 'Native libraries')} ({apk.abis?.join(', ')}): <Mono>{apk.native_libs.slice(0, 20).join(', ')}</Mono></p>}
      {!!apk.urls?.length && <div className="mt-3"><h4 className="text-sm font-medium">{L('Koddaki adresler', 'Addresses in code')}</h4><ul className="mt-1 max-h-40 overflow-auto">{apk.urls.slice(0, 30).map((u: string) => <li key={u}><Mono>{u}</Mono></li>)}</ul></div>}
    </Card>
  )
}

/* ------------------------------------------------------------------ stealer card */

const EXFIL_TR: Record<string, [string, string]> = {
  discord_webhook: ['Discord webhook', 'Discord webhook'], telegram_bot: ['Telegram bot token', 'Telegram bot token'], telegram_api: ['Telegram API adresi', 'Telegram API URL'],
  discord_bot_token: ['Discord bot token (olası)', 'Discord bot token (possible)'], file_upload: ['Dosya yükleme servisi', 'File upload service'], paste: ['Paste sitesi', 'Paste site'],
  tunnel: ['Tünel / dinamik DNS', 'Tunnel / dynamic DNS'], request_bin: ['İstek toplayıcı', 'Request bin'], ftp_creds: ['FTP hesabı', 'FTP login'], smtp: ['E-posta sunucusu', 'Mail server'],
}
const TARGET_TR: Record<string, [string, string]> = {
  browser: ['Tarayıcı şifreleri ve çerezleri', 'Browser passwords and cookies'], discord: ['Discord hesabı (token)', 'Discord account (token)'], crypto_wallet: ['Kripto cüzdanları', 'Crypto wallets'],
  telegram: ['Telegram oturumu', 'Telegram session'], steam: ['Steam hesabı', 'Steam account'], games: ['Oyun hesapları (Roblox, Minecraft…)', 'Game accounts (Roblox, Minecraft…)'],
  ftp_vpn: ['FTP / VPN bilgileri', 'FTP / VPN logins'], recon: ['IP ve konum sorgusu', 'IP and location lookup'], anti_analysis: ['Analiz ortamı kontrolü', 'Analysis environment checks'],
  screen_cam: ['Ekran görüntüsü / kamera', 'Screenshot / webcam'], clipboard: ['Pano (kopyalanan metin)', 'Clipboard'],
}

export function StealerCard({ results }: { results: ScanResult[] }) {
  const L = useL()
  const { lang } = useScan()
  const s = staticOf(results)?.stealer
  if (!s || (s.level === 'none' && !s.exfil?.length && !s.families?.length)) return null
  const steal: string[] = s.steal_categories || []
  const extra = Object.keys(s.targets || {}).filter((k) => !steal.includes(k))
  const strong = s.level === 'stealer'
  return (
    <section className={cn('rounded-2xl border p-5', strong ? 'border-orange-500/40 bg-orange-500/[0.06]' : 'border-amber-500/30 bg-amber-500/[0.05]')}>
      <h3 className={cn('flex items-center gap-2 font-semibold', strong ? 'text-orange-300' : 'text-amber-300')}><ShieldAlert className="size-4" /> {strong ? L('Bilgi çalan program izleri (stealer)', 'Stealer traces') : L('Veri toplama izleri', 'Data collection traces')}</h3>
      {!!s.families?.length && <p className="mt-1 text-sm">{L('Tanınan', 'Recognised')}: <span className="font-medium">{s.families.join(', ')}</span></p>}
      {!!s.exfil?.length && (
        <div className="mt-3">
          <h4 className="text-sm font-medium">{L('Çalınan veri şuraya gidiyor', 'Stolen data goes here')}</h4>
          <ul className="mt-1.5 space-y-1">
            {s.exfil.slice(0, 12).map((e: any, i: number) => (
              <li key={i} className="flex flex-wrap items-baseline gap-2 text-xs">
                <span className="w-44 shrink-0 text-muted-foreground">{EXFIL_TR[e.kind]?.[lang === 'tr' ? 0 : 1] || e.kind}</span>
                <Mono className="text-foreground">{e.value}</Mono>
              </li>
            ))}
          </ul>
          {s.exfil.some((e: any) => e.masked) && <p className="mt-2 text-[11px] text-muted-foreground">{L('Webhook ve token\'ların bir kısmı gizlendi: tamamı, sahibi tarafından silinmesine ya da kötüye kullanılmasına yol açar.', 'Webhooks and tokens are partly hidden: the full value lets anyone delete or abuse them.')}</p>}
        </div>
      )}
      {!!steal.length && (
        <div className="mt-3">
          <h4 className="text-sm font-medium">{L('Hedeflediği bilgiler', 'What it targets')}</h4>
          <div className="mt-1.5 flex flex-wrap gap-1">{steal.map((k) => <Chip key={k} tone="bad">{TARGET_TR[k]?.[lang === 'tr' ? 0 : 1] || k}</Chip>)}</div>
        </div>
      )}
      {!!extra.length && <div className="mt-2 flex flex-wrap gap-1">{extra.map((k) => <Chip key={k} tone="warn">{TARGET_TR[k]?.[lang === 'tr' ? 0 : 1] || k}</Chip>)}</div>}
      <p className="mt-3 text-[11px] text-muted-foreground">{L('Kaynak: dosyanın içinden statik olarak çıkarıldı (çalıştırılmadı). Tek başına kesin karar değildir; diğer katmanlarla birlikte değerlendirilir.', 'Extracted statically from the file (not run). Not a verdict on its own; weighed with the other layers.')}</p>
    </section>
  )
}

/* ------------------------------------------------------------------ source (link / hash) */

export function SourceCard({ source }: { source: any }) {
  const L = useL()
  if (!source) return null
  if (source.hash) return (
    <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground"><Fingerprint className="size-3.5" />
      {L('Hash ile tarandı', 'Scanned by hash')} ({source.hash_kind}) · {source.sample ? L(`örnek ${source.sample} üzerinden indirildi, tüm katmanlar çalıştı`, `sample fetched from ${source.sample}, every layer ran`) : L('dosyanın kendisi bulunamadı: yalnızca hash sorguları çalıştı', 'sample not available: hash lookups only')}
    </p>
  )
  if (!source.url) return null
  const final = source.final_url && source.final_url !== source.url ? source.final_url : null
  return (
    <div className="mt-3 rounded-lg border border-border bg-secondary/40 p-3 text-xs">
      <p className="flex items-center gap-1.5 font-medium text-foreground"><Link2 className="size-3.5" /> {L('Bu linkten indirildi', 'Downloaded from this link')}</p>
      <p className="mt-1"><Mono>{source.url}</Mono></p>
      {final && <p className="mt-1 text-muted-foreground">→ <Mono>{final}</Mono></p>}
      <p className="mt-1 text-muted-foreground">{[source.ip && `IP ${source.ip}`, source.server && `server ${source.server}`, source.content_type, source.redirects?.length ? L(`${source.redirects.length} yönlendirme`, `${source.redirects.length} redirects`) : null, source.tls_verified === false ? L('TLS sertifikası doğrulanamadı', 'TLS not verified') : null].filter(Boolean).join(' · ')}</p>
    </div>
  )
}

/* ------------------------------------------------------------------ similar files + diff */

export function SimilarFiles({ jobId, canCompare }: { jobId: string; canCompare: boolean }) {
  const L = useL()
  const { date } = useScan()
  const [list, setList] = useState<SimilarFile[] | null>(null)
  useEffect(() => { scanApi.similar(jobId).then((d) => setList(d.similar)).catch(() => setList([])) }, [jobId])
  return (
    <Card title={L('Benzer dosyalar', 'Similar files')} icon={<GitCompare className="size-4 text-muted-foreground" />}>
      <p className="-mt-1 mb-3 text-xs text-muted-foreground">{L('ClashGear\'da daha önce taranmış dosyalar arasında TLSH, ssdeep ve import hash benzerliği. Başkalarının dosyalarının adı gösterilmez.', 'TLSH, ssdeep and import-hash neighbours among files ClashGear scanned before. Other people\'s file names are hidden.')}</p>
      {!list ? <p className="text-sm text-muted-foreground">{L('Aranıyor…', 'Searching…')}</p> : !list.length ? <p className="text-sm text-muted-foreground">{L('Benzer dosya yok.', 'No similar files.')}</p> : (
        <ul className="divide-y divide-border">
          {list.map((f, i) => (
            <li key={f.id || i} className="flex flex-wrap items-center gap-3 py-2.5">
              <span className="w-12 shrink-0 text-right font-semibold tabular-nums">%{f.similarity}</span>
              <div className="min-w-0 flex-1">
                {f.id ? <Link to={`/scan/r/${f.id}`} className="block truncate text-sm hover:underline">{f.file_name}</Link> : <p className="text-sm text-muted-foreground">{L('Başka bir kullanıcının dosyası', 'Another user\'s file')}</p>}
                <p className="text-[11px] text-muted-foreground">{date(f.created_at)}{f.tlsh_distance != null ? ` · TLSH ${f.tlsh_distance}` : ''}{f.ssdeep ? ` · ssdeep ${f.ssdeep}` : ''}{f.imphash ? ' · imphash' : ''}{f.family ? ` · ${f.family}` : ''}</p>
              </div>
              <VerdictTag v={f.verdict} />
              {canCompare && f.id && <Link to={`/scan/diff/${f.id}/${jobId}`} className="press rounded-full border border-white/10 px-2.5 py-1 text-[11px] text-neutral-200 hover:bg-white/[0.06]">{L('Karşılaştır', 'Compare')}</Link>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

const DIFF_LABEL: Record<string, [string, string]> = {
  imports: ['İçe aktarılan API\'ler', 'Imported APIs'], sections: ['Bölümler', 'Sections'], urls: ['URL\'ler', 'URLs'], ips: ['IP\'ler', 'IPs'], domains: ['Alan adları', 'Domains'],
  yara: ['YARA kuralları', 'YARA rules'], capabilities: ['capa yetenekleri', 'capa capabilities'], exfil: ['Veri çıkış yolları', 'Exfiltration channels'], steals: ['Hedeflenen bilgiler', 'Targeted data'],
  behaviour: ['Sandbox davranışı', 'Sandbox behaviour'], signatures: ['Sandbox imzaları', 'Sandbox signatures'], packers: ['Paketleyici', 'Packers'], python_modules: ['Python modülleri', 'Python modules'], apk_permissions: ['Android izinleri', 'Android permissions'],
}
const ALERT_TR: Record<string, [string, string]> = {
  new_exfil: ['Yeni sürümde veri gönderme yolu var', 'The new version has a new way to send data out'], new_targets: ['Yeni sürüm yeni bilgileri hedefliyor', 'The new version targets new data'],
  new_behaviour: ['Sandbox\'ta yeni davranış', 'New sandbox behaviour'], signature_lost: ['Dijital imza kaldırılmış', 'The digital signature was removed'],
  new_hosts: ['Yeni bağlandığı adresler', 'New hosts'], verdict_worse: ['Karar kötüleşti', 'The verdict got worse'],
}

export function DiffView({ a, b }: { a: string; b: string }) {
  const L = useL()
  const { lang, date } = useScan()
  const [d, setD] = useState<any>(null)
  const [err, setErr] = useState(false)
  useEffect(() => { scanApi.diff(a, b).then(setD).catch(() => setErr(true)) }, [a, b])
  if (err) return <p className="text-sm text-muted-foreground">{L('Karşılaştırma açılamadı (iki rapor da sizin ya da paylaşılmış olmalı).', 'Could not compare (both reports must be yours or shared).')}</p>
  if (!d) return <p className="text-sm text-muted-foreground">{L('Yükleniyor…', 'Loading…')}</p>
  const rows = (['verdict', 'score', 'family', 'type', 'size', 'compiled_at', 'signed', 'signer'] as const).filter((k) => d[k]?.changed)
  const lists = Object.keys(DIFF_LABEL).filter((k) => d[k] && (d[k].added.length || d[k].removed.length))
  const fmt = (v: any) => (v === true ? '✓' : v === false ? '—' : v == null || v === '' ? '—' : typeof v === 'string' && VERDICT_TR[v] ? VERDICT_TR[v][lang === 'tr' ? 0 : 1] : String(v))
  return (
    <div className="grid gap-4">
      <div className="grid gap-3 sm:grid-cols-[1fr_auto_1fr] sm:items-center">
        {[d.a, d.b].map((x: any, i: number) => (
          <Link key={x.id} to={`/scan/r/${x.id}`} className={cn('rounded-2xl border border-border bg-card p-4 hover:bg-white/[0.03]', i === 1 && 'sm:order-3')}>
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{i === 0 ? L('Eski', 'Older') : L('Yeni', 'Newer')} · {date(x.created_at)}</p>
            <p className="mt-1 truncate font-medium">{x.file_name}</p>
            <Mono className="text-[11px] text-muted-foreground">{x.sha256}</Mono>
          </Link>
        ))}
        <ArrowRight className="mx-auto hidden size-5 text-muted-foreground sm:order-2 sm:block" />
      </div>
      {!!d.alerts?.length && (
        <section className="rounded-2xl border border-orange-500/40 bg-orange-500/[0.06] p-5">
          <h3 className="flex items-center gap-2 font-semibold text-orange-300"><ShieldAlert className="size-4" /> {L('Dikkat edilmesi gerekenler', 'What to look at')}</h3>
          <ul className="mt-2 space-y-1 text-sm">{d.alerts.map((x: any) => <li key={x.code}>{ALERT_TR[x.code]?.[lang === 'tr' ? 0 : 1] || x.code}{x.items?.length ? <span className="text-muted-foreground">: {x.items.join(', ')}</span> : null}</li>)}</ul>
        </section>
      )}
      <Card title={L('Değişen bilgiler', 'Changed facts')}>
        {!rows.length ? <p className="text-sm text-muted-foreground">{L('Karar, aile, imza ve derleme bilgisi aynı.', 'Verdict, family, signature and build info are the same.')}</p> : (
          <table className="w-full text-sm"><tbody>{rows.map((k) => (
            <tr key={k} className="border-t border-border first:border-t-0"><td className="py-1.5 pr-3 text-muted-foreground">{k}</td><td className="py-1.5 pr-3">{fmt(d[k].before)}</td><td className="py-1.5 pr-3 text-muted-foreground">→</td><td className="py-1.5 font-medium">{fmt(d[k].after)}</td></tr>
          ))}</tbody></table>
        )}
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        {lists.map((k) => (
          <Card key={k} title={<>{DIFF_LABEL[k][lang === 'tr' ? 0 : 1]} <span className="text-xs font-normal text-muted-foreground">+{d[k].added.length} / −{d[k].removed.length} · {d[k].same} {L('aynı', 'same')}</span></>}>
            <ul className="max-h-64 space-y-0.5 overflow-auto">
              {d[k].added.map((x: string) => <li key={'+' + x}><Mono className="text-emerald-400">+ {x}</Mono></li>)}
              {d[k].removed.map((x: string) => <li key={'-' + x}><Mono className="text-muted-foreground line-through">− {x}</Mono></li>)}
            </ul>
          </Card>
        ))}
      </div>
      {!lists.length && <p className="text-sm text-muted-foreground">{L('Listelerde fark yok.', 'No differences in the lists.')}</p>}
    </div>
  )
}

/* ------------------------------------------------------------------ 1/3/7-day re-checks */

export function WatchCard({ watch }: { watch: any }) {
  const L = useL()
  const { date, lang } = useScan()
  if (!watch) return null
  const name = (v?: string) => (v ? VERDICT_TR[v]?.[lang === 'tr' ? 0 : 1] || v : '—')
  return (
    <Card title={L('Yeniden kontrol', 'Re-checks')} icon={<History className="size-4 text-muted-foreground" />}>
      <p className="-mt-1 text-xs text-muted-foreground">{L('Antivirüsler yeni örnekleri günler içinde tanır. Bu dosya 1, 3 ve 7 gün sonra hash ile yeniden sorgulanır; karar değişirse burada görünür.', 'Antivirus engines learn new samples over days. This file is looked up again after 1, 3 and 7 days; a changed verdict shows here.')}</p>
      <ul className="mt-3 space-y-1.5 text-sm">
        {watch.history.map((h: any, i: number) => (
          <li key={i} className="flex flex-wrap items-center gap-2">
            <span className="w-16 text-muted-foreground">{h.day}. {L('gün', 'day')}</span>
            {h.skipped || !h.after ? <span className="text-muted-foreground">—</span> : h.after.verdict !== h.before.verdict
              ? <span className="font-medium text-amber-300">{name(h.before.verdict)} → {name(h.after.verdict)} ({h.before.score} → {h.after.score})</span>
              : <span className="text-muted-foreground">{L('değişmedi', 'unchanged')} · {name(h.after.verdict)} {h.after.score}/100</span>}
            {h.vt?.total ? <span className="text-xs text-muted-foreground">· VT {h.vt.malicious}/{h.vt.total}</span> : null}
          </li>
        ))}
        {watch.next_at && <li className="text-xs text-muted-foreground">{L('Sıradaki kontrol', 'Next check')}: {date(watch.next_at)}</li>}
        {!watch.next_at && !watch.history.length && <li className="text-xs text-muted-foreground">—</li>}
      </ul>
    </Card>
  )
}

/* ------------------------------------------------------------------ system changes */

const AUTORUN = /\\CurrentVersion\\(Run|RunOnce|RunServices|Policies\\Explorer\\Run)\\|\\Winlogon\\(Shell|Userinit)|\\Image File Execution Options\\[^\\]+\\Debugger|\\Services\\[^\\]+\\(ImagePath|Start)$/i
const DEFENDER = /\\Windows Defender\\(Exclusions|Real-Time Protection|Features|Spynet)|DisableAntiSpyware|DisableRealtimeMonitoring|\\Policies\\Microsoft\\Windows Defender/i
const SECURITY = /\\Policies\\System\\(EnableLUA|ConsentPromptBehaviorAdmin)|\\FirewallPolicy\\|\\SystemCertificates\\(ROOT|AuthRoot)\\Certificates|\\Internet Settings\\(ProxyServer|ProxyEnable|AutoConfigURL)/i
const FILE_HIT: [RegExp, string, string][] = [
  [/\\Start Menu\\Programs\\Startup\\/i, 'Başlangıç klasörüne dosya koydu', 'Dropped a file in the Startup folder'],
  [/\\System32\\Tasks\\|\\Windows\\Tasks\\/i, 'Zamanlanmış görev oluşturdu', 'Created a scheduled task'],
  [/\\drivers\\etc\\hosts$/i, 'hosts dosyasını değiştirdi', 'Changed the hosts file'],
  [/\\Windows\\(System32|SysWOW64)\\[^\\]+\.(exe|dll|sys)$/i, 'Windows sistem klasörüne dosya yazdı', 'Wrote a file into the Windows system folder'],
]
const CMD_HIT: [RegExp, string, string][] = [
  [/schtasks(\.exe)?\s+\/create/i, 'Zamanlanmış görev komutu', 'Scheduled task command'],
  [/\bsc(\.exe)?\s+(create|config)\b/i, 'Servis kurma komutu', 'Service install command'],
  [/Add-MpPreference|Set-MpPreference/i, 'Defender ayarını değiştirme komutu', 'Defender setting command'],
  [/netsh\s+(advfirewall|firewall)/i, 'Güvenlik duvarı kuralı komutu', 'Firewall rule command'],
  [/vssadmin\s+delete|wbadmin\s+delete|bcdedit/i, 'Yedek / kurtarma silme komutu', 'Backup / recovery deletion command'],
  [/net\s+user\s+\S+\s+\S+\s+\/add/i, 'Yeni kullanıcı ekleme komutu', 'New user command'],
  [/reg(\.exe)?\s+add\s+\S*\\(Run|RunOnce)\b/i, 'Otomatik başlatma kaydı komutu', 'Autorun registry command'],
]

export function SystemChanges({ results, behaviour }: { results: ScanResult[]; behaviour?: { id: string; sources: string[]; examples: string[] }[] }) {
  const L = useL()
  const { lang } = useScan()
  const items = useMemo(() => {
    const out: { kind: string; label: string; detail: string; who: string }[] = []
    const seen = new Set<string>()
    const add = (kind: string, label: string, detail: string, who: string) => { const k = kind + detail; if (!seen.has(k) && out.length < 40) { seen.add(k); out.push({ kind, label, detail, who }) } }
    for (const r of results) {
      if (r.status !== 'done') continue
      for (const p of r.summary?.activity?.processes || []) {
        if (/^(explorer|svchost|dllhost|wmiprvse|tiworker|trustedinstaller|msmpeng|services|lsass|csrss|winlogon)\.exe$/i.test(p.name || '')) continue
        for (const w of p.registry?.written || []) {
          if (AUTORUN.test(w.key)) add('persist', L('Bilgisayar açılınca çalışacak şekilde kendini ekledi', 'Added itself to run at startup'), `${w.key}${w.data ? ` = ${w.data}` : ''}`, p.name)
          else if (DEFENDER.test(w.key)) add('defender', L('Windows Defender ayarını değiştirdi', 'Changed a Windows Defender setting'), w.key, p.name)
          else if (SECURITY.test(w.key)) add('security', L('Güvenlik / ağ ayarını değiştirdi', 'Changed a security / network setting'), w.key, p.name)
        }
        for (const f of p.files?.written || []) for (const [re, tr, en] of FILE_HIT) if (re.test(f)) add('file', lang === 'tr' ? tr : en, f, p.name)
        for (const [re, tr, en] of CMD_HIT) if (re.test(p.command_line || '')) add('cmd', lang === 'tr' ? tr : en, p.command_line, p.name)
      }
      for (const svc of r.summary?.activity?.services || []) add('service', L('Servis oluşturdu / başlattı', 'Created / started a service'), svc, r.source)
    }
    for (const b of behaviour || []) {
      if (!['persistence', 'defense_evasion', 'ransomware'].includes(b.id)) continue
      for (const ex of b.examples) add('sig:' + b.id, b.id === 'persistence' ? L('Kalıcılık (sandbox imzası)', 'Persistence (sandbox signature)') : b.id === 'ransomware' ? L('Dosya şifreleme / yedek silme (sandbox imzası)', 'Encryption / backup deletion (sandbox signature)') : L('Güvenliği kapatma (sandbox imzası)', 'Disabling security (sandbox signature)'), ex, b.sources.join(', '))
    }
    return out
  }, [results, behaviour, L, lang])
  const ran = results.some((r) => r.layer === 8 && r.status === 'done' && r.source !== 'honey')
  if (!ran) return null
  return (
    <Card title={L('Sistemde ne değiştirdi?', 'What did it change on the system?')} icon={<Wrench className="size-4 text-muted-foreground" />}>
      {!items.length ? <p className="text-sm text-emerald-400/90">{L('Sandbox çalıştırmalarında başlangıç kaydı, servis, zamanlanmış görev, Defender ya da güvenlik ayarı değişikliği görülmedi.', 'No startup entries, services, scheduled tasks, Defender or security changes were seen in the sandbox runs.')}</p> : (
        <ul className="space-y-2">
          {items.map((x, i) => (
            <li key={i} className="text-sm">
              <p className={cn('font-medium', /persist|defender|security|sig:/.test(x.kind) ? 'text-amber-300' : 'text-foreground')}>{x.label} <span className="text-xs font-normal text-muted-foreground">· {x.who}</span></p>
              <Mono className="text-[11.5px] text-muted-foreground">{x.detail}</Mono>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

/* ------------------------------------------------------------------ forum post kit */

type Kit = { link: string; image: string; card: string; badge_bbcode: string; bbcode: string; markdown: string; html: string }
/** The detailed forum post of a shared report (card image, verdict, short report, technical spoiler, link) and the bare badge. */
export function BadgeSnippets({ id }: { id: string }) {
  const L = useL()
  const [kit, setKit] = useState<Kit | null>(null)
  const [which, setWhich] = useState<'bbcode' | 'badge_bbcode' | 'markdown' | 'html'>('bbcode')
  const [copied, setCopied] = useState(false)
  useEffect(() => { scanApi.shareKit(id).then(setKit).catch(() => setKit(null)) }, [id])
  if (!kit) return <p className="mt-3 text-[11px] text-muted-foreground">{L('Forum gönderisi hazırlanıyor…', 'Preparing the forum post…')}</p>
  const text = kit[which]
  const copy = () => navigator.clipboard?.writeText(text).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }).catch(() => {})
  const TABS: [typeof which, string][] = [['bbcode', L('Detaylı BBCode', 'Detailed BBCode')], ['badge_bbcode', L('Sadece rozet', 'Badge only')], ['markdown', 'Markdown'], ['html', 'HTML']]
  return (
    <div className="mt-3 border-t border-white/10 pt-3">
      <p className="text-[12px] font-semibold text-foreground">{L('Forum gönderisi', 'Forum post')}</p>
      <img src={which === 'badge_bbcode' ? kit.image : kit.card} alt="ClashGear Scan" className="mt-2 w-full rounded-lg border border-white/10" />
      <div className="mt-2 flex flex-wrap gap-1">
        {TABS.map(([k, label]) => <button key={k} type="button" onClick={() => setWhich(k)} className={cn('rounded-md px-2 py-0.5 text-[11px]', which === k ? 'bg-[#D1FE17] text-black' : 'bg-white/5 text-neutral-300 hover:bg-white/10')}>{label}</button>)}
      </div>
      <textarea readOnly value={text} onFocus={(e) => e.currentTarget.select()} rows={which === 'bbcode' || which === 'markdown' ? 7 : 3}
        className="mt-2 w-full resize-none rounded-lg border border-white/10 bg-black/40 p-2.5 font-mono text-[11px] leading-relaxed text-neutral-300 outline-none" />
      <button type="button" onClick={copy} className="press mt-2 flex h-9 w-full items-center justify-center gap-1.5 rounded-lg bg-[#D1FE17] text-[12px] font-semibold text-black">
        {copied ? <><Check className="size-3.5" /> {L('Kopyalandı', 'Copied')}</> : <><Copy className="size-3.5" /> {L('Kopyala', 'Copy')}</>}
      </button>
      <p className="mt-1.5 text-[11px] text-muted-foreground">{L('Konunuza yapıştırın: rapor kartı, karar, kısa rapor, teknik ayrıntılar ve analiz linki gelir. Kart ve rozet raporun güncel kararını gösterir.', 'Paste it in your thread: report card, verdict, short report, technical details and the analysis link. The card and badge always show the current verdict.')}</p>
    </div>
  )
}

/* ------------------------------------------------------------------ CAPE: Suricata + memory YARA */

export function CapeExtras({ s }: { s: any }) {
  const L = useL()
  const alerts: any[] = s?.suricata || []
  const mem: string[] = s?.memory_yara || []
  if (!alerts.length && !mem.length) return null
  const bad = (sig: string) => /^ET (MALWARE|TROJAN|CNC|EXPLOIT|PHISHING|MOBILE_MALWARE|ATTACK_RESPONSE)/i.test(sig)
  return (
    <div className="mt-4 grid gap-4 border-t border-border pt-3 lg:grid-cols-2">
      {!!alerts.length && (
        <div>
          <h4 className="mb-1.5 text-sm font-medium">{L('Ağ trafiği kuralları (Suricata)', 'Network rules (Suricata)')}</h4>
          <ul className="space-y-1">{alerts.slice(0, 20).map((a) => (
            <li key={a.signature} className="text-xs"><span className={bad(a.signature) ? 'text-orange-400' : 'text-muted-foreground'}>{a.signature}</span>{a.dst ? <span className="text-muted-foreground"> · {a.dst}{a.port ? `:${a.port}` : ''}</span> : null}</li>
          ))}</ul>
        </div>
      )}
      {!!mem.length && (
        <div>
          <h4 className="mb-1.5 text-sm font-medium">{L('Bellek dökümünde YARA', 'YARA on memory dumps')}</h4>
          <div className="flex flex-wrap gap-1">{mem.map((m) => <Chip key={m} tone={/^(MAL|MALWARE|CRIME|APT|RANSOM)_/i.test(m) ? 'bad' : undefined}>{m}</Chip>)}</div>
          <p className="mt-1.5 text-[11px] text-muted-foreground">{L('Paketli dosyalar bellekte açıldıktan sonra taranır; diskteki dosyada görünmeyen kod burada yakalanır.', 'Packed files are scanned after they unpack in memory: code invisible on disk shows up here.')}</p>
        </div>
      )}
    </div>
  )
}
