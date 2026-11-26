// Share kit for public reports (2026-11-16): a compact badge, a report card image and a detailed forum post
// (BBCode / Markdown / HTML) with the verdict, a short report and the link to the full analysis.
// Look: dark, Higgsfield lime (#D1FE17) in soft gradients.

import { Resvg } from '@resvg/resvg-js'
import { listResults, childJobs } from './db.js'

const SITE = 'https://clashgear.shop'
const LIME = '#D1FE17'
const VERDICT_TR = { clean: 'Temiz', malicious: 'Zararlı', suspicious: 'Şüpheli', pua: 'Hile aracı / PUA', unknown: 'Bilinmiyor', running: 'Analiz sürüyor' }
// On the dark images: clean stays brand lime; warnings amber; malicious a warm orange-red (no pure red accents).
const IMG_COLOR = { clean: LIME, malicious: '#FF6B3D', suspicious: '#F5B83D', pua: '#F5B83D', unknown: '#A3A3A3', running: '#A3A3A3' }
// In forum text (light and dark themes): readable greens / ambers.
const TXT_COLOR = { clean: '#5FA800', malicious: '#E4572E', suspicious: '#D29922', pua: '#D29922', unknown: '#8B949E' }
const BEHAVIOUR_TR = { credential_theft: 'bilgi çalma', ransomware: 'fidye / şifreleme', injection: 'başka süreçlere kod enjekte etme', persistence: 'kalıcılık', defense_evasion: 'güvenliği kapatma', c2: 'komuta sunucusu bağlantısı', download_execute: 'dosya indirip çalıştırma' }
const STEAL_TR = { browser: 'tarayıcı şifreleri', discord: 'Discord token', crypto_wallet: 'kripto cüzdanları', telegram: 'Telegram oturumu', steam: 'Steam hesabı', games: 'oyun hesapları', ftp_vpn: 'FTP/VPN bilgileri' }
const TACTIC_TR = { 'Execution': 'Çalıştırma', 'Persistence': 'Kalıcılık', 'Privilege Escalation': 'Yetki yükseltme', 'Defense Evasion': 'Savunmadan kaçınma', 'Credential Access': 'Kimlik bilgisi erişimi', 'Discovery': 'Keşif', 'Collection': 'Veri toplama', 'Command and Control': 'Komuta-kontrol', 'Exfiltration': 'Veri sızdırma', 'Impact': 'Etki', 'Lateral Movement': 'Yanal hareket', 'Initial Access': 'İlk erişim' }
const SANDBOXES = ['cape', 'hybrid_sandbox', 'triage', 'threatzone', 'joe', 'vmray', 'anyrun', 'vt_sandbox']

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const bb = (s) => String(s ?? '').replace(/\[/g, '(').replace(/\]/g, ')')
const fmtSize = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`)
const dateTr = (t) => new Date(t).toLocaleDateString('tr-TR', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'Europe/Istanbul' })
const cut = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s }
function wrap(text, width, lines) {
  const out = []
  let cur = ''
  for (const w of String(text || '').replace(/\s+/g, ' ').trim().split(' ')) {
    if ((cur + ' ' + w).trim().length > width) { out.push(cur); cur = w; if (out.length === lines) break } else cur = (cur + ' ' + w).trim()
  }
  if (out.length < lines && cur) out.push(cur)
  if (out.length === lines && text.length > out.join(' ').length + 1) out[lines - 1] = cut(out[lines - 1], width - 1) + (out[lines - 1].endsWith('…') ? '' : '…')
  return out
}

/** Everything the badge, the card and the post say, from the stored report. */
export function reportFacts(job) {
  const results = listResults(job.id)
  const done = (src) => results.find((r) => r.source === src && r.status === 'done')?.summary || null
  const comp = job.ai?.computed || {}
  const ai = job.ai || {}
  const st = job.static || {}
  const cs = done('cgstatic')
  const v = job.status === 'done' ? job.verdict || 'unknown' : 'running'
  const sandboxes = results.filter((r) => SANDBOXES.includes(r.source) && r.status === 'done')
  const behaviour = (comp.behaviour || []).map((b) => BEHAVIOUR_TR[b.id] || b.id)
  const signer = cs?.signature?.verified === 'Signed' ? cs.signature.signers : results.map((r) => r.summary?.signature).find((s) => s?.verified === 'Signed')?.signers || null
  const sigText = signer ? `Doğrulandı: ${String(signer).split(';')[0].trim()}` : cs?.signature_check?.verified === 'Invalid' ? 'Geçersiz imza' : st.pe ? 'İmzasız' : '—'
  const tactics = Object.keys(cs?.capa?.attack || {}).map((t) => TACTIC_TR[t] || t)
  const steal = (cs?.stealer?.steal_categories || []).map((k) => STEAL_TR[k] || k)
  const exfil = (cs?.stealer?.exfil || []).map((e) => e.kind)
  const kids = childJobs(job.id)
  const reasons = comp.reasons || []
  const headline = ai.headline_tr || (v === 'clean' ? 'Zararlı bir davranış ya da tespit bulunmadı.' : v === 'malicious' ? `Zararlı: ${comp.family || 'birden fazla kaynak bu dosyayı zararlı buldu'}.` : v === 'pua' ? 'Hile aracı / istenmeyen program olarak işaretlendi.' : v === 'suspicious' ? 'Bazı kaynaklar şüpheli buldu; kesin kanıt yok.' : 'Analiz sürüyor.')
  const summary = ai.summary_tr || ''
  const findings = (ai.key_findings_tr || []).slice(0, 4)
  if (!findings.length) {
    if (behaviour.length) findings.push(`Sandbox'ta görülen: ${behaviour.join(', ')}.`)
    if (steal.length) findings.push(`Hedeflediği bilgiler: ${steal.join(', ')}.`)
    if (comp.engines) findings.push(`${comp.engines} antivirüs motorundan ${comp.detected || 0} tanesi tespit etti.`)
    if (signer) findings.push(`Dijital imza geçerli: ${String(signer).split(';')[0].trim()}.`)
    if (reasons.some((r) => r.code === 'known_good')) findings.push('Bilinen güvenilir yazılım listelerinde var.')
  }
  return {
    id: job.id, link: `${SITE}/scan/r/${job.id}`, name: job.file_name, size: job.size, type: st.pe ? `${st.type?.toUpperCase()} ${st.pe.bits}-bit${st.pe.dotnet ? ' .NET' : ''}${st.pe.dll ? ' DLL' : ''}` : String(st.type || 'dosya').toUpperCase(),
    sha256: job.sha256, md5: job.md5, at: job.finished_at || job.created_at,
    verdict: v, verdictTr: VERDICT_TR[v] || v, score: job.score ?? null, family: comp.family || ai.family || null,
    av: comp.engines ? `${comp.detected || 0}/${comp.engines}` : '—',
    sandbox: !sandboxes.length ? 'Çalıştırılmadı' : behaviour.length ? `${behaviour.length} zararlı davranış` : `${sandboxes.length} sandbox · temiz`,
    sandboxCount: sandboxes.length, behaviour, sigText, signer,
    yara: (cs?.yara || []).filter((y) => y.family).map((y) => y.rule).slice(0, 4),
    capa: cs?.capa?.count || 0, tactics, steal, exfil,
    packer: [...(st.pe?.packer_hints || []), ...((cs?.die || []).filter((d) => /packer|protector/i.test(d.type)).map((d) => d.name))].filter(Boolean)[0] || null,
    children: kids.length, badKids: kids.filter((k) => k.verdict === 'malicious').length,
    domains: [...new Set(results.filter((r) => r.layer === 9 && r.status === 'done').flatMap((r) => (r.summary?.items || []).filter((x) => (x.source_name === 'VirusTotal' ? x.malicious >= 3 : x.malicious)).map((x) => x.ioc)))].slice(0, 5),
    source: job.source?.url || null,
    headline, summary, findings,
  }
}

/* ------------------------------------------------------------------ images */

const FONT = 'Segoe UI, Inter, Helvetica, Arial, sans-serif'
const defs = (id, color) => `<defs>
  <radialGradient id="${id}a" cx="12%" cy="0%" r="75%"><stop offset="0" stop-color="${LIME}" stop-opacity="0.34"/><stop offset="0.55" stop-color="${LIME}" stop-opacity="0.07"/><stop offset="1" stop-color="${LIME}" stop-opacity="0"/></radialGradient>
  <radialGradient id="${id}b" cx="100%" cy="100%" r="70%"><stop offset="0" stop-color="${color}" stop-opacity="0.20"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></radialGradient>
  <linearGradient id="${id}s" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${LIME}" stop-opacity="0.55"/><stop offset="0.5" stop-color="#ffffff" stop-opacity="0.08"/><stop offset="1" stop-color="${color}" stop-opacity="0.35"/></linearGradient>
</defs>`
const logo = (x, y, s, color) => `<g transform="translate(${x} ${y}) scale(${s})"><path d="M14 0 L27 7.5 V20.5 L14 28 L1 20.5 V7.5 Z" fill="${LIME}" fill-opacity="0.12" stroke="${LIME}" stroke-width="2"/><path d="M8.5 14.5 l3.8 3.8 l7.4 -8.2" fill="none" stroke="${color}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></g>`

export function badgeSvg(job) {
  const f = reportFacts(job)
  const color = IMG_COLOR[f.verdict]
  const label = f.verdict === 'running' ? 'Analiz sürüyor' : `${f.verdictTr} · ${f.score ?? 0}/100`
  const W = 440, H = 68, pillW = Math.max(124, label.length * 8.3 + 36)
  const date = new Date(f.at).toLocaleDateString('tr-TR', { timeZone: 'Europe/Istanbul' })
  const room = Math.max(8, Math.floor((W - pillW - 14 - 62 - 12) / 6.6) - date.length - 3)
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="ClashGear Scan: ${esc(label)}">
<title>ClashGear Scan: ${esc(label)}</title>${defs('g', color)}
<rect width="${W}" height="${H}" rx="14" fill="#0A0A0A"/><rect width="${W}" height="${H}" rx="14" fill="url(#ga)"/><rect width="${W}" height="${H}" rx="14" fill="url(#gb)"/>
<rect x="0.75" y="0.75" width="${W - 1.5}" height="${H - 1.5}" rx="13.25" fill="none" stroke="url(#gs)" stroke-width="1.5"/>
${logo(16, 20, 1, color)}
<text x="60" y="30" font-family="${FONT}" font-size="15.5" font-weight="700" fill="#F5F5F5">ClashGear Scan</text>
<text x="60" y="49" font-family="${FONT}" font-size="11.5" fill="#A3A3A3">${esc(cut(f.name, room))} · ${esc(date)}</text>
<rect x="${W - pillW - 14}" y="18" width="${pillW}" height="32" rx="16" fill="${color}" fill-opacity="0.13" stroke="${color}" stroke-opacity="0.6"/>
<text x="${W - 14 - pillW / 2}" y="39" text-anchor="middle" font-family="${FONT}" font-size="13.5" font-weight="650" fill="${color}">${esc(label)}</text>
</svg>`
}

/** 1000×520 report card for forum posts (and link previews). */
export function cardSvg(job) {
  const f = reportFacts(job)
  const color = IMG_COLOR[f.verdict]
  const W = 1000, H = 520
  const score = f.score ?? 0
  const R = 62, C = 2 * Math.PI * R, dash = (score / 100) * C
  const stats = [
    ['Antivirüs', f.av, f.av !== '—' && !/^0\//.test(f.av)],
    ['Sandbox', f.sandbox, f.behaviour.length > 0],
    ['Dijital imza', cut(f.sigText, 26), /Geçersiz/.test(f.sigText)],
    ['Aile', cut(f.family || '—', 24), !!f.family],
  ]
  const head = wrap(f.headline, 66, 2)
  const lines = (f.findings.length ? f.findings : [f.summary]).filter(Boolean).slice(0, 3).map((x) => cut(x, 92))
  const meta = [f.type, fmtSize(f.size), f.capa ? `capa ${f.capa} yetenek` : null, f.tactics.length ? `ATT&CK: ${f.tactics.slice(0, 3).join(', ')}` : null].filter(Boolean).join('  ·  ')
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
${defs('c', color)}
<rect width="${W}" height="${H}" rx="26" fill="#0A0A0A"/><rect width="${W}" height="${H}" rx="26" fill="url(#ca)"/><rect width="${W}" height="${H}" rx="26" fill="url(#cb)"/>
<rect x="1" y="1" width="${W - 2}" height="${H - 2}" rx="25" fill="none" stroke="url(#cs)" stroke-width="2"/>
${logo(40, 36, 1.25, color)}
<text x="86" y="62" font-family="${FONT}" font-size="22" font-weight="700" fill="#F5F5F5">ClashGear Scan</text>
<text x="${W - 40}" y="62" text-anchor="end" font-family="${FONT}" font-size="15" fill="#8A8A8A">Tehdit analizi raporu · ${esc(dateTr(f.at))}</text>
<text x="40" y="124" font-family="${FONT}" font-size="30" font-weight="700" fill="#FFFFFF">${esc(cut(f.name, 52))}</text>
<text x="40" y="154" font-family="${FONT}" font-size="15" fill="#9A9A9A">${esc(cut(meta, 110))}</text>
<g transform="translate(118 268)">
  <circle r="${R}" fill="none" stroke="#FFFFFF" stroke-opacity="0.08" stroke-width="12"/>
  <circle r="${R}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${dash.toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90)"/>
  <text y="10" text-anchor="middle" font-family="${FONT}" font-size="38" font-weight="750" fill="#FFFFFF">${score}</text>
  <text y="32" text-anchor="middle" font-family="${FONT}" font-size="12" fill="#8A8A8A">/ 100</text>
</g>
<rect x="56" y="350" width="124" height="34" rx="17" fill="${color}" fill-opacity="0.14" stroke="${color}" stroke-opacity="0.6"/>
<text x="118" y="373" text-anchor="middle" font-family="${FONT}" font-size="15" font-weight="700" fill="${color}">${esc(cut(f.verdictTr, 14))}</text>
${stats.map(([k, val, warn], i) => {
    const x = 230 + i * 186
    return `<rect x="${x}" y="196" width="172" height="76" rx="16" fill="#FFFFFF" fill-opacity="0.04" stroke="#FFFFFF" stroke-opacity="0.08"/>
<text x="${x + 16}" y="222" font-family="${FONT}" font-size="12.5" fill="#8A8A8A">${esc(k)}</text>
<text x="${x + 16}" y="252" font-family="${FONT}" font-size="${String(val).length > 18 ? 13.5 : 18}" font-weight="650" fill="${warn ? IMG_COLOR.suspicious : '#F2F2F2'}">${esc(val)}</text>`
  }).join('\n')}
${head.map((l, i) => `<text x="230" y="${312 + i * 25}" font-family="${FONT}" font-size="18" font-weight="650" fill="#F5F5F5">${esc(l)}</text>`).join('\n')}
${lines.map((l, i) => `<circle cx="236" cy="${370 + head.length * 0 + i * 24}" r="3" fill="${LIME}"/><text x="248" y="${375 + i * 24}" font-family="${FONT}" font-size="14" fill="#B5B5B5">${esc(l)}</text>`).join('\n')}
<line x1="40" y1="452" x2="${W - 40}" y2="452" stroke="#FFFFFF" stroke-opacity="0.08"/>
<text x="40" y="486" font-family="${FONT}" font-size="15" fill="${LIME}">clashgear.shop/scan/r/${esc(f.id)}</text>
<text x="${W - 40}" y="486" text-anchor="end" font-family="${FONT}" font-size="13" fill="#7A7A7A">SHA-256 ${esc(f.sha256.slice(0, 16))}…  ·  1, 3 ve 7 gün sonra yeniden kontrol edilir</text>
</svg>`
}

const cache = new Map()
function render(kind, job, svg, zoom) {
  const k = `${kind}:${job.id}:${job.status}:${job.score}:${job.verdict}:${job.finished_at}`
  let png = cache.get(k)
  if (!png) {
    png = new Resvg(svg(job), { fitTo: { mode: 'zoom', value: zoom }, font: { loadSystemFonts: true, defaultFontFamily: 'Segoe UI' } }).render().asPng()
    cache.set(k, png)
    if (cache.size > 300) cache.delete(cache.keys().next().value)
  }
  return png
}
export const badgePng = (job) => render('badge', job, badgeSvg, 2)
export const cardPng = (job) => render('card', job, cardSvg, 1.5)

/* ------------------------------------------------------------------ forum post */

export function shareSnippets(job) {
  const f = reportFacts(job)
  const img = `${SITE}/api/scan/badge/${job.id}.png`
  const card = `${SITE}/api/scan/card/${job.id}.png`
  const col = TXT_COLOR[f.verdict] || TXT_COLOR.unknown
  const rows = [
    ['Karar', `[COLOR=${col}][B]${f.verdictTr}[/B][/COLOR] · ${f.score ?? '—'}/100`],
    ['Antivirüs', `${f.av} motor tespit etti`],
    ['Sandbox', f.behaviour.length ? `${bb(f.behaviour.join(', '))}` : f.sandboxCount ? `${f.sandboxCount} sandbox'ta zararlı davranış görülmedi` : 'çalıştırılmadı'],
    ['Dijital imza', bb(f.sigText)],
    f.family ? ['Aile', bb(f.family)] : null,
    f.steal.length ? ['Hedeflediği bilgiler', bb(f.steal.join(', '))] : null,
    f.exfil.length ? ['Veri gönderdiği yer', `${bb([...new Set(f.exfil)].join(', ').replace(/_/g, ' '))} (adres raporda)`] : null,
    f.packer ? ['Paketleyici', bb(f.packer)] : null,
    f.children ? ['Açılan / bıraktığı dosyalar', `${f.children}${f.badKids ? ` (${f.badKids} zararlı)` : ''}`] : null,
  ].filter(Boolean)
  const tech = [
    `[B]Dosya:[/B] ${bb(f.name)} · ${bb(f.type)} · ${fmtSize(f.size)}`,
    `[B]SHA-256:[/B] [ICODE]${f.sha256}[/ICODE]`,
    `[B]MD5:[/B] [ICODE]${f.md5}[/ICODE]`,
    f.capa ? `[B]Yetenekler (capa):[/B] ${f.capa}${f.tactics.length ? ` · ATT&CK: ${bb(f.tactics.join(', '))}` : ''}` : null,
    f.yara.length ? `[B]YARA:[/B] ${bb(f.yara.join(', '))}` : null,
    f.domains.length ? `[B]Kötü bilinen adresler:[/B] ${f.domains.map((d) => bb(d.replace(/\./g, '[.]'))).join(', ')}` : null,
    f.source ? `[B]İndirildiği link:[/B] ${bb(f.source.replace(/^http/, 'hxxp'))}` : null,
  ].filter(Boolean)
  const bbcode = [
    `[CENTER][URL=${f.link}][IMG]${card}[/IMG][/URL][/CENTER]`,
    '',
    `[SIZE=5][B]ClashGear Scan analizi:[/B] ${bb(f.name)}[/SIZE]`,
    `[I]${bb(f.headline)}[/I]`,
    '',
    '[LIST]',
    ...rows.map(([k, v]) => `[*][B]${k}:[/B] ${v}`),
    '[/LIST]',
    ...(f.findings.length ? ['', '[B]Öne çıkanlar[/B]', '[LIST]', ...f.findings.map((x) => `[*]${bb(cut(x, 240))}`), '[/LIST]'] : []),
    ...(f.summary ? ['', `[SPOILER=Kısa rapor]${bb(cut(f.summary, 1200))}[/SPOILER]`] : []),
    `[SPOILER=Teknik ayrıntılar]${tech.join('\n')}[/SPOILER]`,
    '',
    `[CENTER][URL=${f.link}][IMG]${img}[/IMG][/URL]`,
    `[B]Tam analiz:[/B] [URL=${f.link}]${f.link}[/URL][/CENTER]`,
    `[SIZE=2]ClashGear Scan · ${dateTr(f.at)} · 40+ istihbarat kaynağı, antivirüs motorları, sandbox ve yapay zeka analisti. Bu rapor 1, 3 ve 7 gün sonra otomatik yeniden kontrol edilir; karar değişirse rozet de güncellenir.[/SIZE]`,
  ].join('\n')
  const mdRows = rows.map(([k, v]) => `- **${k}:** ${String(v).replace(/\[\/?(COLOR[^\]]*|B)\]/g, (m) => (m === '[B]' || m === '[/B]' ? '**' : ''))}`)
  const markdown = [
    `[![ClashGear Scan](${card})](${f.link})`, '', `### ClashGear Scan analizi: ${f.name}`, `_${f.headline}_`, '', ...mdRows,
    ...(f.findings.length ? ['', '**Öne çıkanlar**', ...f.findings.map((x) => `- ${cut(x, 240)}`)] : []),
    '', `\`SHA-256 ${f.sha256}\``, '', `[![ClashGear Scan rozeti](${img})](${f.link})`, `**Tam analiz:** ${f.link}`,
  ].join('\n')
  const html = `<a href="${f.link}"><img src="${card}" alt="ClashGear Scan: ${esc(f.verdictTr)} ${f.score ?? ''}/100" width="1000" height="520" style="max-width:100%;height:auto"></a><br><a href="${f.link}"><img src="${img}" alt="ClashGear Scan rozeti" width="440" height="68"></a>`
  return {
    link: f.link, image: img, card,
    badge_bbcode: `[URL=${f.link}][IMG]${img}[/IMG][/URL]`,
    bbcode, markdown, html,
  }
}
