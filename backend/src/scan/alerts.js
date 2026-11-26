// Scan activity and abuse alerts for the shop owner, sent as Discord DMs by the shop's Discord bot
// (to SCAN_ALERT_DISCORD_IDS, default DISCORD_ADMIN_IDS). DMs and not the REGeared channel webhook,
// because file names and chat text can carry other people's personal data.
// Every finished scan of a non-owner key is reported; abuse signals are reported immediately:
// personal-looking files, upload bursts per IP, evasion/jailbreak requests to Nyx, limits hit,
// login brute force and the daily AI budget nearing its cap. Repeats are throttled per subject.

import { getJob, getKey, aiTotalToday, aiTotalCap } from './db.js'

const API = 'https://discord.com/api/v10'
const SITE = 'https://clashgear.shop'
// Recipients: SCAN_ALERT_DISCORD_IDS, else DISCORD_ADMIN_IDS, else the owner of each guild the bot is in.
let guildOwners = null
async function recipients() {
  const ids = (process.env.SCAN_ALERT_DISCORD_IDS || process.env.DISCORD_ADMIN_IDS || '').split(',').map((s) => s.trim()).filter(Boolean)
  if (ids.length) return ids
  if (!guildOwners?.length) {   // an empty answer (Discord hiccup) must not be cached, or every alert stays silent until a restart
    const auth = { headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}` } }
    const guilds = await (await fetch(`${API}/users/@me/guilds`, auth)).json()
    if (!Array.isArray(guilds)) throw new Error(`discord guilds: ${JSON.stringify(guilds).slice(0, 160)}`)
    const owners = await Promise.all(guilds.map(async (g) => (await (await fetch(`${API}/guilds/${g.id}`, auth)).json()).owner_id))
    guildOwners = [...new Set(owners.filter(Boolean))]
  }
  return guildOwners
}
const dmChannels = new Map() // user id -> DM channel id
const esc = (s) => String(s ?? '').replace(/[\\`*_~|>\[\]()#<@]/g, '\\$&')
const COLOR = { info: 0x8fa6c8, ok: 0x34d399, warn: 0xf59e0b, bad: 0xef4444 }

async function discord(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`discord ${res.status} ${(await res.text()).slice(0, 200)}`)
  return res.json()
}

/** Sends one embed to every recipient's DMs; failures are logged, never thrown. */
export async function sendAlert({ title, lines = [], tone = 'info', url, fields }) {
  if (!process.env.DISCORD_BOT_TOKEN) return
  const embed = {
    title: String(title).slice(0, 256),
    description: lines.filter(Boolean).join('\n').slice(0, 4000),
    ...(fields?.length ? { fields: fields.slice(0, 25).map((f) => ({ name: String(f.name).slice(0, 256), value: String(f.value || '—').slice(0, 1024), inline: !!f.inline })) } : {}),
    color: COLOR[tone] || COLOR.info,
    url,
    footer: { text: 'ClashGear Scan' },
    timestamp: new Date().toISOString(),
  }
  let to = []
  try { to = await recipients() } catch (e) { console.error('scan alert recipients', String(e.message || e)) }
  for (const uid of to) {
    try {
      let ch = dmChannels.get(uid)
      if (!ch) { ch = (await discord('/users/@me/channels', { recipient_id: uid })).id; dmChannels.set(uid, ch) }
      await discord(`/channels/${ch}/messages`, { embeds: [embed], allowed_mentions: { parse: [] } })
    } catch (e) {
      console.error('scan alert failed', uid, String(e.message || e))
    }
  }
}

// one alert per subject per window
const last = new Map()
const once = (key, ms) => {
  const now = Date.now()
  if (now - (last.get(key) || 0) < ms) return false
  last.set(key, now)
  if (last.size > 5000) for (const [k, t] of last) if (now - t > 86_400_000) last.delete(k)
  return true
}

const fmtSize = (n) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`)
const keyLine = (k, ip) => `Anahtar: **${esc(k?.label || '?')}**${k?.shared ? ' (ortak)' : ''} · IP: \`${esc(ip || '?')}\``

// --- personal-data heuristics on uploads ----------------------------------------
const PERSONAL_NAME = /(kimlik|n[uü]fus|tc[\s_-]?no|pasaport|passport|ehliyet|driver|fatura|invoice|dekont|receipt|banka|bank|hesap[\s_-]?[oö]zeti|statement|iban|maa[sş]|bordro|payslip|cv|[oö]zge[cç]mi[sş]|resume|s[oö]zle[sş]me|contract|tapu|sa[gğ]l[ıi]k|rapor|e-?devlet|vergi|tax|sigorta|insurance|ssn|selfie|foto|photo|img_\d|dsc_?\d|whatsapp|şifre|sifre|password|passwd|wallet|seed|mnemonic|private[\s_-]?key|recovery)/i
const DOC_TYPES = new Set(['pdf', 'docx', 'xlsx', 'pptx', 'ole', 'rtf', 'text'])
const IMAGE_EXT = /\.(jpe?g|png|heic|webp|gif|bmp|tiff?)$/i

/** Why an upload looks like a personal document, or null. */
export function personalHint(name, type) {
  if (PERSONAL_NAME.test(name)) return 'dosya adı kişisel belge gibi görünüyor'
  if (IMAGE_EXT.test(name)) return 'fotoğraf / görsel dosyası'
  if (DOC_TYPES.has(type) && !/\.(js|vbs|ps1|bat|cmd|hta|py|sh)$/i.test(name)) return `belge dosyası (${type})`
  return null
}

const uploadsByIp = new Map() // ip -> timestamps (1 h window)

/** Right after an upload: abuse checks (personal file, burst). */
export function onUpload({ jobId, key, ip }) {
  if (!key || key.label === 'owner') return
  const job = getJob(jobId)
  if (!job) return
  const now = Date.now()
  const times = (uploadsByIp.get(ip) || []).filter((t) => now - t < 3_600_000)
  times.push(now)
  uploadsByIp.set(ip, times)

  const hint = personalHint(job.file_name, job.static?.type)
  if (hint) {
    sendAlert({
      title: '⚠ Kişisel dosya şüphesi', tone: 'warn', url: `${SITE}/scan/r/${job.id}`,
      lines: [`**${esc(job.file_name)}** · ${fmtSize(job.size)} · ${esc(job.static?.type || '?')}`, `Neden: ${hint}`, keyLine(key, ip),
        key.shared ? 'Ortak anahtar: bu dosya anahtarı kullanan herkesin geçmişinde görünür. Gerekirse admin panelinden silebilir ya da anahtarı geçici kapatabilirsin.' : ''],
    })
  }
  if (times.length >= 6 && once(`burst:${ip}`, 3_600_000)) {
    sendAlert({ title: '⚠ Yoğun yükleme', tone: 'warn', lines: [`Bu IP son 1 saatte **${times.length}** dosya yükledi.`, keyLine(key, ip)] })
  }
}

/** When a scan finishes: a one-message report of every non-owner upload. */
export function onScanDone(jobId) {
  const job = getJob(jobId)
  if (!job || job.parent_id) return
  const key = getKey(job.key_id)
  if (!key || key.label === 'owner') return
  const v = job.verdict
  const tone = v === 'malicious' ? 'bad' : v === 'suspicious' ? 'warn' : v === 'clean' ? 'ok' : 'info'
  const label = v === 'malicious' ? 'Zararlı' : v === 'suspicious' ? 'Şüpheli' : v === 'clean' ? 'Temiz' : 'Bilinmiyor'
  const c = job.ai?.computed
  sendAlert({
    title: `Yeni analiz · ${label} ${job.score ?? '—'}/100`, tone, url: `${SITE}/scan/r/${job.id}`,
    lines: [
      `**${esc(job.file_name)}** · ${fmtSize(job.size)} · ${esc(job.static?.type || '?')}`,
      c ? `AV: ${c.detected}/${c.engines}${c.family ? ` · Aile: ${esc(c.family)}` : ''}` : '',
      job.ai?.headline_tr ? `Nyx: ${esc(job.ai.headline_tr)}` : '',
      keyLine(key, job.ip),
      `SHA256: \`${job.sha256}\``,
    ],
  })
}

// --- Nyx chat abuse -------------------------------------------------------------
const EVASION = /(fud\b|crypter|crypt(?:le|er)|undetect|tespit\s*edilme|antivir[uü]s(?:ten)?\s*(?:gizle|ka[cç][ıi]r|bypass)|av\s*bypass|bypass\s*(?:av|antivir|defender|smartscreen)|defender[ıi]?\s*(?:kapat|atlat|bypass)|obfuscat(?:e|or)\s*(?:it|this|bunu)|stub\s*yaz|rat\s*yaz|keylogger\s*yaz|stealer\s*yaz|malware\s*yaz|vir[uü]s\s*yaz|ransomware\s*yaz|token\s*grabber)/i
const JAILBREAK = /(ignore\s+(all\s+)?(previous|prior)\s+instructions|önceki\s+talimat|talimatlar[ıi]\s+unut|system\s*prompt|sistem\s*prompt|developer\s*mode|jailbreak|\bDAN\b|rol\s*yap.*kısıtlama|which\s+model|hangi\s+model|anthropic|claude|openai|gpt-?\d)/i

export function onChatMessage({ key, ip, text, chatId }) {
  if (!key || key.label === 'owner') return
  const kind = EVASION.test(text) ? 'zararlı yazılım geliştirme / antivirüs atlatma isteği' : JAILBREAK.test(text) ? 'jailbreak / model bilgisi sorgulama' : null
  if (!kind || !once(`chat:${ip}:${kind}`, 15 * 60_000)) return
  sendAlert({
    title: '⚠ Nyx\'e şüpheli mesaj', tone: 'bad',
    lines: [`Tür: ${kind}`, `> ${esc(text.slice(0, 600)).replace(/\n/g, '\n> ')}`, keyLine(key, ip), `Sohbet: \`${chatId || 'yeni'}\``],
  })
}

/** Limits hit (once per IP per day each). */
export function onLimit({ key, ip, kind }) {
  if (!key || key.label === 'owner' || !once(`limit:${kind}:${ip}`, 86_400_000)) return
  const what = { scan_quota: 'günlük analiz kotası doldu', chat_ip: 'IP başına günlük Nyx mesaj sınırı doldu', chat_key: 'anahtarın günlük Nyx mesaj sınırı doldu',
    self_key_ip: 'bu IP 24 saat içinde ikinci anahtarı istedi (reddedildi)', self_key_day: 'günlük yeni anahtar sınırı doldu',
    self_scan_ip: 'IP başına günlük analiz sınırı doldu (kendi anahtarları)', self_scan_day: 'herkese açık anahtarların günlük toplam analiz sınırı doldu',
    live: 'günlük canlı sandbox oturumu sınırı doldu',
    vpn_hosting: 'VPN / proxy / sunucu IP\'siyle girmeye çalıştı (engellendi)', vpn_relay: 'iCloud Private Relay / WARP gibi bir tünelle girmeye çalıştı (engellendi)',
    vpn_tor: 'Tor ile girmeye çalıştı (engellendi)' }[kind] || kind
  sendAlert({ title: 'Sınıra ulaşıldı', tone: 'info', lines: [what, keyLine(key, ip)] })
}

/** A free-tier request through a VPN / proxy / relay / Tor was refused (once per IP per 6 h). */
export function onVpnBlocked({ ip, key, info, action }) {
  if (!once(`vpn:${ip}`, 6 * 3_600_000)) return
  const what = { hosting: 'VPN / proxy / sunucu', relay: 'Gizlilik tüneli (iCloud Private Relay, WARP…)', tor: 'Tor çıkış düğümü' }[info.kind] || info.kind
  const doing = { login: 'giriş yapmaya', key: 'ücretsiz anahtar oluşturmaya', upload: 'dosya yüklemeye', chat: 'Nyx\'e yazmaya', live: 'canlı sandbox açmaya' }[action] || action
  sendAlert({
    title: '🛡 VPN girişi engellendi',
    tone: 'warn',
    lines: [
      `**${what}** ile ${doing} çalıştı, engellendi.`,
      `IP: \`${esc(ip)}\`${info.country ? ` · Ülke: **${esc(info.country)}**` : ''}`,
      `Sağlayıcı: **${esc(info.isp || '?')}** · Bağlantı türü: ${esc(info.usage || '?')}`,
      key?.label ? `Anahtar: **${esc(key.label)}**${key.prefix ? ` (\`${esc(key.prefix)}…\`)` : ''}` : 'Anahtar: yok (giriş/anahtar oluşturma öncesi)',
      `Sorgu: https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
    ],
  })
}

/** A user flagged a verdict as a false positive; the owner decides in the admin panel. */
export function onFalsePositive({ job, key, ip, note }) {
  sendAlert({
    title: 'Yanlış alarm bildirimi',
    tone: 'info',
    lines: [`**${esc(job.file_name)}** · ${esc(job.verdict)} ${job.score}/100`, note ? `Not: ${esc(note)}` : 'Not yok', keyLine(key, ip), 'Admin paneli → Analiz anahtarları → Yanlış alarmlar'],
  })
}

/** Nyx and Rune changed a file's verdict; a lowered score is worth the owner's look (admin override wins). */
export function onAiVerdict({ job, before, after, reason, key, ip }) {
  const lowered = (after.score ?? 0) < (before.score ?? 0)
  sendAlert({
    title: lowered ? 'Nyx + Rune bir dosyanın skorunu DÜŞÜRDÜ' : 'Nyx + Rune bir dosyanın skorunu değiştirdi',
    tone: lowered ? 'warn' : 'info',
    lines: [`**${esc(job.file_name)}** · ${esc(before.verdict)} ${before.score ?? '—'} → **${esc(after.verdict)} ${after.score}**`, `Gerekçe: ${esc(reason || '')}`, keyLine(key, ip),
      `sha256: \`${job.sha256}\``, lowered ? 'Katılmıyorsan: Admin paneli → Analiz anahtarları → Yanlış alarmlar (owner kararı AI kararını geçer)' : ''].filter(Boolean),
  })
}

/** Nyx closed a chat as misuse: strike 1 closed, 2 warned, 3 banned from Nyx. */
export function onNyxMisuse({ key, ip, level, reason, chatId, linked = [] }) {
  const what = level >= 3 ? 'Nyx\'ten uzaklaştırıldı' : level === 2 ? 'son uyarı verildi' : 'sohbet kapatıldı'
  sendAlert({
    title: level >= 3 ? '⛔ Nyx bir kullanıcıyı uzaklaştırdı' : `Nyx kötüye kullanım tespit etti (${level}/3)`,
    tone: level >= 3 ? 'warn' : 'info',
    lines: [`Tespit: **${esc(reason)}** · ${what}`, keyLine(key, ip), `Sohbet: \`${esc(chatId)}\``,
      linked.length ? `Aynı cihazdaki diğer anahtarlar: ${linked.join(', ')}` : '', level >= 3 ? 'Kaldırmak için: Admin paneli → Analiz anahtarları → Nyx uzaklaştırmaları' : ''].filter(Boolean),
  })
}

/** A free Nyx message refused (or only flagged) as automation or an IDE agent's prompt; once per key per 30 min. */
export function onAutomation({ key, ip, kind, blocked, hits = [], text = '', deviceId }) {
  if (!once(`auto:${key?.id}:${kind}:${blocked}`, 30 * 60_000)) return
  sendAlert({
    title: kind === 'bot' ? '🤖 Otomasyon tarayıcısı tespit edildi' : '🤖 IDE ajanı / aracı imzası tespit edildi',
    tone: blocked ? 'warn' : 'info',
    lines: [
      blocked ? '**Mesaj engellendi**, Nyx\'e gitmedi.' : 'Mesaj geçti (zayıf işaret), Nyx değerlendirecek.',
      `Anahtar: \`${String(key?.prefix || '?').replace(/`/g, "'")}…\` · IP: \`${String(ip || '?').replace(/`/g, "'")}\`${deviceId ? ` · cihaz \`${String(deviceId).slice(0, 8)}\`` : ''}`,
      `İşaretler:\n${hits.map((h) => `• ${esc(h)}`).join('\n')}`,
      text ? `Mesajın başı:\n\`\`\`\n${String(text).slice(0, 300).replace(/`/g, "'")}\n\`\`\`` : '',
    ],
  })
}

// --- CrowdSec (local engine reading Caddy's access log; crowdsec.js polls its alerts) ---------------
const CS_LABEL = [
  [/http-cve|log4j|CVE-/i, 'Bilinen açık (CVE) denemesi'], [/sensitive-files/i, 'Hassas dosya arama'],
  [/admin-interface/i, 'Yönetim paneli arama'], [/backdoor/i, 'Arka kapı arama'], [/sqli/i, 'SQL enjeksiyon denemesi'],
  [/xss/i, 'XSS denemesi'], [/path-traversal/i, 'Dizin atlatma denemesi'], [/bad-user-agent/i, 'Tarama aracı kullanıyor'],
  [/http-probing/i, 'Dizin / dosya taraması'], [/crawl/i, 'Agresif tarama'], [/bf|bruteforce/i, 'Kaba kuvvet giriş denemesi'],
]
const csLabel = (s) => CS_LABEL.find(([re]) => re.test(s))?.[1] || 'Şüpheli etkinlik'

/** New CrowdSec alerts (LAPI alert objects); once per IP + scenario per 6 h. */
export function onCrowdsec(alerts) {
  for (const a of Array.isArray(alerts) ? alerts : []) {
    const ip = a.source?.ip || a.source?.value || '?'
    if (!once(`cs:${ip}:${a.scenario}`, 6 * 3_600_000)) continue
    const ctx = Object.fromEntries((a.meta || []).map((m) => { try { return [m.key, JSON.parse(m.value)] } catch { return [m.key, [m.value]] } }))
    const uris = [...new Set(ctx.target_uri || [])].slice(0, 8)
    const uas = [...new Set(ctx.user_agent || [])].slice(0, 2)
    const code = (s) => String(s).slice(0, 140).replace(/`/g, "'")
    sendAlert({
      title: `🛡 ${csLabel(a.scenario)}`,
      tone: /cve|backdoor|sqli|traversal|sensitive/i.test(a.scenario) ? 'bad' : 'warn',
      lines: [
        `IP: \`${esc(ip)}\`${a.source?.cn ? ` · Ülke: **${esc(a.source.cn)}**` : ''}${a.source?.as_name ? ` · ${esc(a.source.as_name)}` : ''}`,
        `Kural: \`${esc(a.scenario)}\` · ${a.events_count ?? '?'} istek`,
        uris.length ? `Denediği adresler:\n\`\`\`\n${uris.map(code).join('\n')}\n\`\`\`` : '',
        uas.length ? `Tarayıcı / araç: ${uas.map((u) => `\`${code(u)}\``).join(', ')}` : '',
        'Sadece uyarı, engelleme yok.',
        `Sorgu: https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
      ],
    })
  }
}

/** Login throttle tripped. */
export function onLoginBlocked(ip) {
  if (!once(`login:${ip}`, 3_600_000)) return
  sendAlert({ title: '⚠ Giriş denemeleri engellendi', tone: 'warn', lines: [`IP \`${esc(ip)}\` 15 dakikada 5 yanlış anahtar denedi ve 15 dakika engellendi.`] })
}

/** The shared AI budget passing 80 %. */
export function checkAiBudget() {
  const spent = aiTotalToday(), cap = aiTotalCap()
  if (spent < cap * 0.8 || !once(`ai80:${new Date().toISOString().slice(0, 10)}`, 86_400_000)) return
  sendAlert({ title: 'AI bütçesi %80\'i geçti', tone: 'warn', lines: [`Bugün **$${spent.toFixed(2)}** / $${cap} harcandı. Sınır dolunca Nyx ve AI raporları yarına kadar durur.`] })
}

/** Call log of the public 21st MCP front (cg-mcp on this machine), one embed per batch. */
export function onMcpLog(lines) {
  const out = lines.map((l) => String(l).slice(0, 400))
  for (let i = 0; i < out.length;) {
    let n = 0, len = 0
    while (i + n < out.length && len + out[i + n].length + 1 < 3800) len += out[i + n++].length + 1
    n = Math.max(n, 1)
    sendAlert({ title: `21st MCP · ${n} çağrı`, tone: 'info', lines: out.slice(i, i + n) })
    i += n
  }
}
