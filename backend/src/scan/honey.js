// Token Tuzağı (owner, 2026-11-12). The file runs in our CAPE VM inside a user profile full of fake but realistic
// accounts, generated fresh for every run: a Discord token, Chromium passwords and cookies encrypted with the
// guest's own DPAPI key (a stealer really can decrypt them), Steam ssfn, Telegram tdata, Exodus / MetaMask
// wallets, a Roblox cookie, a fake crypto address on the clipboard, and a login for our own trap page
// (/panel/giris). Three tiers of evidence:
//   OKUDU       Windows' own audit log (SACL on every bait file, event 4663) names the process that opened it;
//               CAPE's per-process file reads back it up.
//   PAKETLEDİ   a file made during the run (zips included, also ones deleted after sending) holds bait values.
//   GÖNDERDİ    a bait value shows up in outbound traffic (plain, base64, zipped, or in HTTPS that CAPE decrypted
//               with the guest's TLS keys); otherwise only "connected to X and sent N KB" (likely, not proven).
// Someone trying the trap login later is the last proof: the data left the VM and reached a person.
//
// Guest side: CAPE aux module cg_honey (sandbox /opt/CAPEv2/analyzer/windows/modules/auxiliary/cg_honey.py), host
// side: cg-files POST /honey/<task> (/opt/cg-files/honeyscan.py). Sources kept in Desktop/CrackMe/cg-honey.

import { randomBytes, createHash, createCipheriv } from 'node:crypto'
import { db } from '../store.js'
import { config } from '../config.js'
import { http, formWith } from './http.js'
import { loadSample } from './storage.js'
import { TUNNEL_FILES_PORT } from './tunnel.js'
import { CAPE_RUN_OPTIONS, capeActivity } from './providers/sandbox.js'
import { getJob, getResult, setResult } from './db.js'
import { attachLiveRun, rescoreJob } from './jobs.js'
import { sendAlert } from './alerts.js'
import { ipKind } from './ipguard.js'

const CAPE = () => (process.env.CAPE_URL || '').replace(/\/+$/, '')
const cape = (path, opts = {}) => http(`${CAPE()}${path}`, { ...opts, headers: { Authorization: `Token ${process.env.CAPE_API_KEY}`, ...(opts.headers || {}) } })
const files = (path, opts = {}) => http(`http://127.0.0.1:${TUNNEL_FILES_PORT}${path}`, { ...opts, headers: { Authorization: `Token ${process.env.CAPE_FILES_TOKEN}`, ...(opts.headers || {}) }, timeout: 180_000 })
const DONE = ['completed', 'reported']
const FAILED = ['failed_analysis', 'failed_processing', 'failed_reporting']
export const HONEY_SECONDS = Math.max(90, Number(process.env.SCAN_HONEY_SECONDS) || 180)
export const honeyEnabled = () => !!(process.env.CAPE_URL && process.env.CAPE_API_KEY && process.env.CAPE_FILES_TOKEN)
export const TRAP_PATH = '/panel/giris'

db.exec(`
  CREATE TABLE IF NOT EXISTS scan_honey_runs (
    id TEXT PRIMARY KEY, job_id TEXT NOT NULL, key_id TEXT, task_id INTEGER, status TEXT NOT NULL,
    trap_user TEXT NOT NULL, trap_pass TEXT NOT NULL, bait_json TEXT NOT NULL, result_json TEXT,
    created_at INTEGER NOT NULL, finished_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS scan_honey_runs_job ON scan_honey_runs(job_id);
  CREATE INDEX IF NOT EXISTS scan_honey_runs_user ON scan_honey_runs(trap_user);
  CREATE TABLE IF NOT EXISTS scan_honey_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, at INTEGER NOT NULL, ip TEXT, country TEXT, ua TEXT,
    user TEXT, pass_ok INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS scan_honey_hits_run ON scan_honey_hits(run_id);
`)

// --- what each bait is ----------------------------------------------------------------------------
// kind -> how the report names it (accusative, it is always "…'ı OKUDU"); strong kinds are what stealers are for.
export const KINDS = {
  discord: { label: "Discord token'ını", strong: true },
  browser_passwords: { label: 'kayıtlı tarayıcı şifrelerini', strong: true },
  browser_cookies: { label: 'tarayıcı çerezlerini (oturumları)', strong: true },
  wallet: { label: 'kripto cüzdanlarını', strong: true },
  telegram: { label: 'Telegram oturumunu', strong: true },
  roblox: { label: 'Roblox çerezini', strong: true },
  steam: { label: 'Steam oturum dosyalarını', strong: false },
  browser_key: { label: 'tarayıcının şifre çözme anahtarını', strong: false },
  trap: { label: 'tuzak panel şifresini', strong: false },
}
const BAIT_KIND = {
  discord: 'discord', discord_ls: 'discord', chrome_logins: 'browser_passwords', edge_logins: 'browser_passwords',
  chrome_cookies: 'browser_cookies', edge_cookies: 'browser_cookies', chrome_state: 'browser_key', edge_state: 'browser_key',
  discord_state: 'discord', metamask: 'wallet', metamask_edge: 'wallet', exodus: 'wallet', telegram: 'telegram',
  steam_ssfn: 'steam', steam_users: 'steam', note: 'trap',
}

// --- value generators -------------------------------------------------------------------------------
const AL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const rnd = (n, al = AL) => [...randomBytes(n)].map((x) => al[x % al.length]).join('')
const sha256 = (b) => createHash('sha256').update(b).digest()
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58(buf) {
  let x = BigInt('0x' + buf.toString('hex')), s = ''
  while (x > 0n) { s = B58[Number(x % 58n)] + s; x /= 58n }
  for (const b of buf) { if (b) break; s = '1' + s }
  return s
}
// A valid-checksum P2PKH address of a random hash: nobody holds its key, clipper regexes accept it.
const btcAddress = () => { const p = Buffer.concat([Buffer.from([0]), randomBytes(20)]); return base58(Buffer.concat([p, sha256(sha256(p)).subarray(0, 4)])) }
const ethAddress = () => '0x' + randomBytes(20).toString('hex')
// Chromium "v10": AES-256-GCM under the profile key that Local State keeps DPAPI-wrapped.
const v10 = (key, plain) => {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(Buffer.from(plain, 'utf8')), c.final()])
  return Buffer.concat([Buffer.from('v10'), iv, ct, c.getAuthTag()])
}
const b64 = (b) => Buffer.from(b).toString('base64')
// Microseconds since 1601, whole seconds (exact as a JSON number).
const chromeTime = (msAgo = 0) => (Math.floor((Date.now() - msAgo) / 1000) + 11644473600) * 1e6
const DAY = 86_400_000
// Alphanumeric substring of base64 (markers must survive URL/JSON encoding unchanged).
const alnumB64 = (n) => { for (;;) { const s = randomBytes(n).toString('base64').replace(/=+$/, ''); const m = s.slice(0, 32); if (/^[A-Za-z0-9]+$/.test(m)) return { s, m } } }
// LevelDB-ish record: stealers grep .log/.ldb files, they never parse them.
const ldb = (key, value) => Buffer.concat([randomBytes(7), Buffer.from([0x01, 0x01, 0, 0, 0, 0, 0, 0]), Buffer.from(key, 'latin1'), Buffer.from([0x01]), Buffer.from(value, 'utf8'), randomBytes(5)])

const LOGINS_SQL = `CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES('mmap_status','-1'),('version','40'),('last_compatible_version','40');
CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, form_data BLOB, display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR, skip_zero_click INTEGER, generation_upload_status INTEGER, possible_username_pairs BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, moving_blocked_for BLOB, date_password_modified INTEGER NOT NULL DEFAULT 0, sender_email VARCHAR, sender_name VARCHAR, date_received INTEGER, sharing_notification_displayed INTEGER NOT NULL DEFAULT 0, keychain_identifier BLOB, sender_profile_image_url VARCHAR, UNIQUE (origin_url, username_element, username_value, password_element, signon_realm));`
const COOKIES_SQL = `CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES('mmap_status','-1'),('version','21'),('last_compatible_version','21');
CREATE TABLE cookies(creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL, samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL, source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL, source_type INTEGER NOT NULL, has_cross_site_ancestor INTEGER NOT NULL, UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, source_port));`

/** Fresh fake accounts for one run: the guest spec (files to write) and the markers that identify each value. */
export function makeBait() {
  const markers = []
  const mark = (id, kind, s, label) => { markers.push({ id, kind, s, label }); return s }
  const trapUser = `mkaya.${rnd(6, 'abcdefghjkmnpqrstuvwxyz23456789')}`
  const trapPass = `${rnd(4, 'ABCDEFGHJKLMNPQRSTUVWXYZ')}${rnd(8, 'abcdefghjkmnpqrstuvwxyz23456789')}${rnd(2, '23456789')}`
  mark('trap_user', 'trap', trapUser, 'panel kullanıcı adı')
  mark('trap_pass', 'trap', trapPass, 'panel şifresi')
  const trapUrl = `${config.publicUrl}${TRAP_PATH}`

  // Discord: token = base64(user id) . 6 . 38
  const uid = String(1000000000000000000n + BigInt('0x' + randomBytes(7).toString('hex')) % 300000000000000000n)
  const tail = rnd(38)
  const token = `${Buffer.from(uid).toString('base64').replace(/=+$/, '')}.${rnd(6)}.${tail}`
  mark('discord_token', 'discord', tail, 'Discord token')
  const discordKey = randomBytes(32)
  const discordEnc = `dQw4w9WgXcQ:${b64(v10(discordKey, token))}`

  // Browser accounts (only the trap one can ever be watched; the rest make the profile look lived-in).
  const acct = (site) => ({ site, user: `${['mert', 'kaya', 'mkaya', 'mertk'][randomBytes(1)[0] % 4]}_${rnd(7, 'abcdefghjkmnpqrstuvwxyz23456789')}`, pass: rnd(14) })
  const chromeAccts = [acct('https://discord.com/login'), acct('https://www.roblox.com/login'), acct('https://www.instagram.com/accounts/login/')]
  const edgeAccts = [acct('https://steamcommunity.com/login/home/'), acct('https://www.epicgames.com/id/login')]
  chromeAccts.forEach((a, i) => { mark(`chrome_user_${i}`, 'browser_passwords', a.user, `Chrome kullanıcı adı (${new URL(a.site).hostname})`); mark(`chrome_pass_${i}`, 'browser_passwords', a.pass, `Chrome şifresi (${new URL(a.site).hostname}, çözülmüş)`) })
  edgeAccts.forEach((a, i) => { mark(`edge_user_${i}`, 'browser_passwords', a.user, `Edge kullanıcı adı (${new URL(a.site).hostname})`); mark(`edge_pass_${i}`, 'browser_passwords', a.pass, `Edge şifresi (${new URL(a.site).hostname}, çözülmüş)`) })

  const robloxHex = randomBytes(40).toString('hex').toUpperCase()
  const roblox = `_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_${robloxHex}`
  mark('roblox_cookie', 'roblox', robloxHex.slice(0, 48), 'Roblox .ROBLOSECURITY')
  const steamSecure = `7656119${String(8000000000 + (randomBytes(4).readUInt32BE() % 999999999))}%7C%7C${rnd(40)}`
  mark('steam_cookie', 'browser_cookies', steamSecure.slice(-40), 'Steam oturum çerezi')
  const sessCookie = rnd(32)
  mark('session_cookie', 'browser_cookies', sessCookie, 'oturum çerezi')

  const steamId = `7656119${String(8000000000 + (randomBytes(4).readUInt32BE() % 999999999))}`
  const steamAccount = `mkaya${rnd(6, 'abcdefghjkmnpqrstuvwxyz23456789')}`
  mark('steam_account', 'steam', steamAccount, 'Steam hesap adı')
  const ssfnMark = mark('steam_ssfn', 'steam', rnd(24), 'Steam ssfn')
  const tdataMark = mark('telegram_tdata', 'telegram', rnd(24), 'Telegram tdata')
  const exodusMark = mark('exodus_seed', 'wallet', rnd(24), 'Exodus seed.seco')
  const mm = alnumB64(480)
  mark('metamask_vault', 'wallet', mm.m, 'MetaMask kasası')
  const clip = [btcAddress(), ethAddress()]

  const L = '%LOCALAPPDATA%', A = '%APPDATA%'
  const chrome = `${L}\\Google\\Chrome\\User Data`, edge = `${L}\\Microsoft\\Edge\\User Data`
  const chromeKey = randomBytes(32), edgeKey = randomBytes(32)
  const loginRows = (key, accts) => [{ site: `${config.publicUrl}${TRAP_PATH}`, user: trapUser, pass: trapPass }, ...accts].map((a, i) => ({
    origin_url: a.site, action_url: a.site, username_element: 'username', username_value: a.user, password_element: 'password',
    password_value: `b64:${b64(v10(key, a.pass))}`, submit_element: '', signon_realm: `${new URL(a.site).origin}/`,
    date_created: chromeTime((40 + i * 9) * DAY), blacklisted_by_user: 0, scheme: 0, password_type: 0, times_used: 3 + i, form_data: 'b64:',
    display_name: '', icon_url: '', federation_url: '', skip_zero_click: 0, generation_upload_status: 0, possible_username_pairs: 'b64:',
    date_last_used: chromeTime((2 + i) * DAY), date_password_modified: chromeTime((40 + i * 9) * DAY),
  }))
  const cookieRow = (key, host, name, value) => ({
    creation_utc: chromeTime(20 * DAY), host_key: host, top_frame_site_key: '', name, value: '', encrypted_value: `b64:${b64(v10(key, value))}`, path: '/',
    expires_utc: chromeTime(-300 * DAY), is_secure: 1, is_httponly: 1, last_access_utc: chromeTime(DAY / 3), has_expires: 1, is_persistent: 1,
    priority: 1, samesite: -1, source_scheme: 2, source_port: 443, last_update_utc: chromeTime(DAY / 3), source_type: 0, has_cross_site_ancestor: 0,
  })
  const mmLog = (id) => ({ p: `${id === 'metamask' ? chrome : edge}\\Default\\Local Extension Settings\\${id === 'metamask' ? 'nkbihfbeogaeaoehlefnkodbefgpgknn' : 'ejbalbakoplchlghecdalmeeeajnimhm'}\\000003.log`, bait: id,
    b64: b64(ldb('KeyringController', JSON.stringify({ vault: JSON.stringify({ data: mm.s, iv: randomBytes(16).toString('base64'), keyMetadata: { algorithm: 'PBKDF2', params: { iterations: 600000 } }, salt: randomBytes(32).toString('base64') }) }))) })
  const tdf = (body) => b64(Buffer.concat([Buffer.from('TDF$'), Buffer.from([0x0f, 0x4c, 0x4c, 0x00]), randomBytes(96), Buffer.from(body), randomBytes(64)]))
  const ssfnName = `ssfn${String(BigInt('0x' + randomBytes(8).toString('hex')) % 10000000000000000000n).padStart(19, '1')}`
  const note = `clashgear panel\r\n${trapUrl}\r\nkullanıcı: ${trapUser}\r\nşifre: ${trapPass}\r\n\r\nsteam: ${steamAccount}\r\n`

  const spec = {
    v: 1,
    files: [
      { p: `${A}\\discord\\Local Storage\\leveldb\\000005.ldb`, bait: 'discord', b64: b64(ldb('_https://discord.com\x00\x01token', `"${token}"`)) },
      { p: `${A}\\discord\\Local Storage\\leveldb\\000003.log`, bait: 'discord', b64: b64(ldb('_https://discord.com\x00\x01token', `"${discordEnc}"`)) },
      { p: `${A}\\discord\\Local Storage\\leveldb\\CURRENT`, b64: b64('MANIFEST-000001\n') },
      { p: `${A}\\discord\\Local Storage\\leveldb\\LOCK`, b64: '' },
      { p: `${A}\\discord\\Local Storage\\leveldb\\MANIFEST-000001`, b64: b64(Buffer.concat([randomBytes(12), Buffer.from('leveldb.BytewiseComparator')])) },
      { p: `${chrome}\\Default\\Local Storage\\leveldb\\000003.log`, bait: 'discord_ls', b64: b64(ldb('_https://discord.com\x00\x01token', `"${token}"`)) },
      mmLog('metamask'), mmLog('metamask_edge'),
      { p: `C:\\Program Files (x86)\\Steam\\${ssfnName}`, bait: 'steam_ssfn', b64: b64(Buffer.concat([randomBytes(300), Buffer.from(ssfnMark), randomBytes(200)])) },
      { p: 'C:\\Program Files (x86)\\Steam\\config\\loginusers.vdf', bait: 'steam_users', b64: b64(`"users"\n{\n\t"${steamId}"\n\t{\n\t\t"AccountName"\t\t"${steamAccount}"\n\t\t"PersonaName"\t\t"mertk"\n\t\t"RememberPassword"\t\t"1"\n\t\t"WantsOfflineMode"\t\t"0"\n\t\t"MostRecent"\t\t"1"\n\t\t"Timestamp"\t\t"${Math.floor(Date.now() / 1000) - 7200}"\n\t}\n}\n`) },
      { p: 'C:\\Program Files (x86)\\Steam\\config\\config.vdf', bait: 'steam_users', b64: b64(`"InstallConfigStore"\n{\n\t"Software"\n\t{\n\t\t"Valve"\n\t\t{\n\t\t\t"Steam"\n\t\t\t{\n\t\t\t\t"Accounts"\n\t\t\t\t{\n\t\t\t\t\t"${steamAccount}"\n\t\t\t\t\t{\n\t\t\t\t\t\t"SteamID"\t\t"${steamId}"\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n`) },
      { p: `${A}\\Telegram Desktop\\tdata\\key_datas`, bait: 'telegram', b64: tdf(tdataMark) },
      { p: `${A}\\Telegram Desktop\\tdata\\D877F783D5D3EF8C\\maps`, bait: 'telegram', b64: tdf(tdataMark) },
      { p: `${A}\\Telegram Desktop\\tdata\\D877F783D5D3EF8Cs`, bait: 'telegram', b64: tdf(tdataMark) },
      { p: `${A}\\Telegram Desktop\\tdata\\settingss`, b64: tdf(rnd(16)) },
      { p: `${A}\\Exodus\\exodus.wallet\\seed.seco`, bait: 'exodus', b64: b64(Buffer.concat([Buffer.from('SECO'), Buffer.from([0, 0, 0, 1]), randomBytes(220), Buffer.from(exodusMark), randomBytes(120)])) },
      { p: `${A}\\Exodus\\exodus.wallet\\info.seco`, b64: b64(Buffer.concat([Buffer.from('SECO'), randomBytes(160)])) },
      { p: `${A}\\Exodus\\exodus.wallet\\passphrase.json`, b64: b64('{"passphrase":null}') },
      { p: '%USERPROFILE%\\Desktop\\sifreler.txt', bait: 'note', b64: b64(Buffer.from(note, 'utf8')) },
    ],
    local_state: [
      { p: `${chrome}\\Local State`, key: chromeKey.toString('hex'), bait: 'chrome_state', extra: { profile: { info_cache: { Default: { name: 'Kişi 1' } }, last_used: 'Default' } } },
      { p: `${edge}\\Local State`, key: edgeKey.toString('hex'), bait: 'edge_state', extra: { profile: { info_cache: { Default: { name: 'Profil 1' } }, last_used: 'Default' } } },
      { p: `${A}\\discord\\Local State`, key: discordKey.toString('hex'), bait: 'discord_state' },
    ],
    sqlite: [
      { p: `${chrome}\\Default\\Login Data`, bait: 'chrome_logins', schema: LOGINS_SQL, table: 'logins', rows: loginRows(chromeKey, chromeAccts) },
      { p: `${edge}\\Default\\Login Data`, bait: 'edge_logins', schema: LOGINS_SQL, table: 'logins', rows: loginRows(edgeKey, edgeAccts) },
      { p: `${chrome}\\Default\\Network\\Cookies`, bait: 'chrome_cookies', schema: COOKIES_SQL, table: 'cookies', rows: [cookieRow(chromeKey, '.roblox.com', '.ROBLOSECURITY', roblox), cookieRow(chromeKey, '.discord.com', '__dcfduid', sessCookie)] },
      { p: `${edge}\\Default\\Network\\Cookies`, bait: 'edge_cookies', schema: COOKIES_SQL, table: 'cookies', rows: [cookieRow(edgeKey, 'steamcommunity.com', 'steamLoginSecure', steamSecure)] },
    ],
    reg: [
      { k: 'HKCU\\Software\\Valve\\Steam', n: 'SteamPath', v: 'c:/program files (x86)/steam' },
      { k: 'HKCU\\Software\\Valve\\Steam', n: 'AutoLoginUser', v: steamAccount },
      { k: 'HKCU\\Software\\Roblox\\RobloxStudioBrowser\\roblox.com', n: '.ROBLOSECURITY', v: `SEC::<YES>,EXP::<${new Date(Date.now() + 300 * DAY).toISOString().slice(0, 10)}>,COOK::<${roblox}>` },
    ],
    clip,
    markers: markers.map(({ id, s }) => ({ id, s })),
  }
  return { spec, markers, trapUser, trapPass, trapUrl, clip, token }
}

// --- runs -------------------------------------------------------------------------------------------
const parse = (s) => { try { return s ? JSON.parse(s) : null } catch { return null } }
const runRow = (id) => { const r = db.prepare('SELECT * FROM scan_honey_runs WHERE id = ?').get(id); return r && { ...r, bait: parse(r.bait_json), result: parse(r.result_json) } }
export const latestRun = (jobId) => { const r = db.prepare('SELECT id FROM scan_honey_runs WHERE job_id = ? ORDER BY created_at DESC LIMIT 1').get(jobId); return r ? runRow(r.id) : null }
const setRun = (id, f) => db.prepare(`UPDATE scan_honey_runs SET ${Object.keys(f).map((k) => `${k} = ?`).join(', ')} WHERE id = ?`).run(...Object.values(f), id)
export const honeyToday = (keyId) => db.prepare('SELECT count(*) n FROM scan_honey_runs WHERE key_id = ? AND created_at > ?').get(keyId, Date.now() - DAY).n
const active = new Map()

/** Submits the job's file to CAPE with the bait profile; the result lands on the job as source "honey". */
export async function startHoney(job, keyId) {
  if (!honeyEnabled()) throw new Error('honey_not_configured')
  const run = latestRun(job.id)
  if (run && ['queued', 'running'].includes(run.status)) return run
  const b = makeBait()
  const opt = Buffer.from(JSON.stringify(b.spec)).toString('base64url')
  const up = await cape('/tasks/create/file/', {
    method: 'POST',
    body: formWith({ options: `${CAPE_RUN_OPTIONS},cghoney=${opt}`, timeout: String(HONEY_SECONDS), enforce_timeout: '1', priority: '2' }, loadSample(job.sha256), 'file', job.file_name),
    timeout: 120_000,
  })
  const task = up?.data?.task_ids?.[0]
  if (!task) throw new Error(up?.error_value || 'honey_submit_failed')
  const id = randomBytes(9).toString('base64url')
  db.prepare('INSERT INTO scan_honey_runs (id, job_id, key_id, task_id, status, trap_user, trap_pass, bait_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, job.id, keyId, task, 'queued', b.trapUser, b.trapPass, JSON.stringify({ markers: b.markers, clip: b.clip, trap_url: b.trapUrl, paths: b.spec.files.concat(b.spec.local_state, b.spec.sqlite).filter((f) => f.bait).map((f) => ({ p: f.p, bait: f.bait })) }), Date.now())
  setResult(job.id, 'honey', 8, { status: 'running', ref: id, summary: { honey: { status: 'queued', task, started_at: Date.now(), seconds: HONEY_SECONDS } } })
  follow(id)
  return runRow(id)
}

function follow(id) {
  if (!active.has(id)) active.set(id, watch(id).catch((e) => { console.error('honey run failed', id, e); fail(id, String(e.message || e)) }).finally(() => active.delete(id)))
  return active.get(id)
}
function fail(id, error) {
  const run = runRow(id)
  if (!run) return
  setRun(id, { status: 'error', finished_at: Date.now() })
  setResult(run.job_id, 'honey', 8, { status: 'error', error: error.slice(0, 200) })
}

async function watch(id) {
  const run = runRow(id)
  if (!run) return
  const until = run.created_at + 45 * 60_000
  for (;;) {
    const t = (await cape(`/tasks/view/${run.task_id}/`).catch(() => null))?.data
    if (t?.status === 'running' && run.status === 'queued') {
      setRun(id, { status: 'running' })
      run.status = 'running'
      setResult(run.job_id, 'honey', 8, { status: 'running', summary: { honey: { status: 'running', task: run.task_id, started_at: Date.now(), seconds: HONEY_SECONDS } } })
    }
    if (t && t.status === 'reported') break
    if (t && FAILED.includes(t.status)) return fail(id, t.status)
    if (Date.now() > until) return fail(id, 'timeout')
    await new Promise((r) => setTimeout(r, 10_000))
  }
  await finalize(run)
}

/** Re-reads a finished run's evidence (after a fix to the detection) and rewrites its result. */
export const reprocessHoney = (id) => finalize(runRow(id), { quiet: true })

async function finalize(run, { quiet = false } = {}) {
  const rep = await cape(`/tasks/get/report/${run.task_id}/`, { timeout: 180_000 }).catch(() => null)
  const scan = await files(`/honey/${run.task_id}`, { method: 'POST', body: JSON.stringify({ markers: run.bait.markers.map(({ id: mid, s }) => ({ id: mid, s })) }), headers: { 'Content-Type': 'application/json' } })
  const job = getJob(run.job_id)
  const result = buildResult(run, rep, scan, job)
  setRun(run.id, { status: 'done', finished_at: run.finished_at || Date.now(), result_json: JSON.stringify({ ...result, full: { webhooks: scan?.webhooks || [], bots: scan?.bots || [] } }) })
  setResult(run.job_id, 'honey', 8, { status: 'done', summary: summaryOf(result, honeyHits(run.id)) })
  rescoreJob(run.job_id)
  if (result.proof && !quiet) {
    sendAlert({ title: '🪤 Token Tuzağı: çalma kanıtlandı', tone: 'bad', url: `${config.publicUrl}/scan/r/${run.job_id}`, lines: [`**${job?.file_name || run.job_id}**`, ...result.chains.slice(0, 4).map((c) => c.text), result.endpoints.webhooks.length ? `Discord webhook: ${result.endpoints.webhooks.length}` : '', result.endpoints.bots.length ? `Telegram bot: ${result.endpoints.bots.length}` : ''] })
  }
  // The same run is a full CAPE analysis: when the report has none yet, it becomes the CAPE result too (its
  // captured files become child scans, which can take minutes; attachLiveRun rescores again at the end).
  if (getResult(run.job_id, 'cape')?.status !== 'done' && rep) attachLiveRun(run.job_id, run.task_id).catch((e) => console.error('honey cape attach failed', run.job_id, e))
}

// --- result -----------------------------------------------------------------------------------------
const tailOf = (p) => String(p).replace(/^%[A-Z_]+%|^C:/i, '').toLowerCase()
// (and the browsers/apps themselves: a sample that opens a URL starts Edge, which reads its own profile)
const SYSTEM_PROC = /\\(msedge|msedgewebview2|chrome|discord|steam|telegram|exodus|explorer|svchost|searchprotocolhost|searchindexer|searchfilterhost|msmpeng|python|pythonw|perfhostsvc|wevtutil|dllhost|runtimebroker|backgroundtaskhost|sihost|ctfmon|taskhostw|smartscreen|compattelrunner|wmiprvse)\.exe$/i
const EXFIL_HOST = /(^|\.)(api\.telegram\.org|discord(app)?\.com|gofile\.io|file\.io|transfer\.sh|anonfiles\.com|catbox\.moe|litterbox\.catbox\.moe|pastebin\.com|paste\.ee|hastebin\.com|ngrok(-free)?\.(io|app)|webhook\.site|pipedream\.net|requestbin\.(com|net)|0x0\.st|bashupload\.com|uguu\.se|pixeldrain\.com|tmpfiles\.org|filebin\.net|mega\.nz|dropboxapi\.com|content\.dropboxapi\.com|api\.anonfiles\.com|store\d*\.gofile\.io|keep\.sh|oshi\.at|temp\.sh|discordapp\.net)$/i
const BENIGN_HOST = /(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|live\.com|msedge\.net|bing\.com|msftconnecttest\.com|office\.com|office\.net|azureedge\.net|digicert\.com|skype\.com|microsoftonline\.com|msauth\.net|msftauth\.net|gvt1\.com|google\.com|googleapis\.com|gstatic\.com|akamaized\.net|akamaiedge\.net|trafficmanager\.net|lencr\.org)$/i
const maskSecret = (s, keep = 4) => (s.length <= keep * 2 + 3 ? '…' : `${s.slice(0, keep)}…${s.slice(-keep)}`)
const maskHook = (u) => u.replace(/(webhooks\/\d{4})\d+\/([A-Za-z0-9_-]{4})[A-Za-z0-9_-]+([A-Za-z0-9_-]{4})/, '$1…/$2…$3')
const maskBot = (t) => t.replace(/^(\d{3})\d+:([A-Za-z0-9_-]{3})[A-Za-z0-9_-]+([A-Za-z0-9_-]{3})$/, '$1…:$2…$3')
const procName = (p) => String(p || '').split('\\').pop()

function buildResult(run, rep, scan, job) {
  const markerKind = Object.fromEntries(run.bait.markers.map((m) => [m.id, m.kind]))
  const markerLabel = Object.fromEntries(run.bait.markers.map((m) => [m.id, m.label]))
  const guest = scan?.guest || null
  const baitPaths = (guest?.baits?.length ? guest.baits.map((b) => ({ p: b.path, bait: b.id })) : run.bait.paths).map((b) => ({ tail: tailOf(b.p), bait: b.bait }))
  const baitOf = (path) => baitPaths.find((b) => tailOf(path).endsWith(b.tail))?.bait

  // OKUDU: the audit log first (kernel-side), CAPE's API trace for monitored processes as backup.
  const reads = new Map() // kind -> { kind, processes:Set, files:Set, source:Set }
  const addRead = (bait, path, proc, source) => {
    const kind = BAIT_KIND[bait]
    if (!kind || SYSTEM_PROC.test(proc || '')) return
    const r = reads.get(kind) || { kind, processes: new Set(), files: new Set(), source: new Set() }
    if (proc) r.processes.add(procName(proc))
    r.files.add(String(path).replace(/^C:\\Users\\[^\\]+/i, '%USERPROFILE%'))
    r.source.add(source)
    reads.set(kind, r)
  }
  for (const r of guest?.reads || []) addRead(r.bait, r.path, r.process, 'audit')
  const activity = rep ? capeActivity(rep) : null
  for (const p of activity?.processes || []) {
    for (const f of p.files?.read || []) {
      const bait = baitOf(f)
      if (bait) addRead(bait, f, p.path || p.name, 'cape')
    }
  }

  // PAKETLEDİ: files made during the run that hold bait values (the guest's sweep + what CAPE captured).
  const packed = []
  const seenPack = new Set()
  const pushPack = (path, ids, archive, where) => {
    const key = procName(path).toLowerCase()
    if (seenPack.has(key) || !ids.length) return
    seenPack.add(key)
    packed.push({ file: String(path).replace(/^C:\\Users\\[^\\]+/i, '%USERPROFILE%'), archive: !!archive, kinds: [...new Set(ids.map((i) => markerKind[i]).filter(Boolean))], values: ids.map((i) => markerLabel[i]).filter(Boolean).slice(0, 8), where })
  }
  // a browser started by the sample rewrites its own profile (journals, "Login Data For Account"): not the sample
  const ownProfile = /\\User Data\\|\\discord\\|\\Telegram Desktop\\|\\Exodus\\|\\Steam\\/i
  for (const p of guest?.packed || []) if (p.markers?.length && !ownProfile.test(p.path)) pushPack(p.path, p.markers, p.archive, 'guest')
  const unreadableArchives = (guest?.packed || []).filter((p) => p.unreadable).map((p) => procName(p.path)).slice(0, 5)
  for (const h of (scan?.hits || []).filter((x) => x.where === 'dropped')) pushPack(h.path, Object.keys(h.markers), h.archive, 'cape')

  // GÖNDERDİ: bait values seen leaving the VM.
  const sent = []
  for (const h of (scan?.hits || []).filter((x) => x.where !== 'dropped')) {
    const ids = Object.keys(h.markers)
    const how = [...new Set(Object.values(h.markers).flat())]
    sent.push({
      host: h.host || h.dst, dst: h.dst, port: h.dport, method: h.method || null,
      path: h.uri ? maskBotUri(String(h.uri)).slice(0, 160) : null,
      tls: h.where === 'https' || h.dport === 443, decrypted: h.where === 'https',
      kinds: [...new Set(ids.map((i) => markerKind[i]).filter(Boolean))], values: ids.map((i) => markerLabel[i]).filter(Boolean).slice(0, 8),
      encodings: how.map((e) => e.replace('+zip', ' (zip içinde)').replace('+gzip', ' (gzip içinde)')), archive: !!h.archive,
    })
  }
  const sentHosts = new Set(sent.map((s) => s.host))
  // Likely sent: only when it touched the baits, then opened a connection to an upload/chat API or pushed real data out.
  const touched = reads.size > 0 || packed.length > 0
  const uploads = touched ? (scan?.flows || [])
    .filter((f) => !sentHosts.has(f.host || f.dst) && !BENIGN_HOST.test(f.host || '') && (EXFIL_HOST.test(f.host || '') ? f.bytes > 600 : f.bytes > 20_000))
    .slice(0, 8).map((f) => ({ host: f.host || f.dst, dst: f.dst, port: f.dport, kb: Math.round(f.bytes / 102.4) / 10, exfil_api: EXFIL_HOST.test(f.host || '') })) : []

  // only an address replacing ours is a clipper (CAPE's human module also pastes random words)
  const CRYPTO_ADDR = /^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|[1-9A-HJ-NP-Za-km-z]{32,44})$/
  const clipboard = (guest?.clipboard || []).filter((c) => CRYPTO_ADDR.test(String(c.got || '').trim())).map((c) => ({ expected: c.expected, got: c.got, after_s: c.t }))
  const hooks = scan?.webhooks || []
  const bots = scan?.bots || []
  // Strings of the file itself sometimes carry the webhook/bot even when the traffic was TLS we could not open.
  for (const u of job?.static?.indicators?.urls || []) {
    if (/discord(app)?\.com\/api\/(v\d+\/)?webhooks\/\d+\//i.test(u) && !hooks.includes(u)) hooks.push(u)
    const b = /api\.telegram\.org\/bot(\d{8,11}:[A-Za-z0-9_-]{35})/.exec(u); if (b && !bots.includes(b[1])) bots.push(b[1])
  }
  const endpoints = { webhooks: hooks.map(maskHook), bots: bots.map(maskBot), chat_ids: scan?.chat_ids || [] }

  // The plain-language chain per kind: "Discord token'ını OKUDU → ZIP'LEDİ → api.telegram.org adresine GÖNDERDİ".
  const order = Object.keys(KINDS)
  const kinds = new Set([...reads.keys(), ...packed.flatMap((p) => p.kinds), ...sent.flatMap((s) => s.kinds)])
  const chains = [...kinds].sort((a, b) => order.indexOf(a) - order.indexOf(b)).map((kind) => {
    const r = reads.get(kind)
    const pk = packed.find((p) => p.kinds.includes(kind))
    const sn = sent.filter((s) => s.kinds.includes(kind))
    const steps = []
    if (r || pk || sn.length) steps.push({ step: 'read', by: r ? [...r.processes].slice(0, 3) : [] })
    if (pk) steps.push({ step: 'packed', archive: pk.archive, file: procName(pk.file) })
    if (sn.length) steps.push({ step: 'sent', to: [...new Set(sn.map((s) => s.host))].slice(0, 3), proof: 'content' })
    else if (uploads.length && (r || pk) && KINDS[kind].strong) steps.push({ step: 'sent', to: uploads.slice(0, 2).map((u) => u.host), proof: 'connection' })
    const text = `${KINDS[kind].label[0].toUpperCase()}${KINDS[kind].label.slice(1)} ` + steps.map((s) =>
      s.step === 'read' ? 'OKUDU' : s.step === 'packed' ? (s.archive ? "ZIP'LEDİ" : 'PAKETLEDİ') : s.proof === 'content' ? `${s.to.join(', ')} adresine GÖNDERDİ` : `${s.to.join(', ')} adresine bağlandı (büyük ihtimalle gönderdi)`).join(' → ')
    return { kind, strong: KINDS[kind].strong, steps, text }
  })

  const strongRead = [...reads.keys()].filter((k) => KINDS[k]?.strong)
  const proof = packed.length > 0 || sent.length > 0 || clipboard.length > 0 || strongRead.length >= 3
  const clipText = clipboard.length ? [{ kind: 'clipboard', strong: true, steps: [], text: `Panodaki kripto adresini DEĞİŞTİRDİ (${clipboard[0].expected.slice(0, 8)}… → ${String(clipboard[0].got).slice(0, 14)}…): clipper` }] : []
  return {
    task: run.task_id, finished_at: Date.now(), audit: !!guest?.audit, guest_ok: !!guest, monitor_missed: (activity?.unmonitored || []).length > 0,
    reads: [...reads.values()].map((r) => ({ kind: r.kind, processes: [...r.processes].slice(0, 5), files: [...r.files].slice(0, 6), source: [...r.source] })),
    packed: packed.slice(0, 12), unreadable_archives: unreadableArchives, sent: sent.slice(0, 12), uploads, clipboard, endpoints,
    chains: [...clipText, ...chains], proof, strong_reads: strongRead,
    flows: (scan?.flows || []).filter((f) => !BENIGN_HOST.test(f.host || '')).slice(0, 15).map((f) => ({ host: f.host || f.dst, port: f.dport, kb: Math.round(f.bytes / 102.4) / 10 })),
    trap_url: run.bait.trap_url,
    errors: (guest?.errors || []).slice(0, 5),
  }
}
const maskBotUri = (u) => u.replace(/bot(\d{3})\d+:([A-Za-z0-9_-]{3})[A-Za-z0-9_-]+/, 'bot$1…:$2…')

/** What the report (and the scorer) gets: the result without the raw values. */
function summaryOf(result, used = []) {
  const proof = result.proof || used.length > 0
  const strong = result.strong_reads.length > 0
  const touched = result.reads.length > 0 || result.packed.length > 0
  return {
    verdict: proof ? 'malicious' : strong ? 'suspicious' : touched ? 'suspicious' : 'no_touch',
    ...(proof ? { score: 95 } : strong ? { score: 72 } : touched ? { score: 40 } : {}),
    honey: { status: 'done', ...result, used, proof, headline: (result.chains.find((c) => c.steps.length >= 2) || result.chains[0])?.text || null },
  }
}

// --- the trap login ---------------------------------------------------------------------------------
const recentHit = new Map() // ip:run -> time of the last alert
/** A login attempt on /panel/giris. Returns the run it belongs to (if any); the page always says "wrong password". */
export async function trapAttempt({ user, pass, ip, country, ua }) {
  const u = String(user || '').trim().toLowerCase().slice(0, 120)
  const p = String(pass || '').slice(0, 200)
  if (!u && !p) return null
  const run = db.prepare('SELECT id FROM scan_honey_runs WHERE trap_user = ? OR trap_pass = ? ORDER BY created_at DESC LIMIT 1').get(u, p)
  if (!run) return null
  const r = runRow(run.id)
  const passOk = r.trap_pass === p ? 1 : 0
  db.prepare('INSERT INTO scan_honey_hits (run_id, at, ip, country, ua, user, pass_ok) VALUES (?, ?, ?, ?, ?, ?, ?)').run(r.id, Date.now(), ip, country || null, String(ua || '').slice(0, 200), u.slice(0, 80), passOk)
  const used = honeyHits(r.id)
  if (r.result) {
    setResult(r.job_id, 'honey', 8, { status: 'done', summary: summaryOf(r.result, used) })
    rescoreJob(r.job_id)
  }
  const key = `${ip}:${r.id}`
  if (Date.now() - (recentHit.get(key) || 0) > 6 * 3_600_000) {
    recentHit.set(key, Date.now())
    const job = getJob(r.job_id)
    const info = await ipKind(ip).catch(() => null)
    sendAlert({
      title: '🪤 Çalınan bilgi denendi', tone: 'bad', url: `${config.publicUrl}/scan/r/${r.job_id}`,
      lines: [
        `**${job?.file_name || r.job_id}** dosyasının Token Tuzağı'nda çaldığı panel bilgisi **${ago(Date.now() - r.created_at)}** sonra denendi.`,
        `IP \`${ip}\`${country ? ` · ${country}` : ''}${info?.isp ? ` · ${info.isp}` : ''}${info?.usageType ? ` · ${info.usageType}` : ''}`,
        `Kullanıcı adı ${u === r.trap_user ? 'doğru' : `\`${u.slice(0, 40)}\``}, şifre ${passOk ? 'doğru' : 'farklı'}`,
        ua ? `UA: \`${String(ua).slice(0, 120)}\`` : '',
      ],
    })
  }
  return r.id
}
export const honeyHits = (runId) => db.prepare('SELECT at, country, pass_ok FROM scan_honey_hits WHERE run_id = ? ORDER BY at').all(runId)
  .map((h) => ({ at: h.at, country: h.country, pass_ok: !!h.pass_ok }))
const ago = (ms) => {
  const d = Math.floor(ms / DAY), h = Math.floor((ms % DAY) / 3_600_000), m = Math.floor((ms % 3_600_000) / 60_000)
  return d ? `${d} gün${h ? ` ${h} saat` : ''}` : h ? `${h} saat${m ? ` ${m} dakika` : ''}` : `${Math.max(1, m)} dakika`
}

/** Owner view (Nyx/Rune with an owner key): the run with the unmasked webhooks and bot tokens. */
export function honeyForTools(jobId, owner) {
  const run = latestRun(jobId)
  if (!run) return null
  const res = run.result || null
  const out = { status: run.status, task: run.task_id, created_at: run.created_at, finished_at: run.finished_at, trap_url: run.bait?.trap_url, used: honeyHits(run.id) }
  if (res) {
    const { full, ...rest } = res
    Object.assign(out, rest)
    if (owner && full) out.endpoints_unmasked = full
  }
  return out
}

/** After a restart: keep following the runs CAPE has not reported yet. */
export function resumeHoney() {
  setTimeout(() => {
    for (const r of db.prepare("SELECT id FROM scan_honey_runs WHERE status IN ('queued', 'running')").all()) follow(r.id)
  }, 15_000)
}
