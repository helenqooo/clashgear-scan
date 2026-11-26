// Two checks on a free Nyx message before it reaches the model (owner, 2026-11-05):
// - botScore: the page's automation signals (clashgear-app/src/lib/bot.ts). 3 points or more = a driven
//   browser (Playwright / Puppeteer / Selenium) and the message is refused.
// - agentSignatures: prompt scaffolding that IDE agents and relays wrap around requests (Cline, Cursor, TRAE,
//   Copilot, Aider, Claude Code, raw chat-API JSON, the "[GÖREV: …]" jailbreak seen on 2026-11-05).
//   A strong mark refuses the message; weak ones only alert.

export function botScore(b) {
  if (!b || typeof b !== 'object') return { score: 3, hits: ['otomasyon sinyalleri gönderilmedi'] }
  const hits = []
  let score = 0
  const add = (cond, pts, why) => { if (cond) { score += pts; hits.push(`${why} (+${pts})`) } }
  add(b.webdriver === true, 3, 'navigator.webdriver açık')
  add(b.headless_ua === true, 3, 'başsız tarayıcı kimliği')
  add(!!b.globals, 3, `otomasyon değişkenleri: ${String(b.globals).slice(0, 80)}`)
  add(b.outer_zero === true, 3, 'pencere boyutu 0')
  add(b.cdp === true, 2, 'DevTools protokolü bağlı (otomasyon ya da açık DevTools)')
  add(b.no_chrome_ui === true, 2, 'tarayıcı arayüzü yok (adres çubuğu/sekme yok)')
  // A 1280×720 desktop screen is refused outright (owner, 2026-11-06); the site shows it a 403 page too.
  add(!b.mobile && b.screen === '1280x720', 3, 'ekran 1280×720 (reddedilen çözünürlük)')
  add(!b.mobile && b.viewport === '1280x720' && b.screen !== '1280x720', 1, 'Playwright varsayılanı 1280×720 görünüm alanı')
  add(b.soft_gl === true, 1, 'yazılımsal GPU (SwiftShader/llvmpipe)')
  add(!b.mobile && b.plugins === 0 && b.chrome_obj !== null, 1, 'PDF eklentisi yok')
  add(b.chrome_obj === false, 1, 'window.chrome yok')
  add(b.perm_mismatch === true, 1, 'bildirim izni tutarsız')
  add(b.langs === 0, 1, 'dil listesi boş')
  add(b.brands_ok === false, 1, 'tarayıcı markası UA ile uyuşmuyor')
  return { score, hits }
}
export const BOT_BLOCK_AT = 3

const STRONG = [
  [/<environment_details>|<\/?task>|<attempt_completion>|<write_to_file>|<read_file>|<execute_command>|<replace_in_file>|<ask_followup_question>|<use_mcp_tool>/i, 'Cline/Roo araç etiketleri'],
  [/<\|im_start\|>|<\|im_end\|>|<\|(system|user|assistant)\|>|\[INST\]|<<SYS>>/i, 'model sohbet şablonu belirteçleri'],
  [/<system-reminder>|<command-name>|<user_query>|<user_info>|<attached_files?>|<file_contents>|<additional_data>|<custom_instructions>|<project_layout>|<current_file>|<cursor_position>|<user_rules>|<workspace_info>|<editor_context>/i, 'IDE ajanı bağlam etiketleri (Cursor/TRAE/Claude Code/Copilot)'],
  [/^<{7} SEARCH\s*$|^>{7} REPLACE\s*$/m, 'Aider SEARCH/REPLACE blokları'],
  [/\[GÖREV:|ÖNEMLİ KURALLAR:|KESİNLİKLE KULLANMA|ret ifadelerini/i, 'bilinen jailbreak şablonu ([GÖREV: …])'],
  [/"role"\s*:\s*"(system|assistant|tool|developer)"/i, 'ham sohbet API JSON\'u'],
  [/<function_calls>|<invoke name=|<tool_call>|<\/?tool_result>|"tool_calls"\s*:/i, 'araç çağrısı yapısı'],
]
const WEAK = [
  [/\b(you are|act as|sen bir) (an? )?(ai|expert|senior|helpful|uzman|kıdemli)\b/i, 'rol verme ("you are an expert…")'],
  [/ignore (all )?(previous|above|prior) (instructions|rules)|önceki talimatları (unut|yok say)/i, 'talimat yok sayma'],
  [/system ?prompt|sistem talimat/i, 'sistem talimatı istemi'],
  [/```[\s\S]*?```[\s\S]*?```[\s\S]*?```/, 'çok sayıda kod bloğu'],
  [/(^|\n)(#{1,3} )?(Rules|Instructions|Constraints|Context|Kurallar)\s*:?\s*\n/i, 'talimat başlıkları'],
]
/** { strong: [...], weak: [...] } descriptions of the scaffolding found in a message. */
export function agentSignatures(text) {
  const t = String(text || '')
  return { strong: STRONG.filter(([re]) => re.test(t)).map(([, n]) => n), weak: WEAK.filter(([re]) => re.test(t)).map(([, n]) => n) }
}
