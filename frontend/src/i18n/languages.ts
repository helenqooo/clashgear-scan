import type { Dict } from './content'
import type { MiniDict } from './miniapp'

// Every language the site and Mini App ship. Keep in sync with clashgear-backend/src/langs.js.
export const LANGS = [
  { code: 'en', name: 'English', flag: '🇬🇧' },
  { code: 'tr', name: 'Türkçe', flag: '🇹🇷' },
  { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  { code: 'uk', name: 'Українська', flag: '🇺🇦' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'pt', name: 'Português', flag: '🇧🇷' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'it', name: 'Italiano', flag: '🇮🇹' },
  { code: 'pl', name: 'Polski', flag: '🇵🇱' },
  { code: 'nl', name: 'Nederlands', flag: '🇳🇱' },
  { code: 'ar', name: 'العربية', flag: '🇸🇦' },
  { code: 'fa', name: 'فارسی', flag: '🇮🇷' },
  { code: 'az', name: 'Azərbaycan', flag: '🇦🇿' },
  { code: 'id', name: 'Indonesia', flag: '🇮🇩' },
  { code: 'vi', name: 'Tiếng Việt', flag: '🇻🇳' },
  { code: 'th', name: 'ไทย', flag: '🇹🇭' },
  { code: 'hi', name: 'हिन्दी', flag: '🇮🇳' },
  { code: 'zh', name: '中文', flag: '🇨🇳' },
  { code: 'ja', name: '日本語', flag: '🇯🇵' },
  { code: 'ko', name: '한국어', flag: '🇰🇷' },
] as const

export type LangCode = (typeof LANGS)[number]['code']

const CODES = new Set<string>(LANGS.map((l) => l.code))
export const isLang = (v: unknown): v is LangCode => typeof v === 'string' && CODES.has(v)

/** "pt-BR" -> "pt" when supported, else null. */
export const supportedLang = (tag?: string | null): LangCode | null => {
  const c = String(tag || '').slice(0, 2).toLowerCase()
  return isLang(c) ? c : null
}

// ISO country -> site language. Countries not listed fall back to English.
const BY_LANG: Record<Exclude<LangCode, 'en'>, string[]> = {
  tr: ['TR', 'CY'],
  ru: ['RU', 'BY', 'KZ', 'KG', 'TJ', 'UZ', 'TM', 'AM', 'MD', 'GE'],
  uk: ['UA'],
  es: ['ES', 'MX', 'AR', 'CO', 'CL', 'PE', 'VE', 'EC', 'GT', 'CU', 'BO', 'DO', 'HN', 'PY', 'SV', 'NI', 'CR', 'PA', 'UY', 'PR', 'GQ'],
  pt: ['BR', 'PT', 'AO', 'MZ', 'CV', 'GW', 'ST', 'TL'],
  de: ['DE', 'AT', 'CH', 'LI'],
  fr: ['FR', 'BE', 'LU', 'MC', 'SN', 'CI', 'CM', 'ML', 'BF', 'NE', 'TG', 'BJ', 'GA', 'CG', 'CD', 'GN', 'MG', 'HT'],
  it: ['IT', 'SM', 'VA'],
  pl: ['PL'],
  nl: ['NL', 'SR'],
  ar: ['SA', 'AE', 'EG', 'IQ', 'JO', 'KW', 'QA', 'BH', 'OM', 'LB', 'SY', 'YE', 'LY', 'DZ', 'MA', 'TN', 'SD', 'PS', 'MR'],
  fa: ['IR', 'AF'],
  az: ['AZ'],
  id: ['ID'],
  vi: ['VN'],
  th: ['TH'],
  hi: ['IN'],
  zh: ['CN', 'TW', 'HK', 'MO'],
  ja: ['JP'],
  ko: ['KR'],
}
const COUNTRY_LANG: Record<string, LangCode> = Object.fromEntries(
  Object.entries(BY_LANG).flatMap(([lang, countries]) => countries.map((c) => [c, lang as LangCode])),
)
export const langForCountry = (country?: string | null): LangCode => COUNTRY_LANG[String(country || '').toUpperCase()] || 'en'

/** BCP-47 tag for number/date formatting. */
export const localeTag = (lang: LangCode) => (lang === 'tr' ? 'tr-TR' : lang === 'en' ? 'en-US' : lang)

// Non-tr/en languages live in ./locales/<code>.ts and are fetched on demand.
type LocaleModule = { site: Dict; mini: MiniDict }
const loaders = import.meta.glob<LocaleModule>('./locales/*.ts')
export function loadLocale(lang: LangCode) {
  const load = loaders[`./locales/${lang}.ts`]
  return load ? load() : Promise.resolve(null)
}
