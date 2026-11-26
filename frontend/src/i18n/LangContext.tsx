import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { content, type Dict } from './content'
import { isLang, langForCountry, loadLocale, type LangCode } from './languages'

const STORAGE_KEY = 'cg-lang'

// `local` is the visitor's country language (from IP) when it is neither TR nor EN; the toggle
// shows it next to TR/EN.
type Ctx = { lang: LangCode; setLang: (l: LangCode) => void; c: Dict; local: LangCode | null }
const LangCtx = createContext<Ctx | null>(null)

function savedLang(): LangCode | null {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    return isLang(saved) ? saved : null
  } catch {
    return null
  }
}

const loaded: Partial<Record<LangCode, Dict>> = { tr: content.tr, en: content.en }

export function LangProvider({ children }: { children: ReactNode }) {
  const [pinned, setPinned] = useState<LangCode | null>(savedLang)
  // Until the IP lookup answers: the saved choice, else Turkish for Turkish browsers, else English.
  const [lang, setLangState] = useState<LangCode>(() => pinned ?? (/^tr/i.test(navigator.language || '') ? 'tr' : 'en'))
  const [local, setLocal] = useState<LangCode | null>(null)
  const [dict, setDict] = useState<Dict>(() => loaded[lang] ?? content.en)

  useEffect(() => {
    let alive = true
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 3500)
    fetch('https://api.country.is/', { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : null))
      .then((data: { country?: string } | null) => {
        if (!alive || !data?.country) return
        // Countries without a listed language get English.
        const byIp = langForCountry(data.country)
        if (byIp !== 'tr' && byIp !== 'en') setLocal(byIp)
        if (!pinned) setLangState(byIp)
      })
      .catch(() => {})
      .finally(() => clearTimeout(timer))
    return () => {
      alive = false
      ctrl.abort()
      clearTimeout(timer)
    }
  }, [pinned])

  // Other languages are split out of the main bundle; keep showing the current text until loaded.
  useEffect(() => {
    let alive = true
    if (loaded[lang]) setDict(loaded[lang]!)
    else
      loadLocale(lang).then((m) => {
        if (!m) return
        loaded[lang] = m.site
        if (alive) setDict(m.site)
      })
    document.documentElement.lang = lang
    return () => {
      alive = false
    }
  }, [lang])

  const setLang = (l: LangCode) => {
    setPinned(l)
    setLangState(l)
    try {
      localStorage.setItem(STORAGE_KEY, l)
    } catch {

    }
  }

  const value = useMemo<Ctx>(() => ({ lang, setLang, c: dict, local }), [lang, dict, local])
  return <LangCtx.Provider value={value}>{children}</LangCtx.Provider>
}

export function useLang() {
  const ctx = useContext(LangCtx)
  if (!ctx) throw new Error('useLang must be used within LangProvider')
  return ctx
}

export function useC() {
  return useLang().c
}
