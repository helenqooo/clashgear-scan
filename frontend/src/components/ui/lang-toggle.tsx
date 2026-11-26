import { useLang } from '@/i18n/LangContext'
import { cn } from '@/lib/utils'
import type { LangCode } from '@/i18n/languages'

// TR and EN are always offered; the visitor's country language (or a saved third choice) joins them.
export function LangToggle({ className }: { className?: string }) {
  const { lang, setLang, local } = useLang()
  const options: LangCode[] = ['tr', 'en']
  for (const extra of [local, lang]) if (extra && !options.includes(extra)) options.push(extra)
  return (
    <div
      role="group"
      aria-label="Language"
      className={cn('inline-flex items-center rounded-full border border-border bg-card/60 p-0.5 text-xs font-medium', className)}
    >
      {options.map((l) => (
        <button
          key={l}
          type="button"
          onClick={() => setLang(l)}
          aria-pressed={lang === l}
          className={cn(
            'rounded-full px-2.5 py-1 uppercase transition-colors',
            lang === l ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {l}
        </button>
      ))}
    </div>
  )
}
