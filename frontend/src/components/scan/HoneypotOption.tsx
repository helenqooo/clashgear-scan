// Upload-form option: run Token Tuzağı (honeypot) on the file right after upload. A checkbox row with the "Yeni" badge
// and an info icon whose explanation opens on hover, focus or tap.
import { useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { Check, Info } from 'lucide-react'
import { scanApi } from '@/lib/scanApi'
import { cn } from '@/lib/utils'

export function HoneypotOption({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  const [info, setInfo] = useState<{ available: boolean; seconds: number; left: number | null } | null>(null)
  const [open, setOpen] = useState(false)
  const [pinned, setPinned] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => { scanApi.honeyInfo().then(setInfo).catch(() => {}) }, [])
  // a tapped-open explanation closes on a tap elsewhere
  useEffect(() => {
    if (!pinned) return
    const off = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node)) { setPinned(false); setOpen(false) } }
    document.addEventListener('pointerdown', off)
    return () => document.removeEventListener('pointerdown', off)
  }, [pinned])
  const used = info?.left === 0
  const off = disabled || !info?.available || used
  useEffect(() => { if (off && checked) onChange(false) }, [off, checked, onChange])

  return (
    <div ref={box} className="relative mt-3">
      <div className={cn('flex items-center gap-3 rounded-xl border px-3.5 py-3 transition-colors',
        checked ? 'border-[#D1FE17]/45 bg-[#D1FE17]/[0.06]' : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.04]', off && 'opacity-60')}>
        <button type="button" role="checkbox" aria-checked={checked} disabled={off} onClick={() => onChange(!checked)}
          className="press flex min-w-0 flex-1 items-center gap-3 text-left disabled:cursor-not-allowed">
          <span className={cn('flex size-5 shrink-0 items-center justify-center rounded-md border transition-colors',
            checked ? 'border-[#D1FE17] bg-[#D1FE17] text-black' : 'border-white/25 bg-transparent')}>
            <motion.span initial={false} animate={{ scale: checked ? 1 : 0.4, opacity: checked ? 1 : 0 }} transition={{ type: 'spring', stiffness: 500, damping: 30 }}>
              <Check className="size-3.5" strokeWidth={3} />
            </motion.span>
          </span>
          <span className="rounded-full bg-[#D1FE17] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-black">Yeni</span>
          <span className="text-sm font-medium text-white">Honeypot</span>
          <span className="truncate text-xs text-neutral-500">
            {!info ? '' : !info.available ? 'şu an bakımda' : used ? 'bugünkü hakkın doldu' : info.left == null ? 'sınırsız' : `bugün ${info.left} hakkın var`}
          </span>
        </button>
        <button type="button" aria-label="Honeypot nedir?" aria-expanded={open}
          onMouseEnter={() => setOpen(true)} onMouseLeave={() => { if (!pinned) setOpen(false) }}
          onFocus={() => setOpen(true)} onBlur={() => { if (!pinned) setOpen(false) }}
          onClick={() => { setPinned(!pinned); setOpen(!pinned) }}
          className="press flex size-7 shrink-0 items-center justify-center rounded-full text-neutral-400 transition-colors hover:bg-white/[0.06] hover:text-white">
          <Info className="size-4" />
        </button>
      </div>
      <AnimatePresence>
        {open && (
          <motion.div role="tooltip" initial={{ opacity: 0, y: 6, filter: 'blur(6px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} exit={{ opacity: 0, y: 6, filter: 'blur(6px)' }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="absolute right-0 top-full z-30 mt-2 w-[min(380px,calc(100vw-48px))] rounded-2xl border border-white/10 bg-[#141518]/95 p-4 text-sm shadow-[0_24px_60px_-20px_rgba(0,0,0,0.8)] backdrop-blur">
            <div className="flex items-center gap-2">
              <span className="rounded-full bg-[#D1FE17] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-black">Yeni</span>
              <span className="font-semibold text-white">Honeypot (Token Tuzağı)</span>
            </div>
            <p className="mt-2 leading-relaxed text-neutral-300">
              Dosyan, sahte ama gerçekçi hesaplarla dolu bir Windows makinesinde çalışır: Discord token'ı, tarayıcıda kayıtlı şifreler ve
              çerezler, Steam, Telegram, kripto cüzdanları, panoda bir kripto adresi. Hepsi bu çalıştırmaya özel üretilir.
            </p>
            <ul className="mt-2.5 space-y-1.5 text-neutral-300">
              <li><span className="text-white">Okudu mu:</span> hangi programın hangi yemi açtığını Windows'un kendi kaydı gösterir.</li>
              <li><span className="text-white">Paketledi mi:</span> çalışırken oluşan zip ve dosyalarda yem değerleri aranır.</li>
              <li><span className="text-white">Gönderdi mi:</span> değerler ağ trafiğinde, şifreli HTTPS içinde bile aranır; webhook ve bot adresleri çıkarılır.</li>
            </ul>
            <p className="mt-2.5 leading-relaxed text-neutral-400">
              Çalınan sahte bilgi sonradan denenirse raporuna eklenir. Sonuç raporun Sandbox sekmesinde görünür, yaklaşık 4–5 dakika sürer.
              Dosya yemlere dokunmazsa bu temiz olduğunu kanıtlamaz.
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
