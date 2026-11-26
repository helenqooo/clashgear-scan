import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { Ban, ShieldAlert } from 'lucide-react'

// Nyx's warning (2nd strike) and ban (3rd strike) windows. Layout from 21st.dev "Alert Dialog Layout"
// (ai2, split variant: tinted title band over the body) and the countdown from "CountdownButton"
// (ruixen.ui): the ban's "Anladım" stays disabled for 10 s and can't be dismissed any other way.
export type Misuse = { level: 1 | 2 | 3; reason: string; behavior: string }

const BAN_WAIT = 10

export function NyxMisuseModal({ misuse, onClose }: { misuse: Misuse | null; onClose: () => void }) {
  const reduce = useReducedMotion()
  const ban = misuse?.level === 3
  const [left, setLeft] = useState(0)
  useEffect(() => { setLeft(ban ? BAN_WAIT : 0) }, [misuse, ban])
  useEffect(() => {
    if (left <= 0) return
    const t = window.setTimeout(() => setLeft((s) => s - 1), 1000)
    return () => window.clearTimeout(t)
  }, [left])
  const locked = left > 0
  useEffect(() => {
    if (!misuse) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !locked) onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [misuse, locked, onClose])

  const tone = ban
    ? { band: 'bg-red-500/[0.12] text-red-300 border-red-500/25', ring: 'border-red-500/30', glow: 'shadow-[0_30px_90px_-20px_rgba(239,68,68,0.35)]', btn: 'bg-red-500 text-white hover:bg-red-500/90', fill: 'bg-red-400/30' }
    : { band: 'bg-amber-400/[0.12] text-amber-200 border-amber-400/25', ring: 'border-amber-400/30', glow: 'shadow-[0_30px_90px_-20px_rgba(251,191,36,0.3)]', btn: 'bg-[#d4ff3a] text-black hover:bg-[#c6f02e]', fill: '' }

  return createPortal(
    <AnimatePresence>
      {misuse && misuse.level >= 2 && (
        <>
          <motion.div className="scan-dark dark fixed inset-0 z-[200] bg-black/75 backdrop-blur-md"
            onClick={() => { if (!locked) onClose() }}
            initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.25 }} />
          <div className="scan-dark dark pointer-events-none fixed inset-0 z-[201] flex items-center justify-center p-4">
            <motion.div role="alertdialog" aria-modal="true" aria-labelledby="nyx-misuse-title"
              initial={reduce ? false : { opacity: 0, scale: 0.94, y: 14, filter: 'blur(6px)' }}
              animate={{ opacity: 1, scale: 1, y: 0, filter: 'blur(0px)' }}
              exit={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.96, y: 8 }}
              transition={{ type: 'spring', bounce: 0.25, duration: 0.55 }}
              className={`pointer-events-auto w-full max-w-md overflow-hidden rounded-3xl border bg-[#0d0f0b] text-left ${tone.ring} ${tone.glow}`}>
              <div className={`flex items-center gap-3 border-b px-6 py-4 ${tone.band}`}>
                <motion.span className="flex shrink-0"
                  animate={reduce ? undefined : ban ? { rotate: [0, -12, 12, -8, 8, 0] } : { scale: [1, 1.15, 1] }}
                  transition={{ duration: ban ? 0.6 : 1.4, repeat: ban ? 0 : Infinity, delay: 0.3 }}>
                  {ban ? <Ban className="size-6" /> : <ShieldAlert className="size-6" />}
                </motion.span>
                <h2 id="nyx-misuse-title" className="text-lg font-bold tracking-[-0.01em]">{ban ? 'Nyx seni uzaklaştırdı' : 'Nyx seni uyarıyor'}</h2>
                <span className="ml-auto rounded-full bg-white/10 px-2 py-0.5 text-[11px] font-semibold tabular-nums text-white/80">{misuse.level}/3</span>
              </div>
              <div className="px-6 pb-6 pt-5">
                {ban ? (
                  <>
                    <p className="text-[15px] leading-relaxed text-neutral-200">
                      Nyx üçüncü kez <b className="text-white">{misuse.reason}</b> tespit etti ve seni uzaklaştırdı.
                    </p>
                    <p className="mt-3 text-sm leading-relaxed text-neutral-400">
                      Artık Nyx'e mesaj atamazsın. Dosya taraması ve raporlar açık kalmaya devam ediyor. Bunun bir hata olduğunu düşünüyorsan forumdan ClashGear'a yaz.
                    </p>
                  </>
                ) : (
                  <>
                    <p className="text-[15px] leading-relaxed text-neutral-200">
                      Nyx <b className="text-white">{misuse.reason}</b> tespit etti.
                    </p>
                    <p className="mt-3 text-sm leading-relaxed text-neutral-300">
                      Eğer <b className="text-amber-200">{misuse.behavior}</b> devam edersen Nyx seni uzaklaştırabilir.
                    </p>
                    <p className="mt-3 text-[13px] text-neutral-500">Nyx sadece yüklediğin dosyaların analizi için var.</p>
                  </>
                )}
                <button type="button" disabled={locked} onClick={onClose} autoFocus={!locked}
                  className={`press relative mt-6 h-11 w-full overflow-hidden rounded-xl text-sm font-bold transition-colors disabled:cursor-not-allowed ${locked ? 'bg-white/[0.06] text-neutral-400' : tone.btn}`}>
                  {locked && (
                    <motion.span aria-hidden className={`absolute inset-y-0 left-0 ${tone.fill}`}
                      initial={{ width: '0%' }} animate={{ width: '100%' }} transition={{ duration: BAN_WAIT, ease: 'linear' }} />
                  )}
                  <span className="relative tabular-nums">{locked ? `Anladım (${left})` : 'Anladım'}</span>
                </button>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  )
}
