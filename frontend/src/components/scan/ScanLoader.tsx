// Full-screen loading screen in front of the scan landing. It holds the page (scroll locked) until
// the fonts and the prism's 3D code are in, so nothing pops in on the first scroll. On a slow
// network it offers a skip after a few seconds and stops waiting after 12 s.
import { useEffect, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { BrandMark } from '@/components/ui/brand'
import { TextShimmer } from '@/components/ui/text-shimmer'
import { useScan } from '@/i18n/scan'

const MIN_MS = 700
const SKIP_AFTER_MS = 4000
const GIVE_UP_MS = 12000
const TASKS = 2

export function ScanLoader() {
  const { t } = useScan()
  const reduce = useReducedMotion()
  const [done, setDone] = useState(0)
  const [canSkip, setCanSkip] = useState(false)
  const [open, setOpen] = useState(true)

  useEffect(() => {
    const root = document.documentElement
    root.style.overflow = 'hidden'
    window.scrollTo(0, 0)
    const t0 = performance.now()
    let alive = true
    const finish = () => {
      const wait = Math.max(0, MIN_MS - (performance.now() - t0))
      setTimeout(() => { if (alive) setOpen(false) }, wait)
    }
    const bump = () => setDone((n) => n + 1)
    Promise.all([
      document.fonts?.ready.then(bump, bump) ?? bump(),
      import('./PrismSection').then(bump, bump),
    ]).then(finish)
    const skip = setTimeout(() => setCanSkip(true), SKIP_AFTER_MS)
    const giveUp = setTimeout(finish, GIVE_UP_MS)
    return () => {
      alive = false
      clearTimeout(skip)
      clearTimeout(giveUp)
      root.style.overflow = ''
    }
  }, [])

  useEffect(() => { if (!open) document.documentElement.style.overflow = '' }, [open])

  const pct = Math.round((done / TASKS) * 100)

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="scan-loader"
          role="status"
          aria-live="polite"
          aria-label={t.loader.title}
          initial={{ opacity: 1 }}
          exit={reduce ? { opacity: 0 } : { opacity: 0, scale: 1.04, filter: 'blur(14px)' }}
          transition={{ type: 'spring', bounce: 0, duration: 0.7 }}
          className="fixed inset-0 z-[100] flex flex-col items-center justify-center bg-[#0a0b0d] px-6"
        >
          <motion.div initial={{ opacity: 0, y: 8, filter: 'blur(8px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} transition={{ type: 'spring', bounce: 0, duration: 0.6 }}
            className="flex flex-col items-center">
            <div className="flex items-center gap-2.5 text-lg font-semibold tracking-[-0.01em] text-white">
              <BrandMark size={28} /> ClashGear <span className="font-normal text-neutral-500">Scan</span>
            </div>
            <div className="mt-10 h-px w-56 overflow-hidden rounded-full bg-white/10 sm:w-72">
              <motion.div className="h-full origin-left bg-white" initial={{ scaleX: 0.08 }} animate={{ scaleX: Math.max(0.08, pct / 100) }} transition={{ type: 'spring', bounce: 0, duration: 0.5 }} />
            </div>
            <div className="mt-4 flex w-56 items-center justify-between text-[12px] text-neutral-500 sm:w-72">
              <TextShimmer>{t.loader.title}</TextShimmer>
              <span className="tabular-nums text-neutral-400">{pct}%</span>
            </div>
            <AnimatePresence>
              {canSkip && (
                <motion.button key="skip" type="button" onClick={() => setOpen(false)} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  className="press mt-8 rounded-lg px-3 py-1.5 text-[12px] text-neutral-500 transition-colors hover:text-white">
                  {t.loader.skip}
                </motion.button>
              )}
            </AnimatePresence>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
