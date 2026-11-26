// Scan top bar. Behaviour from 21st.dev "Morphing Scroll Navbar" (@laziekiki): a flat full-width bar
// at the top that becomes a floating glass capsule once you scroll, tucks its links away while you
// scroll down, brings them back when you scroll up, and draws reading progress along the top edge.
// Re-done with framer-motion springs (no bounce) and a highlight that slides between links.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion, useReducedMotion } from 'framer-motion'
import { BrandMark } from '@/components/ui/brand'
import { LangToggle } from '@/components/ui/lang-toggle'
import { cn } from '@/lib/utils'

const SPRING = { type: 'spring' as const, bounce: 0, duration: 0.45 }

export function ScanNav({ links, cta, product = 'Scan', home = '/', productClass = 'font-normal text-neutral-500' }: { links: { href: string; label: string }[]; cta: React.ReactNode; product?: string; home?: string; productClass?: string }) {
  const reduce = useReducedMotion()
  const [atTop, setAtTop] = useState(true)
  const [down, setDown] = useState(false)
  const [progress, setProgress] = useState(0)
  const [active, setActive] = useState('')
  const [hover, setHover] = useState<string | null>(null)

  useEffect(() => {
    let lastY = window.scrollY
    let frame = 0
    const update = () => {
      frame = 0
      const y = window.scrollY
      const delta = y - lastY
      setAtTop(y < 8)
      if (delta > 6) setDown(true)
      else if (delta < -6) setDown(false)
      const doc = document.documentElement
      const max = doc.scrollHeight - doc.clientHeight
      setProgress(max > 0 ? Math.min(1, Math.max(0, y / max)) : 0)
      const marker = y + window.innerHeight * 0.34
      let next = ''
      for (const l of links) {
        const el = document.getElementById(l.href.slice(1))
        if (el && el.offsetTop <= marker) next = l.href
      }
      setActive(next)
      lastY = y
    }
    const onScroll = () => { if (!frame) frame = requestAnimationFrame(update) }
    update()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => { window.removeEventListener('scroll', onScroll); if (frame) cancelAnimationFrame(frame) }
  }, [links])

  const floating = !atTop
  const compact = floating && down
  const lit = hover ?? active

  return (
    <>
      <div aria-hidden className="fixed inset-x-0 top-0 z-50 h-px origin-left bg-gradient-to-r from-white/30 via-white to-white/30" style={{ transform: `scaleX(${progress})` }} />
      <nav aria-label="Scan" className="pointer-events-none fixed inset-x-0 top-0 z-40 flex justify-center px-3">
        <motion.div
          initial={false}
          animate={{
            maxWidth: compact ? 560 : floating ? 940 : 1180,
            height: compact ? 50 : floating ? 54 : 64,
            marginTop: floating ? 12 : 0,
            backgroundColor: floating ? 'rgba(18,18,18,0.62)' : 'rgba(18,18,18,0)',
            borderColor: floating ? 'rgba(255,255,255,0.09)' : 'rgba(255,255,255,0)',
            boxShadow: floating ? '0 1px 0 rgba(255,255,255,0.06) inset, 0 18px 50px -24px rgba(0,0,0,0.9)' : '0 0 0 rgba(0,0,0,0)',
          }}
          transition={reduce ? { duration: 0 } : SPRING}
          className={cn('pointer-events-auto flex w-full items-center justify-between gap-4 rounded-2xl border pl-4 pr-2', floating && 'backdrop-blur-xl backdrop-saturate-150')}
        >
          <Link to={home} className="flex shrink-0 items-center gap-2 text-[15px] font-semibold tracking-[-0.01em] text-white">
            <BrandMark size={22} /> ClashGear <span className={productClass}>{product}</span>
          </Link>

          <motion.div
            initial={false}
            animate={{ opacity: compact ? 0 : 1, y: compact ? -6 : 0, maxWidth: compact ? 0 : 520 }}
            transition={reduce ? { duration: 0 } : SPRING}
            onMouseLeave={() => setHover(null)}
            className={cn('hidden items-center overflow-hidden md:flex', compact && 'pointer-events-none')}
          >
            {links.map((l) => (
              <a key={l.href} href={l.href} onMouseEnter={() => setHover(l.href)} aria-current={active === l.href ? 'location' : undefined}
                className={cn('relative isolate whitespace-nowrap rounded-lg px-3 py-1.5 text-[13px] transition-colors duration-200', lit === l.href ? 'text-white' : 'text-neutral-400')}>
                {lit === l.href && <motion.span layoutId="scan-nav-pill" transition={SPRING} className="absolute inset-0 -z-10 rounded-lg bg-white/[0.08]" />}
                {l.label}
              </a>
            ))}
          </motion.div>

          <div className="flex shrink-0 items-center gap-2">
            <LangToggle />
            {cta}
          </div>
        </motion.div>
      </nav>
    </>
  )
}
