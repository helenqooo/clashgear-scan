// Adapted from 21st.dev "Vertical Tabs" (@0xUrvish): a numbered list on the left, the active item's
// panel on the right, auto-advancing with a progress rail. Tuned to Apple's motion rules: critically
// damped springs (no bounce), autoplay pauses on hover/focus and stops for good once the user picks
// an item, arrow keys move between items, and reduced motion cross-fades instead of sliding.
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { cn } from '@/lib/utils'

export type VerticalTabItem = { id: string; title: string; description: string; panel: ReactNode }

const SPRING = { type: 'spring' as const, bounce: 0, duration: 0.4 }

export function VerticalTabs({ items, autoPlayMs = 5000, className }: { items: VerticalTabItem[]; autoPlayMs?: number; className?: string }) {
  const reduce = useReducedMotion()
  const [active, setActive] = useState(0)
  const [direction, setDirection] = useState(1)
  const [hovered, setHovered] = useState(false)
  const [userPicked, setUserPicked] = useState(false)
  const playing = !hovered && !userPicked && !reduce

  const go = useCallback((i: number, user = false) => {
    const n = (i + items.length) % items.length
    setDirection(n > active || (active === items.length - 1 && n === 0) ? 1 : -1)
    setActive(n)
    if (user) setUserPicked(true)
  }, [active, items.length])

  useEffect(() => {
    if (!playing) return
    const t = window.setTimeout(() => go(active + 1), autoPlayMs)
    return () => window.clearTimeout(t)
  }, [active, playing, autoPlayMs, go])

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); go(active + 1, true) }
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') { e.preventDefault(); go(active - 1, true) }
  }

  const variants = {
    enter: (d: number) => (reduce ? { opacity: 0 } : { y: d > 0 ? 24 : -24, opacity: 0, filter: 'blur(6px)' }),
    center: { y: 0, opacity: 1, filter: 'blur(0px)' },
    exit: (d: number) => (reduce ? { opacity: 0 } : { y: d > 0 ? -24 : 24, opacity: 0, filter: 'blur(6px)' }),
  }

  return (
    <div className={cn('grid grid-cols-1 items-start gap-10 lg:grid-cols-12 lg:gap-16', className)} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
      <div role="tablist" aria-orientation="vertical" onKeyDown={onKey} className="flex flex-col lg:col-span-5">
        {items.map((it, i) => {
          const on = i === active
          return (
            <button
              key={it.id}
              role="tab"
              aria-selected={on}
              tabIndex={on ? 0 : -1}
              onClick={() => go(i, true)}
              onFocus={() => setHovered(true)}
              onBlur={() => setHovered(false)}
              className={cn(
                'group relative flex items-start gap-4 border-t border-white/[0.06] py-3.5 pl-5 text-left outline-none transition-colors duration-200 first:border-0',
                'focus-visible:bg-white/[0.03]',
                on ? 'text-foreground' : 'text-muted-foreground/70 hover:text-foreground',
              )}
            >
              <span className="absolute bottom-0 left-0 top-0 w-px bg-white/10">
                {on && (
                  <motion.span
                    key={`${active}-${playing}`}
                    className="absolute left-0 top-0 w-full origin-top bg-white"
                    initial={{ height: playing ? '0%' : '100%' }}
                    animate={{ height: '100%' }}
                    transition={playing ? { duration: autoPlayMs / 1000, ease: 'linear' } : { duration: 0 }}
                  />
                )}
              </span>
              <span className="mt-1 w-6 shrink-0 text-[10px] font-medium tabular-nums opacity-50">{it.id}</span>
              <span className="flex flex-1 flex-col gap-1.5">
                <span className="text-[17px] font-medium tracking-[-0.01em]">{it.title}</span>
                <AnimatePresence initial={false}>
                  {on && (
                    <motion.span initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={SPRING} className="block overflow-hidden">
                      <span className="block max-w-sm pb-1 text-sm leading-relaxed text-muted-foreground">{it.description}</span>
                    </motion.span>
                  )}
                </AnimatePresence>
              </span>
            </button>
          )
        })}
      </div>

      <div className="lg:sticky lg:top-24 lg:col-span-7">
        <div className="relative min-h-[360px] overflow-hidden rounded-3xl border border-white/[0.08] bg-white/[0.02]">
          <AnimatePresence initial={false} custom={direction} mode="popLayout">
            <motion.div key={active} custom={direction} variants={variants} initial="enter" animate="center" exit="exit" transition={SPRING} className="h-full w-full">
              {items[active]?.panel}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
