// From 21st.dev "Infinite Slider" (@ibelick / motion-primitives). The react-use-measure dependency is
// replaced by a ResizeObserver; with reduced motion the row simply stands still.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { animate, motion, useMotionValue, useReducedMotion } from 'framer-motion'
import { cn } from '@/lib/utils'

export function InfiniteSlider({ children, gap = 16, duration = 25, durationOnHover, reverse = false, className }: {
  children: ReactNode; gap?: number; duration?: number; durationOnHover?: number; reverse?: boolean; className?: string
}) {
  const reduce = useReducedMotion()
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(0)
  const [current, setCurrent] = useState(duration)
  const [transitioning, setTransitioning] = useState(false)
  const [key, setKey] = useState(0)
  const x = useMotionValue(0)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(() => setWidth(el.scrollWidth))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    if (reduce || !width) return
    const size = width + gap
    const from = reverse ? -size / 2 : 0
    const to = reverse ? 0 : -size / 2
    const controls = transitioning
      ? animate(x, [x.get(), to], { ease: 'linear', duration: current * Math.abs((x.get() - to) / size), onComplete: () => { setTransitioning(false); setKey((k) => k + 1) } })
      : animate(x, [from, to], { ease: 'linear', duration: current, repeat: Infinity, repeatType: 'loop', repeatDelay: 0, onRepeat: () => x.set(from) })
    return controls.stop
  }, [key, x, current, width, gap, transitioning, reverse, reduce])

  const hover = durationOnHover
    ? { onHoverStart: () => { setTransitioning(true); setCurrent(durationOnHover) }, onHoverEnd: () => { setTransitioning(true); setCurrent(duration) } }
    : {}

  return (
    <div className={cn('overflow-hidden', className)}>
      <motion.div ref={ref} className="flex w-max" style={{ x, gap: `${gap}px` }} {...hover}>
        {children}
        {children}
      </motion.div>
    </div>
  )
}
