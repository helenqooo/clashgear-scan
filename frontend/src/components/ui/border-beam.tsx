// From 21st.dev "Border Beam" (@gooseui): a beam of light that travels along a container's border.
// Put it inside a `relative` element with rounded corners; it inherits the radius.
import type { CSSProperties } from 'react'
import { cn } from '@/lib/utils'

export function BorderBeam({ className, duration = 12, delay = 0, colorFrom = 'rgba(255,255,255,0.9)', colorTo = 'rgba(255,255,255,0.15)', borderWidth = 1 }: {
  className?: string; duration?: number; delay?: number; colorFrom?: string; colorTo?: string; borderWidth?: number
}) {
  return (
    <div
      aria-hidden
      className={cn('border-beam pointer-events-none absolute inset-0 rounded-[inherit]', className)}
      style={{ '--duration': `${duration}s`, '--delay': `-${delay}s`, '--color-from': colorFrom, '--color-to': colorTo, '--border-width': `${borderWidth}px` } as CSSProperties}
    >
      <div className="border-beam-ring absolute inset-0 rounded-[inherit]" />
    </div>
  )
}
