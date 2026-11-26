// AI avatar orb with blinking eyes, from the owner's 21st.dev "components-primitives-avatar".
// Changes: framer-motion import, a "nyx" preset in the site's graphite/silver-blue palette, eyes
// that look toward a point (`look`, each axis -1..1), and a slow "breathing" while it thinks.
import { useId } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'

export type AvatarColor = 'nyx' | 'blue' | 'violet' | 'vesper'
export type AvatarSize = 'sm' | 'md' | 'lg' | 'xl'

const PRESETS: Record<AvatarColor, { gradient: string; boxShadow: string; iris: string; shine: string }> = {
  nyx: {
    gradient: 'radial-gradient(circle at 50% 45%, #141a24 0%, #3a4a63 40%, #8fa6c8 70%, #e6edf7 100%)',
    boxShadow: '0 0 4px 0 rgba(160,185,220,.35), 0 0 22px 8px rgba(120,150,200,.16), inset 0 0 0 1px rgba(255,255,255,.06)',
    iris: 'linear-gradient(135deg, #ffffff 0%, #dbe6f7 100%)',
    shine: 'radial-gradient(ellipse at 30% 24%, rgba(255,255,255,.7) 0%, rgba(255,255,255,.1) 50%, transparent 70%)',
  },
  blue: {
    gradient: 'radial-gradient(circle at 50% 45%, #0d4d9a 0%, #3d7dd8 40%, #6fb3ff 68%, #e0eeff 100%)',
    boxShadow: '0 0 4px 0px rgba(20,102,216,.35), 0 0 16px 6px rgba(20,102,216,.18), inset 0 0 0 1px rgba(255,255,255,.05)',
    iris: 'linear-gradient(135deg, #ffffff 0%, #d4ecff 100%)',
    shine: 'radial-gradient(ellipse at 30% 24%, rgba(255,255,255,.75) 0%, rgba(255,255,255,.1) 50%, transparent 70%)',
  },
  violet: {
    gradient: 'radial-gradient(circle at 50% 45%, #4a2a7a 0%, #a855f7 40%, #d8b4fe 68%, #f3e8ff 100%)',
    boxShadow: '0 0 4px 0px rgba(168,85,247,.35), 0 0 16px 6px rgba(168,85,247,.18), inset 0 0 0 1px rgba(255,255,255,.05)',
    iris: 'linear-gradient(135deg, #ffffff 0%, #ede9fe 100%)',
    shine: 'radial-gradient(ellipse at 30% 24%, rgba(255,255,255,.75) 0%, rgba(255,255,255,.1) 50%, transparent 70%)',
  },
  // Vesper (ClashGear Motion): the evening star — deep olive core through Higgsfield lime to a pale lime rim.
  vesper: {
    gradient: 'radial-gradient(circle at 50% 45%, #141a03 0%, #3d500b 38%, #a9d313 68%, #f3ffcc 100%)',
    boxShadow: '0 0 4px 0 rgba(209,254,23,.4), 0 0 22px 8px rgba(209,254,23,.16), inset 0 0 0 1px rgba(255,255,255,.06)',
    iris: 'linear-gradient(135deg, #ffffff 0%, #f1ffc2 100%)',
    shine: 'radial-gradient(ellipse at 30% 24%, rgba(255,255,255,.7) 0%, rgba(255,255,255,.1) 50%, transparent 70%)',
  },
}

const SIZE: Record<AvatarSize, { orb: string; eye: string; gap: string; y: string; reach: number }> = {
  sm: { orb: 'size-8', eye: 'w-1 h-1.5', gap: 'gap-1.5', y: '-translate-y-0.5', reach: 2 },
  md: { orb: 'size-12', eye: 'w-1.5 h-2.5', gap: 'gap-2.5', y: '-translate-y-0.5', reach: 3 },
  lg: { orb: 'size-16', eye: 'w-2 h-3', gap: 'gap-3.5', y: '-translate-y-1', reach: 4 },
  xl: { orb: 'size-24', eye: 'w-3 h-[18px]', gap: 'gap-5', y: '-translate-y-1.5', reach: 7 },
}

function Eye({ blinking, delayMs, iris, cls }: { blinking: boolean; delayMs: number; iris: string; cls: string }) {
  return <div className={cn('rounded-full', cls)} style={{ background: iris, ...(blinking ? { animation: `av-blink 3.6s ease-in-out ${delayMs}ms infinite` } : {}) }} />
}

export function AiAvatar({ blinking = true, color = 'nyx', size = 'md', look = { x: 0, y: 0 }, thinking = false, label = 'AI', className }: {
  blinking?: boolean
  color?: AvatarColor
  size?: AvatarSize
  /** where the eyes look, each axis -1..1 */
  look?: { x: number; y: number }
  thinking?: boolean
  label?: string
  className?: string
}) {
  const uid = useId().replace(/\W/g, '')
  const p = PRESETS[color]
  const d = SIZE[size]
  return (
    <motion.div
      role="img"
      aria-label={label}
      whileTap={{ scaleX: 1.15, scaleY: 1.3 }}
      animate={thinking ? { scale: [1, 1.06, 1], rotate: [0, -3, 3, 0] } : { scale: 1, rotate: 0 }}
      transition={thinking ? { duration: 1.6, repeat: Infinity, ease: 'easeInOut' } : { type: 'spring', bounce: 0, duration: 0.5 }}
      className={cn('relative flex shrink-0 cursor-pointer items-center justify-center overflow-hidden rounded-full', d.orb, className)}
      style={{ background: p.gradient, boxShadow: p.boxShadow }}
    >
      <svg aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.2] mix-blend-overlay" width="100%" height="100%">
        <filter id={`n${uid}`} x="0%" y="0%" width="100%" height="100%">
          <feTurbulence type="fractalNoise" baseFrequency="0.72" numOctaves="4" stitchTiles="stitch" />
          <feColorMatrix type="saturate" values="0" />
        </filter>
        <rect width="100%" height="100%" filter={`url(#n${uid})`} />
      </svg>
      <div aria-hidden className="pointer-events-none absolute inset-0" style={{ background: p.shine }} />
      <div aria-hidden className="pointer-events-none absolute inset-0 blur-[2px]" style={{ background: 'radial-gradient(circle at 62% 68%, rgba(0,0,0,0.18) 0%, transparent 55%)' }} />
      <motion.div
        className={cn('relative z-10 flex items-center', d.gap, d.y)}
        animate={{ x: Math.max(-1, Math.min(1, look.x)) * d.reach, y: Math.max(-1, Math.min(1, look.y)) * d.reach * 0.7 }}
        transition={{ type: 'spring', bounce: 0, duration: 0.35 }}
      >
        <Eye blinking={blinking} delayMs={0} iris={p.iris} cls={d.eye} />
        <Eye blinking={blinking} delayMs={60} iris={p.iris} cls={d.eye} />
      </motion.div>
    </motion.div>
  )
}

export default AiAvatar
