// From 21st.dev "Animated Radial Chart" (@isaiahbjork). Added: arc colour follows the value
// (green -> amber -> red) and an optional caption under the number.
import { motion, useMotionValue, useTransform, animate } from 'framer-motion'
import { useEffect, useId } from 'react'
import { cn } from '@/lib/utils'

interface AnimatedRadialChartProps {
  value?: number
  size?: number
  strokeWidth?: number
  className?: string
  showLabels?: boolean
  duration?: number
  caption?: string
  /** arc gradient (3 stops); default follows the value (risk tone) */
  colors?: [string, string, string]
}

const tone = (v: number) => (v >= 70 ? ['#fcd34d', '#f59e0b', '#d97706'] : v >= 35 ? ['#facc15', '#f59e0b', '#ea580c'] : ['#34d399', '#10b981', '#059669'])

export function AnimatedRadialChart({ value = 74, size = 300, strokeWidth: customStrokeWidth, className, showLabels = true, duration = 2, caption, colors }: AnimatedRadialChartProps) {
  const uid = useId().replace(/:/g, '')
  const strokeWidth = customStrokeWidth ?? Math.max(12, size * 0.06)
  const radius = size * 0.35
  const center = size / 2
  const circumference = Math.PI * radius
  const innerLineRadius = radius - strokeWidth - 4

  const animatedValue = useMotionValue(0)
  const offset = useTransform(animatedValue, [0, 100], [circumference, 0])
  const progressAngle = useTransform(animatedValue, [0, 100], [-Math.PI, 0])
  const innerRadius = radius - strokeWidth / 2
  const x1 = useTransform(progressAngle, (a) => center + Math.cos(a) * innerRadius)
  const y1 = useTransform(progressAngle, (a) => center + Math.sin(a) * innerRadius)
  const x2 = useTransform(progressAngle, (a) => center + Math.cos(a) * innerRadius - Math.cos(a) * 30)
  const y2 = useTransform(progressAngle, (a) => center + Math.sin(a) * innerRadius - Math.sin(a) * 30)
  const shown = useTransform(animatedValue, (latest) => Math.round(latest))

  useEffect(() => {
    const controls = animate(animatedValue, value, { duration, ease: 'easeOut' })
    return controls.stop
  }, [value, animatedValue, duration])

  const fontSize = Math.max(16, size * 0.1)
  const labelFontSize = Math.max(12, size * 0.04)
  const [c0, c1, c2] = colors ?? tone(value)

  return (
    <div className={cn('relative', className)} style={{ width: size, height: size * 0.7 }}>
      <svg width={size} height={size * 0.7} viewBox={`0 0 ${size} ${size * 0.7}`} className="overflow-visible">
        <defs>
          <linearGradient id={`base-${uid}`} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
            <stop offset="50%" stopColor="#d1d5db" stopOpacity="0.7" />
            <stop offset="100%" stopColor="#6b7280" stopOpacity="0.6" />
          </linearGradient>
          <linearGradient id={`progress-${uid}`} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={c0} />
            <stop offset="50%" stopColor={c1} />
            <stop offset="100%" stopColor={c2} />
          </linearGradient>
          <linearGradient id={`text-${uid}`} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.7" />
            <stop offset="50%" stopColor="#d1d5db" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#6b7280" stopOpacity="0.3" />
          </linearGradient>
          <filter id={`shadow-${uid}`} x="-50%" y="-50%" width="200%" height="200%">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#000000" floodOpacity="0.3" />
          </filter>
        </defs>
        <path d={`M ${center - innerLineRadius} ${center} A ${innerLineRadius} ${innerLineRadius} 0 0 1 ${center + innerLineRadius} ${center}`} fill="none" stroke="#6b7280" strokeWidth="1" opacity="0.6" />
        <path d={`M ${center - radius} ${center} A ${radius} ${radius} 0 0 1 ${center + radius} ${center}`} fill="none" stroke={`url(#base-${uid})`} strokeWidth={strokeWidth} filter={`url(#shadow-${uid})`} />
        <motion.path
          d={`M ${center - radius} ${center} A ${radius} ${radius} 0 0 1 ${center + radius} ${center}`}
          fill="none"
          stroke={`url(#progress-${uid})`}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          filter={`url(#shadow-${uid})`}
        />
        <motion.line x1={x1} y1={y1} x2={x2} y2={y2} stroke={`url(#text-${uid})`} strokeWidth="1" />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.div className="mt-10 font-bold tracking-tight" style={{ fontSize: `${fontSize}px` }} initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.5, delay: duration * 0.75 }}>
          <span className="bg-gradient-to-r from-foreground to-muted-foreground bg-clip-text text-transparent">
            <motion.span>{shown}</motion.span>
            <span className="text-[0.5em]">/100</span>
          </span>
        </motion.div>
        {caption && <div className="text-xs font-medium uppercase tracking-widest text-muted-foreground">{caption}</div>}
      </div>

      {showLabels && (
        <>
          <motion.div className="absolute font-medium text-gray-400" style={{ fontSize: `${labelFontSize}px`, left: center - radius - 5, top: center + strokeWidth / 2 }} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: duration * 0.25 }}>0</motion.div>
          <motion.div className="absolute font-medium text-gray-400" style={{ fontSize: `${labelFontSize}px`, left: center + radius - 20, top: center + strokeWidth / 2 }} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: duration * 0.25 }}>100</motion.div>
        </>
      )}
    </div>
  )
}
