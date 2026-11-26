// The scan pages' background: the GradFlow "Glass fold" shader (already used by the main site) in
// a neutral graphite/silver palette, under a scrim that is darkest where the copy sits, so text and
// cards on top always keep their contrast.
import { GlassFold } from '@/components/ui/glass-fold'
import { cn } from '@/lib/utils'

export const SCAN_GLASS = { color1: '#2b2f36', color2: '#0a0b0d', color3: '#d6dce6' }

export function ScanGlass({ className, variant = 'hero' }: { className?: string; variant?: 'hero' | 'top' }) {
  return (
    <div aria-hidden className={cn('pointer-events-none absolute inset-0 -z-10', className)}>
      <GlassFold {...SCAN_GLASS} speed={0.35} scale={1.1} noise={0.07} resolution={0.5} className="h-full w-full" />
      {variant === 'hero' ? (
        <>
          {/* copy column on the left (top on phones) gets the deepest shade */}
          <div className="absolute inset-0 hidden lg:block" style={{ background: 'linear-gradient(90deg, rgba(10,11,13,.86) 0%, rgba(10,11,13,.62) 38%, rgba(10,11,13,.30) 70%, rgba(10,11,13,.42) 100%)' }} />
          <div className="absolute inset-0 lg:hidden" style={{ background: 'linear-gradient(180deg, rgba(10,11,13,.84) 0%, rgba(10,11,13,.66) 50%, rgba(10,11,13,.5) 100%)' }} />
          <div className="absolute inset-0" style={{ background: 'radial-gradient(ellipse 90% 70% at 50% 40%, transparent 40%, rgba(10,11,13,.55) 100%)' }} />
        </>
      ) : (
        <div className="absolute inset-0" style={{ background: 'rgba(10,11,13,.55)' }} />
      )}
    </div>
  )
}
