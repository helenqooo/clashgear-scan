import { cn } from '@/lib/utils'

// Rune, Nyx's reverse-engineering agent: the owner's 21st "Ask AI" mascot (a breathing blob with two
// blinking eyes) in rose, so it reads as a different agent from Nyx's lime. `awake` = Rune is working:
// the blob tilts and the eyes look down at the code.
export function RuneMascot({ awake = false, size = 28, className }: { awake?: boolean; size?: number; className?: string }) {
  const eye = Math.max(2, Math.round(size / 9))
  return (
    <span aria-hidden data-awake={awake}
      className={cn('relative inline-flex shrink-0 items-center justify-center bg-rose-400 text-rose-950 shadow-[0_0_18px_-4px_rgba(251,113,133,0.55)] transition-transform duration-[440ms] ease-[cubic-bezier(.22,1.5,.5,1)] [animation:rune-blob_9s_ease-in-out_infinite] data-[awake=true]:rotate-6 data-[awake=true]:scale-[1.05]', className)}
      style={{ width: size, height: size }}>
      <span className={cn('flex transition-transform duration-300', awake ? 'translate-x-px translate-y-[2px]' : 'translate-x-px -translate-y-px')} style={{ gap: Math.round(size / 5.5) }}>
        <span className="block rounded-[5px] bg-current [animation:rune-blink_6.5s_infinite]" style={{ width: eye, height: Math.round(size / 3.8) }} />
        <span className="block rounded-[5px] bg-current [animation:rune-blink_6.5s_infinite]" style={{ width: eye, height: Math.round(size / 3.8) }} />
      </span>
      <style>{`
        @keyframes rune-blob {
          0%, 100% { border-radius: 58% 42% 55% 45% / 52% 58% 42% 48%; }
          33% { border-radius: 45% 55% 48% 52% / 58% 44% 56% 42%; }
          66% { border-radius: 52% 48% 42% 58% / 45% 52% 48% 55%; }
        }
        @keyframes rune-blink {
          0%, 42%, 46%, 100% { transform: scaleY(1); }
          44% { transform: scaleY(.12); }
        }
        @media (prefers-reduced-motion: reduce) { [data-awake] { animation: none !important; } }
      `}</style>
    </span>
  )
}
