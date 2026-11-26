// Presentational take on the owner's 21st.dev "Liquid Multimodal Input": same shell (matte noise,
// inner shade, spinning 1px conic edge, drop glow, attachment cards, toolbar, model chip, send
// button) recoloured to the site's silver palette, and driven by props so a scripted demo can
// "type" into it, attach a file and press send. Refs expose the drop area, text and send button
// so a demo cursor can aim at them.
import { forwardRef, type ReactNode } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ArrowUp, ChevronDown, FileText, Image as ImageIcon, Paperclip, Sparkles } from 'lucide-react'
import { cn } from '@/lib/utils'

const MATTE_NOISE = `url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0.65 0'/></filter><rect width='100%25' height='100%25' filter='url(%23n)'/></svg>")`

export type LiquidInputProps = {
  value: string
  placeholder: string
  files?: { name: string; size?: string }[]
  focused?: boolean
  dragOver?: boolean
  sendPressed?: boolean
  modelLabel?: string
  dropHint?: string
  className?: string
  sendRef?: React.Ref<HTMLSpanElement>
  textRef?: React.Ref<HTMLDivElement>
  footer?: ReactNode
}

export const LiquidInput = forwardRef<HTMLDivElement, LiquidInputProps>(function LiquidInput(
  { value, placeholder, files = [], focused, dragOver, sendPressed, modelLabel = 'Pro', dropHint = 'Drop files here', className, sendRef, textRef },
  ref,
) {
  const canSend = value.trim().length > 0 || files.length > 0
  return (
    <div ref={ref} className={cn('relative w-full', className)}>
      {/* aurora glow while something is dragged over */}
      <motion.div aria-hidden className="pointer-events-none absolute -inset-[2px] rounded-[30px] blur-[10px]" initial={false}
        animate={{ opacity: dragOver ? 0.85 : 0 }} transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
        style={{ background: 'conic-gradient(from 0deg, #8fa6c8, #e6edf7, #8fa6c8, #3a4a63, #8fa6c8)' }} />

      <div className={cn(
        'group relative isolate flex w-full flex-col gap-2 overflow-hidden rounded-[28px] p-3 text-base transition-colors duration-150',
        'border border-white/[0.07] bg-[radial-gradient(ellipse_90%_70%_at_50%_-10%,#161a20_0%,#0a0b0d_72%)]',
        'shadow-[0_1px_2px_rgba(0,0,0,.4),0_8px_24px_-12px_rgba(0,0,0,.6)]',
        focused && 'border-white/[0.16]',
        dragOver && 'border-[#8fa6c8]/50',
      )}>
        <div aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.055] mix-blend-overlay" style={{ backgroundImage: MATTE_NOISE, backgroundSize: '240px 240px' }} />
        <div aria-hidden className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_bottom,rgba(0,0,0,0.12)_0%,transparent_28%,transparent_72%,rgba(0,0,0,0.22)_100%)]" />
        {/* spinning 1px edge, brighter while focused */}
        <div aria-hidden className={cn('lmi-border pointer-events-none absolute inset-0 z-10 rounded-[28px] transition-opacity duration-500', focused ? 'opacity-100' : 'opacity-50')}
          style={{ padding: '1px', WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)', WebkitMaskComposite: 'xor', maskComposite: 'exclude', background: 'conic-gradient(from var(--lmi-angle, 0deg), transparent 65%, rgba(143,166,200,0.6) 80%, #e6edf7 95%, transparent 100%)' }} />

        <div className="relative z-20 w-full min-w-0">
          {/* attachments appear with a spring and leave at once (the message carries them away) */}
          {files.length > 0 && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} transition={{ duration: 0.2 }} className="flex flex-wrap gap-3 px-2 pb-3 pt-1">
                {files.map((f) => (
                  <motion.div key={f.name} initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: 'spring', stiffness: 400, damping: 28 }}
                    className="flex h-14 max-w-[240px] items-center gap-2.5 rounded-xl border border-white/10 bg-white/[0.05] px-3 shadow-sm">
                    <FileText className="size-5 shrink-0 text-neutral-400" />
                    <span className="min-w-0">
                      <span className="block truncate text-xs font-medium text-neutral-100">{f.name}</span>
                      {f.size && <span className="block text-[11px] text-neutral-500">{f.size}</span>}
                    </span>
                  </motion.div>
                ))}
              </motion.div>
          )}
          <div ref={textRef} aria-label="Chat input" className="min-h-[64px] w-full whitespace-pre-wrap px-3 py-1 text-[15px] leading-snug">
            {value ? <span className="text-neutral-100">{value}</span> : <span className="text-neutral-500">{placeholder}</span>}
            {focused && <span className="lmi-caret ml-px inline-block h-[1.05em] w-px translate-y-[0.15em] bg-neutral-200" />}
          </div>
        </div>

        <div className="relative z-20 mt-auto flex w-full items-center gap-1 px-1">
          <span className="grid size-8 place-items-center rounded-full text-neutral-400"><Paperclip className="size-[18px]" /></span>
          <span className="grid size-8 place-items-center rounded-full text-neutral-400"><ImageIcon className="size-[18px]" /></span>
          <div className="ml-auto flex items-center gap-2">
            <span className="inline-flex h-8 items-center gap-1.5 rounded-full px-2.5 text-[13px] font-medium text-neutral-300">
              <Sparkles className="size-4" /> {modelLabel} <ChevronDown className="size-3.5 opacity-70" />
            </span>
            <motion.span ref={sendRef} initial={false} animate={{ scale: sendPressed ? 0.88 : 1 }} transition={{ type: 'spring', stiffness: 400, damping: 22 }}
              className={cn('ml-1 grid size-8 shrink-0 place-items-center rounded-full transition-colors', canSend ? 'bg-white text-black shadow-[0_2px_10px_-2px_rgba(230,237,247,0.45)]' : 'bg-white/10 text-white/30')}>
              <ArrowUp className="size-4" strokeWidth={2.5} />
            </motion.span>
          </div>
        </div>

        <AnimatePresence>
          {dragOver && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.18 }}
              className="pointer-events-none absolute inset-0 z-30 grid place-items-center rounded-[28px] bg-[#0b0d10]/60 backdrop-blur-[2px]">
              <div className="flex items-center gap-2 rounded-full border border-white/15 bg-[#14171c] px-5 py-2.5 text-sm font-semibold text-neutral-100 shadow-xl">
                <Paperclip className="size-4" /> {dropHint}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
})
