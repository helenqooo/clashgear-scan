import { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'

// Text that, when it changes, breaks up before it settles (the Nyx → Rune handover in the chat header):
// the old characters scramble into glyphs with a red/cyan channel split and sliced jitter, then each
// character of the new text locks in, left to right. Reduced motion swaps at once.
const GLYPHS = '!<>-_\\/[]{}=+*^?#01xz§¤░▒'
const DURATION = 700

/** `animate` false swaps at once (e.g. opening another chat); only a live handover breaks the text up. */
export function GlitchText({ text, animate = true, className }: { text: string; animate?: boolean; className?: string }) {
  const [shown, setShown] = useState(text)
  const [glitching, setGlitching] = useState(false)
  const prev = useRef(text)

  useEffect(() => {
    if (prev.current === text) return
    const from = prev.current
    prev.current = text
    if (!animate || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) { setShown(text); setGlitching(false); return }
    setGlitching(true)
    const len = Math.max(from.length, text.length)
    const start = performance.now()
    let raf = 0
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / DURATION)
      let out = ''
      for (let i = 0; i < len; i++) {
        const lockAt = 0.4 + (i / len) * 0.5 // each new character settles at its own moment
        if (p >= lockAt) out += text[i] ?? ''
        else if (p < 0.12) out += from[i] ?? ''
        else out += Math.random() < 0.75 ? GLYPHS[(Math.random() * GLYPHS.length) | 0] : (from[i] ?? text[i] ?? '')
      }
      setShown(out)
      if (p < 1) raf = requestAnimationFrame(tick)
      else { setShown(text); setGlitching(false) }
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [text])

  return (
    <span data-glitch={glitching} data-text={shown} className={cn('cg-glitch relative inline-block whitespace-pre', className)}>
      {shown}
      <style>{`
        .cg-glitch[data-glitch=true] { animation: cg-glitch-shake 90ms steps(2) infinite; text-shadow: 1.5px 0 rgba(251,113,133,.9), -1.5px 0 rgba(34,211,238,.75); }
        .cg-glitch[data-glitch=true]::before, .cg-glitch[data-glitch=true]::after {
          content: attr(data-text); position: absolute; inset: 0; pointer-events: none; overflow: hidden;
        }
        .cg-glitch[data-glitch=true]::before { color: rgb(251,113,133); animation: cg-glitch-slice-a 160ms steps(3) infinite; }
        .cg-glitch[data-glitch=true]::after { color: rgb(34,211,238); animation: cg-glitch-slice-b 200ms steps(3) infinite; }
        @keyframes cg-glitch-shake { 0% { transform: translate(0) skewX(0) } 50% { transform: translate(-1px, 1px) skewX(-8deg) } 100% { transform: translate(1px, -1px) skewX(6deg) } }
        @keyframes cg-glitch-slice-a { 0% { clip-path: inset(0 0 70% 0); transform: translateX(-3px) } 50% { clip-path: inset(40% 0 30% 0); transform: translateX(3px) } 100% { clip-path: inset(75% 0 0 0); transform: translateX(-2px) } }
        @keyframes cg-glitch-slice-b { 0% { clip-path: inset(60% 0 10% 0); transform: translateX(3px) } 50% { clip-path: inset(10% 0 65% 0); transform: translateX(-3px) } 100% { clip-path: inset(30% 0 45% 0); transform: translateX(2px) } }
      `}</style>
    </span>
  )
}
