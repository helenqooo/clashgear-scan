// 21st.dev "Sentinel Core Eye" (dhileepkumargm): a cybernetic eye whose iris follows the pointer, with
// periodic blinks, a scanning pupil and glowing circuit traces. The component shipped without its CSS,
// so the look is rebuilt here in ClashGear lime; keyframes live in index.css (sentinel-*).
import { useEffect, useRef } from 'react'

export function SentinelEye({ size = 96 }: { size?: number }) {
  const irisRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const move = (x: number, y: number) => {
      const iris = irisRef.current
      const ball = iris?.parentElement
      if (!iris || !ball) return
      const r = ball.getBoundingClientRect()
      const dx = x - (r.left + r.width / 2), dy = y - (r.top + r.height / 2)
      const max = r.width / 4
      const a = Math.atan2(dy, dx), d = Math.min(Math.hypot(dx, dy), max)
      iris.style.transform = `translate(calc(-50% + ${Math.cos(a) * d}px), calc(-50% + ${Math.sin(a) * d}px))`
    }
    const onMouse = (e: MouseEvent) => move(e.clientX, e.clientY)
    const onTouch = (e: TouchEvent) => { const t = e.touches[0]; if (t) move(t.clientX, t.clientY) }
    window.addEventListener('mousemove', onMouse)
    window.addEventListener('touchmove', onTouch, { passive: true })
    return () => { window.removeEventListener('mousemove', onMouse); window.removeEventListener('touchmove', onTouch) }
  }, [])

  const w = size, h = size * 0.62
  return (
    <div className="relative" style={{ width: w * 1.5, height: h * 1.35 }} aria-hidden>
      {/* circuit traces */}
      <span className="sentinel-circuit absolute left-0 top-1/2 h-px w-[22%] -translate-y-1/2 bg-gradient-to-r from-transparent to-[#d4ff3a]" />
      <span className="sentinel-circuit absolute right-0 top-1/2 h-px w-[22%] -translate-y-1/2 bg-gradient-to-l from-transparent to-[#d4ff3a]" style={{ animationDelay: '1.1s' }} />
      <span className="absolute left-[14%] top-[30%] size-1.5 rounded-full bg-[#d4ff3a] shadow-[0_0_8px_#d4ff3a]" />
      <span className="absolute right-[14%] top-[66%] size-1.5 rounded-full bg-[#d4ff3a] shadow-[0_0_8px_#d4ff3a]" />
      {/* eye */}
      <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-[50%] border border-[#d4ff3a]/60 shadow-[0_0_28px_rgba(212,255,58,0.35),inset_0_0_18px_rgba(0,0,0,0.9)]"
        style={{ width: w, height: h, background: 'radial-gradient(circle at 50% 45%, #1b2110, #070806 70%)' }}>
        <div ref={irisRef} className="absolute left-1/2 top-1/2 grid place-items-center rounded-full transition-transform duration-100 ease-out"
          style={{ width: h * 0.78, height: h * 0.78, transform: 'translate(-50%, -50%)', background: 'radial-gradient(circle, #e6ff7a 0%, #d4ff3a 30%, #6f8a12 62%, #20290a 100%)', boxShadow: '0 0 18px rgba(212,255,58,0.65)' }}>
          <div className="relative overflow-hidden rounded-full bg-black" style={{ width: h * 0.32, height: h * 0.32 }}>
            <span className="sentinel-scan absolute inset-x-0 h-[2px] bg-[#d4ff3a] shadow-[0_0_6px_#d4ff3a]" />
          </div>
        </div>
        {/* eyelids */}
        <span className="sentinel-lid absolute inset-x-0 top-0 h-1/2 origin-top bg-[#070806]" />
        <span className="sentinel-lid absolute inset-x-0 bottom-0 h-1/2 origin-bottom bg-[#070806]" />
      </div>
    </div>
  )
}
