// Owner's 21st.dev "Liquid Metal Button" (@paper-design/shaders), with a lime (Higgsfield green) crown:
// glowing ring + lime label, and a width prop for longer Turkish labels.
import { liquidMetalFragmentShader, ShaderMount } from '@paper-design/shaders'
import { Sparkles } from 'lucide-react'
import type React from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'

const LIME = '#d4ff3a'

interface LiquidMetalButtonProps {
  label?: string
  onClick?: () => void
  viewMode?: 'text' | 'icon'
  width?: number
  disabled?: boolean
  icon?: React.ReactNode
}

export function LiquidMetalButton({ label = 'Get Started', onClick, viewMode = 'text', width = 142, disabled, icon }: LiquidMetalButtonProps) {
  const [isHovered, setIsHovered] = useState(false)
  const [isPressed, setIsPressed] = useState(false)
  const [ripples, setRipples] = useState<Array<{ x: number; y: number; id: number }>>([])
  const shaderRef = useRef<HTMLDivElement>(null)
  // biome-ignore lint/suspicious/noExplicitAny: External library without types
  const shaderMount = useRef<any>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const rippleId = useRef(0)

  const dimensions = useMemo(() => {
    if (viewMode === 'icon') return { width: 46, height: 46, innerWidth: 42, innerHeight: 42, shaderWidth: 46, shaderHeight: 46 }
    return { width, height: 46, innerWidth: width - 4, innerHeight: 42, shaderWidth: width, shaderHeight: 46 }
  }, [viewMode, width])

  useEffect(() => {
    const styleId = 'shader-canvas-style-exploded'
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style')
      style.id = styleId
      style.textContent = `
        .shader-container-exploded canvas {
          width: 100% !important;
          height: 100% !important;
          display: block !important;
          position: absolute !important;
          top: 0 !important;
          left: 0 !important;
          border-radius: 100px !important;
        }
        @keyframes ripple-animation {
          0% { transform: translate(-50%, -50%) scale(0); opacity: 0.6; }
          100% { transform: translate(-50%, -50%) scale(4); opacity: 0; }
        }
        @keyframes lime-crown { 0%, 100% { opacity: 0.55; } 50% { opacity: 1; } }
      `
      document.head.appendChild(style)
    }
    if (shaderRef.current) {
      try {
        shaderMount.current?.destroy?.()
        shaderMount.current = new ShaderMount(
          shaderRef.current,
          liquidMetalFragmentShader,
          { u_repetition: 4, u_softness: 0.5, u_shiftRed: 0.3, u_shiftBlue: 0.3, u_distortion: 0, u_contour: 0, u_angle: 45, u_scale: 8, u_shape: 1, u_offsetX: 0.1, u_offsetY: -0.1 },
          undefined,
          0.6,
        )
      } catch (error) {
        console.error('liquid metal shader failed:', error)
      }
    }
    return () => {
      shaderMount.current?.destroy?.()
      shaderMount.current = null
    }
  }, [])

  const handleMouseEnter = () => { setIsHovered(true); shaderMount.current?.setSpeed?.(1) }
  const handleMouseLeave = () => { setIsHovered(false); setIsPressed(false); shaderMount.current?.setSpeed?.(0.6) }
  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (disabled) return
    if (shaderMount.current?.setSpeed) {
      shaderMount.current.setSpeed(2.4)
      setTimeout(() => shaderMount.current?.setSpeed?.(isHovered ? 1 : 0.6), 300)
    }
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect()
      const ripple = { x: e.clientX - rect.left, y: e.clientY - rect.top, id: rippleId.current++ }
      setRipples((prev) => [...prev, ripple])
      setTimeout(() => setRipples((prev) => prev.filter((r) => r.id !== ripple.id)), 600)
    }
    onClick?.()
  }

  const ease = 'all 0.8s cubic-bezier(0.34, 1.56, 0.64, 1), width 0.4s ease, height 0.4s ease'
  return (
    <div className="relative inline-block" style={{ opacity: disabled ? 0.6 : 1 }}>
      {/* lime crown */}
      <div aria-hidden style={{ position: 'absolute', inset: -3, borderRadius: 100, boxShadow: `0 0 0 1px ${LIME}88, 0 0 22px ${LIME}55, 0 0 48px ${LIME}22`, animation: 'lime-crown 2.8s ease-in-out infinite', pointerEvents: 'none' }} />
      <div style={{ perspective: '1000px', perspectiveOrigin: '50% 50%' }}>
        <div style={{ position: 'relative', width: dimensions.width, height: dimensions.height, transformStyle: 'preserve-3d', transition: ease, transform: 'none' }}>
          <div style={{ position: 'absolute', top: 0, left: 0, width: dimensions.width, height: dimensions.height, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7, transformStyle: 'preserve-3d', transition: `${ease}, gap 0.4s ease`, transform: 'translateZ(20px)', zIndex: 30, pointerEvents: 'none' }}>
            {viewMode === 'icon' && <Sparkles size={16} style={{ color: LIME, filter: 'drop-shadow(0px 1px 2px rgba(0, 0, 0, 0.5))' }} />}
            {viewMode === 'text' && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 14, color: LIME, fontWeight: 600, textShadow: `0px 1px 2px rgba(0, 0, 0, 0.6), 0 0 12px ${LIME}66`, whiteSpace: 'nowrap', letterSpacing: '-0.01em' }}>
                {icon}
                {label}
              </span>
            )}
          </div>

          <div style={{ position: 'absolute', top: 0, left: 0, width: dimensions.width, height: dimensions.height, transformStyle: 'preserve-3d', transition: ease, transform: `translateZ(10px) ${isPressed ? 'translateY(1px) scale(0.98)' : 'translateY(0) scale(1)'}`, zIndex: 20 }}>
            <div style={{ width: dimensions.innerWidth, height: dimensions.innerHeight, margin: 2, borderRadius: 100, background: 'linear-gradient(180deg, #202020 0%, #000000 100%)', boxShadow: isPressed ? 'inset 0px 2px 4px rgba(0, 0, 0, 0.4), inset 0px 1px 2px rgba(0, 0, 0, 0.3)' : 'none', transition: `${ease}, box-shadow 0.15s cubic-bezier(0.4, 0, 0.2, 1)` }} />
          </div>

          <div style={{ position: 'absolute', top: 0, left: 0, width: dimensions.width, height: dimensions.height, transformStyle: 'preserve-3d', transition: ease, transform: `translateZ(0px) ${isPressed ? 'translateY(1px) scale(0.98)' : 'translateY(0) scale(1)'}`, zIndex: 10 }}>
            <div style={{
              height: dimensions.height, width: dimensions.width, borderRadius: 100, background: 'rgb(0 0 0 / 0)', transition: `${ease}, box-shadow 0.15s cubic-bezier(0.4, 0, 0.2, 1)`,
              boxShadow: isPressed
                ? '0px 0px 0px 1px rgba(0, 0, 0, 0.5), 0px 1px 2px 0px rgba(0, 0, 0, 0.3)'
                : isHovered
                  ? '0px 0px 0px 1px rgba(0, 0, 0, 0.4), 0px 12px 6px 0px rgba(0, 0, 0, 0.05), 0px 8px 5px 0px rgba(0, 0, 0, 0.1), 0px 4px 4px 0px rgba(0, 0, 0, 0.15), 0px 1px 2px 0px rgba(0, 0, 0, 0.2)'
                  : '0px 0px 0px 1px rgba(0, 0, 0, 0.3), 0px 36px 14px 0px rgba(0, 0, 0, 0.02), 0px 20px 12px 0px rgba(0, 0, 0, 0.08), 0px 9px 9px 0px rgba(0, 0, 0, 0.12), 0px 2px 5px 0px rgba(0, 0, 0, 0.15)',
            }}>
              <div ref={shaderRef} className="shader-container-exploded" style={{ borderRadius: 100, overflow: 'hidden', position: 'relative', width: dimensions.shaderWidth, maxWidth: dimensions.shaderWidth, height: dimensions.shaderHeight, transition: 'width 0.4s ease, height 0.4s ease' }} />
            </div>
          </div>

          <button
            ref={buttonRef}
            type="button"
            onClick={handleClick}
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            onMouseDown={() => setIsPressed(true)}
            onMouseUp={() => setIsPressed(false)}
            disabled={disabled}
            style={{ position: 'absolute', top: 0, left: 0, width: dimensions.width, height: dimensions.height, background: 'transparent', border: 'none', cursor: disabled ? 'default' : 'pointer', outline: 'none', zIndex: 40, transformStyle: 'preserve-3d', transform: 'translateZ(25px)', transition: ease, overflow: 'hidden', borderRadius: 100 }}
            aria-label={label}
          >
            {ripples.map((ripple) => (
              <span key={ripple.id} style={{ position: 'absolute', left: ripple.x, top: ripple.y, width: 20, height: 20, borderRadius: '50%', background: 'radial-gradient(circle, rgba(255, 255, 255, 0.4) 0%, rgba(255, 255, 255, 0) 70%)', pointerEvents: 'none', animation: 'ripple-animation 0.6s ease-out' }} />
            ))}
          </button>
        </div>
      </div>
    </div>
  )
}
