import { useTheme } from '@/theme/ThemeContext'

export function BrandMark({ size = 30, className }: { size?: number; className?: string }) {
  const { theme } = useTheme()
  const src = theme === 'dark' ? '/logo-mark-light.png' : '/logo-mark-dark.png'
  return <img src={src} width={size} height={size} alt="" className={className} />
}

export function BrandWordmark({ className }: { className?: string }) {
  const { theme } = useTheme()
  const src = theme === 'dark' ? '/logo-word-light.png' : '/logo-word-dark.png'
  return <img src={src} alt="ClashGear" className={className} />
}
