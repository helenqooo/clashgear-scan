// From 21st.dev "Text Shimmer" (Agent Elements, @serafimcloud): shimmering status text.
// Keyframes live in index.css (.text-shimmer) instead of being injected at runtime.
import type { CSSProperties, ElementType, ReactNode } from 'react'
import { cn } from '@/lib/utils'

export function TextShimmer({ children, as: Tag = 'span', className, duration = 2 }: { children: ReactNode; as?: ElementType; className?: string; duration?: number }) {
  return <Tag className={cn('text-shimmer', className)} style={{ animationDuration: `${duration}s` } as CSSProperties}>{children}</Tag>
}
