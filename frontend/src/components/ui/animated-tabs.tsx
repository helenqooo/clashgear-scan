// From 21st.dev "Animated Tabs" (@educalvolpz); motion import switched to framer-motion and the
// underline uses the site's primary colour. Horizontal scroll when the tabs do not fit.
import { motion, useReducedMotion } from 'framer-motion'
import { type ReactNode, useCallback, useId, useState } from 'react'
import { cn } from '@/lib/utils'

export interface AnimatedTabsProps {
  activeTab?: string
  className?: string
  defaultTab?: string
  layoutId?: string
  onChange?: (tabId: string) => void
  tabs: { id: string; label: string; icon?: ReactNode }[]
  variant?: 'underline' | 'pill' | 'segment'
}

const SPRING = { bounce: 0.05, duration: 0.25, type: 'spring' as const }

export default function AnimatedTabs({ tabs, activeTab: controlled, defaultTab, onChange, variant = 'underline', layoutId: customLayoutId, className }: AnimatedTabsProps) {
  const reduce = useReducedMotion()
  const generatedId = useId()
  const layoutId = customLayoutId ?? `animated-tabs-${generatedId}`
  const [internal, setInternal] = useState(defaultTab ?? tabs[0]?.id ?? '')
  const isControlled = controlled !== undefined
  const activeTab = isControlled ? controlled : internal

  const change = useCallback((id: string) => {
    if (!isControlled) setInternal(id)
    onChange?.(id)
  }, [isControlled, onChange])

  const onKey = useCallback((e: React.KeyboardEvent, i: number) => {
    let n = i
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') n = 0
    else if (e.key === 'End') n = tabs.length - 1
    else return
    e.preventDefault()
    const t = tabs[n]
    if (t) {
      change(t.id)
      document.getElementById(`${layoutId}-tab-${t.id}`)?.focus()
    }
  }, [tabs, change, layoutId])

  return (
    <div
      aria-label="Tabs"
      role="tablist"
      className={cn(
        'relative inline-flex max-w-full overflow-x-auto',
        variant === 'underline' && 'gap-1 border-b border-border',
        variant === 'pill' && 'gap-1 rounded-full bg-muted p-1',
        variant === 'segment' && 'gap-0 rounded-lg bg-muted p-1',
        className,
      )}
    >
      {tabs.map((tab, index) => {
        const active = activeTab === tab.id
        return (
          <button
            key={tab.id}
            id={`${layoutId}-tab-${tab.id}`}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => change(tab.id)}
            onKeyDown={(e) => onKey(e, index)}
            className={cn(
              'relative z-10 flex shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap px-4 py-2 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              variant === 'underline' && 'rounded-t-md',
              variant === 'pill' && 'rounded-full',
              variant === 'segment' && 'flex-1 rounded-md',
              active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {active && (
              <motion.span
                layout
                layoutId={layoutId}
                style={{ originY: '0px' }}
                transition={reduce ? { duration: 0 } : SPRING}
                className={cn(
                  'absolute',
                  variant === 'underline' && '-bottom-px left-0 right-0 h-0.5 bg-primary',
                  variant === 'pill' && 'inset-0 rounded-full border border-border bg-background shadow-sm',
                  variant === 'segment' && 'inset-0 rounded-md border border-border bg-background shadow-sm',
                )}
              />
            )}
            {tab.icon ? <span className="relative z-10">{tab.icon}</span> : null}
            <span className="relative z-10">{tab.label}</span>
          </button>
        )
      })}
    </div>
  )
}
