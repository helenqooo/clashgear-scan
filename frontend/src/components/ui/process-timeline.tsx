// From 21st.dev "Onboarding Timeline" (@ephraimduncan): vertical steps with done / in-progress /
// upcoming states. Steps come from props; the in-progress dot pulses.
import type { ReactNode } from 'react'
import { Check, X } from 'lucide-react'
import { cn } from '@/lib/utils'

export type TimelineStep = {
  id: string | number
  type: 'done' | 'in progress' | 'open' | 'failed'
  title: ReactNode
  description?: ReactNode
  activityTime?: ReactNode
}

export function ProcessTimeline({ steps, title, className }: { steps: TimelineStep[]; title?: ReactNode; className?: string }) {
  return (
    <div className={className}>
      {title && <h3 className="font-medium text-foreground">{title}</h3>}
      <ul className={cn('space-y-6', title && 'mt-6')}>
        {steps.map((step, i) => (
          <li className="relative flex gap-x-3" key={step.id}>
            <div className={cn('absolute left-0 top-0 flex w-6 justify-center', i === steps.length - 1 ? 'h-6' : '-bottom-6')}>
              <span aria-hidden className="w-px bg-border" />
            </div>
            <div className="flex items-start space-x-2.5">
              <div className="relative flex size-6 flex-none items-center justify-center bg-background">
                {step.type === 'done' ? (
                  <Check aria-hidden className="size-5 text-primary" />
                ) : step.type === 'failed' ? (
                  <X aria-hidden className="size-4 text-muted-foreground" />
                ) : step.type === 'in progress' ? (
                  <div aria-hidden className="size-2.5 animate-pulse rounded-full bg-primary ring-4 ring-background" />
                ) : (
                  <div aria-hidden className="size-3 rounded-full border border-border bg-background ring-4 ring-background" />
                )}
              </div>
              <div className="min-w-0">
                <p className="mt-0.5 text-sm font-medium text-foreground">
                  {step.title}{' '}
                  {step.activityTime && <span className="font-normal text-muted-foreground/60">&#8729; {step.activityTime}</span>}
                </p>
                {step.description && <div className="mt-0.5 text-sm leading-6 text-muted-foreground">{step.description}</div>}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
