// From the owner's 21st.dev "Background inbox": a list of background jobs with a status glyph
// (ready ✓, running spinner, waiting clock), an unread dot, a time and a hover dismiss button.
// Solar icons and base-ui swapped for lucide and plain buttons; Tailwind 3 opacities.
import * as React from 'react'
import { CheckCircle2, Clock3, Inbox, LoaderCircle, X } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface BackgroundInboxItem {
  id: string
  title: string
  detail?: string
  status: 'ready' | 'running' | 'waiting'
  time?: string
  active?: boolean
  unread?: boolean
}

const titleTone: Record<BackgroundInboxItem['status'], string> = {
  ready: 'text-foreground',
  running: 'text-muted-foreground',
  waiting: 'text-muted-foreground/70',
}

function InboxStatus({ status }: Pick<BackgroundInboxItem, 'status'>) {
  if (status === 'ready') return <CheckCircle2 aria-label="Hazır" className="size-4 text-emerald-500" />
  if (status === 'running') return <LoaderCircle aria-label="Çalışıyor" className="size-4 animate-spin text-blue-400 motion-reduce:animate-none" />
  return <Clock3 aria-label="Bekliyor" className="size-4 text-muted-foreground/70" />
}

export function BackgroundInbox({ className, title = 'Background inbox', icon, items, onDismiss, onSelect, empty, ...props }: Omit<React.ComponentProps<'section'>, 'onSelect' | 'title'> & {
  title?: React.ReactNode
  icon?: React.ReactNode
  items: BackgroundInboxItem[]
  onDismiss?: (id: string) => void
  onSelect?: (id: string) => void
  empty?: React.ReactNode
}) {
  const running = items.filter((i) => i.status === 'running').length
  return (
    <section className={cn('rounded-[16px] bg-card p-2 font-sans text-sm text-muted-foreground', className)} {...props}>
      <header className="flex items-center gap-2 px-3 pb-1 pt-2">
        {icon ?? <Inbox className="size-4 text-muted-foreground" />}
        <h3 className="text-sm font-medium leading-5 text-muted-foreground">{title}</h3>
        <span className={cn('ml-auto rounded-full px-2 py-0.5 text-xs tabular-nums leading-5', running ? 'bg-blue-400/15 text-blue-300' : 'bg-foreground/[0.06] text-muted-foreground')}>
          {running ? `${running} çalışıyor` : items.length}
        </span>
      </header>
      {!items.length && empty}
      <ul className="flex flex-col">
        {items.map((item) => (
          <li key={item.id} className={cn('group relative rounded-[12px] px-3 py-2.5 transition-colors duration-200', item.active ? 'bg-foreground/[0.07]' : 'hover:bg-foreground/[0.04]')}>
            <div className="flex items-start gap-3">
              <span className="flex h-6 shrink-0 items-center"><InboxStatus status={item.status} /></span>
              <button type="button" onClick={() => onSelect?.(item.id)} className={cn('min-w-0 flex-1 rounded-sm text-left outline-none focus-visible:ring-2 focus-visible:ring-ring', onDismiss && 'pr-5')}>
                <span className="flex items-baseline gap-3">
                  <span className="flex min-w-0 flex-1 items-center gap-2">
                    <span className={cn('truncate text-[14px] font-medium leading-6', titleTone[item.status])}>{item.title}</span>
                    {item.unread && <><span aria-hidden className="size-1.5 shrink-0 rounded-full bg-blue-400" /><span className="sr-only">Okunmadı</span></>}
                  </span>
                  {item.time && <span className={cn('shrink-0 text-xs tabular-nums text-muted-foreground/70', onDismiss && 'transition-opacity duration-150 group-focus-within:opacity-0 group-hover:opacity-0')}>{item.time}</span>}
                </span>
                {item.detail && <span className="mt-0.5 block truncate text-[12.5px] leading-5 text-muted-foreground/70">{item.detail}</span>}
              </button>
            </div>
            {onDismiss && (
              <button type="button" aria-label={`${item.title} kaldır`} onClick={() => onDismiss(item.id)}
                className="absolute right-2.5 top-3 grid size-6 place-items-center rounded-md text-muted-foreground opacity-0 transition-opacity duration-150 hover:bg-muted hover:text-foreground group-focus-within:opacity-100 group-hover:opacity-100">
                <X className="size-3" />
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  )
}

export default BackgroundInbox
