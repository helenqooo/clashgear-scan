// From 21st.dev "Message Thread" (Hirael, MIT, Mohammad Shehadeh <https://hirael.com/blocks/ai/message-thread>):
// a message list that follows streaming output, with a jump-to-latest pill, message rows, a streaming
// cursor and typing dots. Tool calls and reasoning are drawn by the Nyx work log instead, so those
// parts (and their Collapsible dependency) are left out.
import * as React from 'react'
import { ArrowDown } from 'lucide-react'
import { cn } from '@/lib/utils'

export type MessageRole = 'user' | 'assistant' | 'system'

const ThreadContext = React.createContext<{ atBottom: boolean; scrollToBottom: () => void } | null>(null)
const useMessageThread = () => {
  const c = React.useContext(ThreadContext)
  if (!c) throw new Error('MessageThread parts must be rendered inside <MessageThread>.')
  return c
}
const reduced = () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

export function MessageThread({ follow = true, threshold = 48, className, children, ...props }: React.ComponentProps<'div'> & { follow?: boolean; threshold?: number }) {
  const viewportRef = React.useRef<HTMLDivElement>(null)
  const contentRef = React.useRef<HTMLDivElement>(null)
  const pinnedRef = React.useRef(true)
  const autoRef = React.useRef(false)
  const [atBottom, setAtBottom] = React.useState(true)

  const scrollToBottom = React.useCallback(() => {
    const el = viewportRef.current
    if (!el) return
    pinnedRef.current = true
    autoRef.current = true
    el.scrollTo({ top: el.scrollHeight, behavior: reduced() ? 'auto' : 'smooth' })
  }, [])

  const onScroll = React.useCallback(() => {
    const el = viewportRef.current
    if (!el) return
    const pinned = el.scrollHeight - el.scrollTop - el.clientHeight < threshold
    // Ignore the in-between positions of a programmatic smooth scroll so the pill doesn't flicker.
    if (autoRef.current) { if (!pinned) return; autoRef.current = false }
    pinnedRef.current = pinned
    setAtBottom(pinned)
  }, [threshold])

  // Streaming children grow without re-rendering the container, so watch the content box.
  React.useLayoutEffect(() => {
    const viewport = viewportRef.current, content = contentRef.current
    if (!viewport || !content || !follow) return
    viewport.scrollTop = viewport.scrollHeight
    const ro = new ResizeObserver(() => { if (pinnedRef.current) viewport.scrollTop = viewport.scrollHeight })
    ro.observe(content)
    return () => ro.disconnect()
  }, [follow])

  const ctx = React.useMemo(() => ({ atBottom, scrollToBottom }), [atBottom, scrollToBottom])
  return (
    <ThreadContext.Provider value={ctx}>
      <div ref={viewportRef} data-slot="message-thread" role="log" aria-live="polite" onScroll={onScroll}
        className={cn('relative flex flex-col overflow-y-auto overscroll-contain', className)} {...props}>
        <div ref={contentRef} className="flex flex-col gap-7 p-4 sm:p-6">{children}</div>
      </div>
    </ThreadContext.Provider>
  )
}

/** Render it as the last child of the thread. */
export function MessageThreadScrollButton({ children = 'Sona git' }: { children?: React.ReactNode }) {
  const { atBottom, scrollToBottom } = useMessageThread()
  if (atBottom) return null
  return (
    <div className="sticky bottom-3 z-10 -mt-6 flex h-0 justify-center overflow-visible">
      <button type="button" onClick={scrollToBottom}
        className="press flex -translate-y-full items-center gap-1.5 rounded-full border border-white/10 bg-neutral-900/90 px-3 py-1.5 text-xs text-neutral-300 shadow-xl backdrop-blur hover:text-white">
        <ArrowDown className="size-3.5" aria-hidden /> {children}
      </button>
    </div>
  )
}

const RoleContext = React.createContext<MessageRole>('assistant')

export function Message({ role = 'assistant', className, ...props }: React.ComponentProps<'div'> & { role?: MessageRole }) {
  return (
    <RoleContext.Provider value={role}>
      <div data-slot="message" data-role={role} className={cn('group/message flex w-full items-start gap-3', role === 'user' && 'flex-row-reverse', role === 'system' && 'justify-center', className)} {...props} />
    </RoleContext.Provider>
  )
}

export function MessageBody({ className, ...props }: React.ComponentProps<'div'>) {
  const role = React.useContext(RoleContext)
  return <div className={cn('flex min-w-0 flex-col gap-2', role === 'user' && 'max-w-[85%] items-end', role === 'assistant' && 'flex-1 items-stretch', role === 'system' && 'items-center', className)} {...props} />
}

export function MessageContent({ className, ...props }: React.ComponentProps<'div'>) {
  const role = React.useContext(RoleContext)
  return (
    <div className={cn('text-sm leading-relaxed break-words',
      role === 'user' && 'rounded-2xl rounded-tr-md bg-white px-3.5 py-2.5 text-[13.5px] text-black',
      role === 'assistant' && 'text-neutral-300',
      role === 'system' && 'rounded-full border border-white/10 px-3 py-1 text-xs text-neutral-500',
      className)} {...props} />
  )
}

export function MessageStreamingCursor({ className }: { className?: string }) {
  return <span aria-hidden className={cn('ms-0.5 inline-block h-[1em] w-[0.5em] translate-y-[0.15em] animate-pulse rounded-[1px] bg-neutral-300 align-baseline motion-reduce:animate-none', className)} style={{ animationDuration: '1s' }} />
}

export function MessageTyping({ label = 'Nyx yazıyor' }: { label?: string }) {
  return (
    <div role="status" aria-label={label} className="inline-flex items-center gap-1 py-2">
      {[0, 150, 300].map((d) => <span key={d} aria-hidden className="size-1.5 animate-bounce rounded-full bg-neutral-500 motion-reduce:animate-none" style={{ animationDelay: `${d}ms` }} />)}
    </div>
  )
}
