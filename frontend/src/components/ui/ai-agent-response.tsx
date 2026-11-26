// From the owner's 21st.dev "AI Agent Response" (a port of a Rust transcript view): an activity rail
// that hangs tool chips off one trunk, a "Thought process" chip, a terminal block for commands, a
// numbered code excerpt for what was read, and a group header that summarises the work
// ("ran 2 commands · read 1 file"). The demo played a scripted timeline; here every row comes from
// a live event, so the timers are gone and `live` drives the shimmer, the spinner and the fold.
// Ported to Tailwind 3 (hsl tokens, bracketed opacities).
import * as React from 'react'
import { Brain, CheckCheck, ChevronDown, ChevronRight, Copy, FileText, Lock, Search, Terminal, Wrench } from 'lucide-react'
import { cn } from '@/lib/utils'

const GROUP_HEADER_H = 26
const ROW_H = 32
const TRUNK_X = 12.5
const BEND_R = 6
const BRANCH_END_X = 28
const ICON_LEFT = 32
const ICON_SIZE = 16
const GUTTER_W = 48
const TEXT_GAP = 8
const LINE_H = 18
const OUTPUT_MAX_LINES = 24
const FOLD = 'duration-[140ms] ease-[cubic-bezier(0.23,1,0.32,1)]'

export type TraceKind = 'thought' | 'exec' | 'read' | 'search' | 'tool'
export type TraceNode = {
  id: string
  kind: TraceKind
  label: string
  /** One-line chip detail; `file` shows a file badge instead, `command` a mono pill. */
  detail?: string
  file?: string
  command?: string
  status: 'running' | 'done' | 'failed'
  durationMs?: number
  /** thought body */
  text?: string
  /** expanded bodies */
  code?: string
  lineStart?: number
  output?: string
  details?: string[]
  invocation?: string
  /** The server withheld this step's content (reversing steps on free keys): a click shows why, not what. */
  locked?: boolean
}

function LockedNotice() {
  return (
    <div className="flex items-center gap-2 py-1.5 text-[12px] text-rose-300/85" style={{ animation: 'agent-fade 250ms cubic-bezier(0.23,1,0.32,1) both' }}>
      <Lock className="size-3.5 shrink-0" aria-hidden />
      <span>Güvenlik nedeniyle reverser ajanının işlemlerini görüntüleyemezsiniz.</span>
    </div>
  )
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/** view.rs tool_group_summary */
export function summarize(nodes: TraceNode[]) {
  let commands = 0, reads = 0, searches = 0, failed = 0
  for (const n of nodes) {
    if (n.status === 'failed') failed++
    if (n.kind === 'exec') commands++
    else if (n.kind === 'read') reads++
    else if (n.kind === 'search') searches++
  }
  const seg: string[] = []
  if (commands) seg.push(`ran ${plural(commands, 'command', 'commands')}`)
  if (reads) seg.push(`read ${plural(reads, 'file', 'files')}`)
  if (searches) seg.push(`searched ${plural(searches, 'time', 'times')}`)
  if (failed) seg.push(`${failed} failed`)
  return seg.join(' · ')
}

/* ---------------------------------------------------------------- rail */

/** One SVG owns the trunk, elbow and branch so the joints share a pixel grid. */
function ActivityRail({ hasPredecessor, continues, failed }: { hasPredecessor: boolean; continues: boolean; failed: boolean }) {
  const stroke = failed ? 'stroke-rose-800' : 'stroke-neutral-700'
  const branchY = ROW_H / 2
  const bendY = branchY - BEND_R
  return (
    <svg aria-hidden width={BRANCH_END_X} height={ROW_H} className="pointer-events-none absolute inset-y-0 left-0 h-full flex-none overflow-visible">
      <line x1={TRUNK_X} y1={hasPredecessor ? 0 : -10} x2={TRUNK_X} y2={bendY} strokeWidth={1} className={stroke} />
      <path d={`M${TRUNK_X} ${bendY} Q${TRUNK_X} ${branchY} ${TRUNK_X + BEND_R} ${branchY} H${BRANCH_END_X}`} fill="none" strokeWidth={1} className={stroke} />
      {continues && <line x1={TRUNK_X} y1={bendY} x2={TRUNK_X} y2="100%" strokeWidth={1} className={stroke} />}
    </svg>
  )
}

/* ---------------------------------------------------------------- bodies */

const TOKEN_RE = /(\/\/.*$|\/\*[\s\S]*?\*\/|;.*$)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|\b(const|let|var|function|return|if|else|for|while|do|break|continue|new|struct|typedef|static|void|int|char|bool|unsigned|long|short|DWORD|HANDLE|BYTE|BOOL|LPVOID|LPCSTR|LPCWSTR|size_t|uint8_t|uint32_t|uint64_t|sizeof|goto|switch|case|default|null|NULL|true|false)\b|(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b)|(\b[A-Z][A-Za-z0-9_]*\b)|([a-zA-Z_$][\w$]*(?=\s*\())/gm
const TOKEN_CLS: Record<number, string> = {
  1: 'italic text-muted-foreground/60',
  2: 'text-emerald-400',
  3: 'text-violet-400',
  4: 'text-amber-400',
  5: 'text-sky-300',
  6: 'text-blue-400',
}
/** Single-pass tokenizer: comments, strings, keywords, numbers, types, calls. */
export function highlightCode(code: string): React.ReactNode {
  const out: React.ReactNode[] = []
  let last = 0, key = 0
  let m: RegExpExecArray | null
  TOKEN_RE.lastIndex = 0
  while ((m = TOKEN_RE.exec(code)) !== null) {
    if (m.index > last) out.push(code.slice(last, m.index))
    const group = m.slice(1).findIndex((g) => g !== undefined) + 1
    out.push(<span key={key++} className={TOKEN_CLS[group]}>{m[0]}</span>)
    last = m.index + m[0].length
    if (m[0].length === 0) TOKEN_RE.lastIndex++
  }
  if (last < code.length) out.push(code.slice(last))
  return out
}

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = React.useState(false)
  return (
    <button type="button" aria-label={label} onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="rounded-sm p-0.5 text-muted-foreground transition-colors hover:text-foreground active:scale-95">
      {copied ? <CheckCheck className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
    </button>
  )
}

/** A numbered, highlighted excerpt; scrolls past `maxH`. */
export function CodeBlock({ code, lineStart = 1, className, title, maxH = 300 }: { code: string; lineStart?: number; className?: string; title?: string; maxH?: number }) {
  const lines = code.replace(/\n+$/, '').split('\n')
  return (
    <div className={cn('overflow-hidden rounded-lg border border-border/70 bg-card font-mono text-[12px] select-text', className)}>
      {title !== undefined && (
        <div className="flex items-center justify-between border-b border-border/60 bg-muted/40 px-2.5 py-1 text-[11px] text-muted-foreground">
          <span className="truncate">{title}</span>
          <CopyBtn text={code} label="Kopyala" />
        </div>
      )}
      <div className="overflow-auto py-1" style={{ lineHeight: `${LINE_H}px`, maxHeight: maxH }}>
        {lines.map((line, i) => (
          <div key={i} className="flex items-start hover:bg-muted/40">
            <span className="w-11 shrink-0 select-none pr-2.5 text-right text-[10.5px] tabular-nums text-muted-foreground/50">{lineStart + i}</span>
            <pre className="min-w-0 flex-1 whitespace-pre pr-3 text-foreground/90">{highlightCode(line) }</pre>
          </div>
        ))}
      </div>
    </div>
  )
}

export function TerminalCommand({ command, output, failed, durationMs, running, className }: {
  command: string; output?: string; failed?: boolean; durationMs?: number; running?: boolean; className?: string
}) {
  const lines = (output ?? '').split('\n')
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop()
  return (
    <div className={cn('flex w-full flex-col overflow-hidden rounded-lg border border-border/70 bg-card font-mono text-[12px] select-text', className)}>
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/40 px-2.5 py-1">
        <div className="flex min-w-0 flex-1 items-center gap-2 text-[12px]">
          <Terminal className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
          <span className="truncate text-foreground/90">{command}</span>
        </div>
        <div className="ml-2 flex shrink-0 items-center gap-2 text-[11px]">
          {durationMs !== undefined && <span className="tabular-nums text-muted-foreground">{durationMs}ms</span>}
          {running
            ? <span className="inline-flex items-center gap-1 rounded-md bg-muted px-1.5 py-0.5 text-muted-foreground"><span className="size-1.5 animate-pulse rounded-full bg-muted-foreground" />running</span>
            : failed
              ? <span className="rounded-md bg-rose-500/10 px-1.5 py-0.5 font-medium tabular-nums text-rose-400">exit 1</span>
              : <span className="rounded-md bg-emerald-500/10 px-1.5 py-0.5 font-medium tabular-nums text-emerald-400">exit 0</span>}
          <CopyBtn text={output ? `$ ${command}\n\n${output}` : `$ ${command}`} label="Komutu kopyala" />
        </div>
      </div>
      {lines.length > 0 && (
        <div className="max-h-[420px] overflow-auto px-2.5 py-[6px] text-[12px] text-muted-foreground">
          <pre className="whitespace-pre font-mono">
            {lines.map((l, i) => <div key={i} style={{ minHeight: LINE_H, lineHeight: `${LINE_H}px` }}>{l || ' '}</div>)}
          </pre>
        </div>
      )}
    </div>
  )
}

function OutputDetail({ lines: raw }: { lines: string[] }) {
  const lines = [...raw]
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop()
  const shown = lines.slice(0, OUTPUT_MAX_LINES)
  if (!shown.length) return null
  return (
    <div className="flex flex-col overflow-x-auto py-[6px] font-mono text-[12px] text-muted-foreground select-text">
      {shown.map((line, i) => <div key={i} className="whitespace-pre" style={{ minHeight: LINE_H, lineHeight: `${LINE_H}px` }}>{line || ' '}</div>)}
      {lines.length > OUTPUT_MAX_LINES && <div className="text-[12px]" style={{ height: LINE_H }}>… {lines.length - OUTPUT_MAX_LINES} more lines</div>}
    </div>
  )
}

/* ---------------------------------------------------------------- rows */

function ChipRow({ first, last, failed, label, labelSuffix, icon, detail, file, command, active, open, onToggle, body, bodyPadLeft = GUTTER_W + TEXT_GAP, trail }: {
  first: boolean; last: boolean; failed: boolean; label: string; labelSuffix?: React.ReactNode; icon: React.ReactNode
  detail?: string; file?: string; command?: string; active?: boolean; open?: boolean; onToggle?: () => void
  body?: React.ReactNode; bodyPadLeft?: number; trail?: React.ReactNode
}) {
  const expandable = !!body
  return (
    <div className="relative flex w-full flex-col" style={{ animation: 'agent-row-in 360ms cubic-bezier(0.16,1,0.3,1) both' }}>
      <ActivityRail hasPredecessor={!first} continues={!last || !!open} failed={failed} />
      <span className={cn('absolute z-[1] flex items-center justify-center', failed && 'text-rose-400')}
        style={{ left: ICON_LEFT, top: ROW_H / 2 - ICON_SIZE / 2, width: ICON_SIZE, height: ICON_SIZE }}>
        {active ? <span aria-hidden className="size-3.5 animate-spin rounded-full border-[1.5px] border-muted-foreground/30 border-t-foreground/70" /> : icon}
      </span>
      <div className="flex min-w-0 flex-1 flex-col" style={{ marginLeft: GUTTER_W + TEXT_GAP }}>
        <button type="button" disabled={!expandable} aria-expanded={expandable ? open : undefined} onClick={onToggle}
          className={cn('group/chip flex w-full items-center gap-2 text-left', expandable ? 'cursor-pointer active:scale-[0.995]' : 'cursor-default')} style={{ height: ROW_H }}>
          <span className={cn('flex h-[18px] shrink-0 items-center text-[12px] font-medium leading-[18px] tracking-tight transition-colors', failed ? 'text-rose-400' : 'text-muted-foreground', expandable && !failed && 'group-hover/chip:text-foreground')}>
            {active ? <span className="agent-shimmer-text">{label}</span> : label}
            {labelSuffix && <span className="ml-1.5">{labelSuffix}</span>}
          </span>
          {file ? (
            <span className="flex h-[22px] min-w-0 max-w-[55%] shrink items-center gap-1.5 overflow-hidden rounded-[5px] bg-muted/70 pl-px pr-1.5 text-[12px] text-foreground/85 transition-colors group-hover/chip:bg-muted">
              <span className="flex size-5 shrink-0 items-center justify-center rounded-[4px] bg-background"><FileText className="size-3.5 text-muted-foreground" aria-hidden /></span>
              <span className="truncate">{file}</span>
            </span>
          ) : command ? (
            <span className="inline-flex h-[22px] min-w-0 max-w-[60%] shrink items-center overflow-hidden rounded-[5px] bg-muted/70 px-2 font-mono text-[11.5px] text-foreground/85 transition-colors group-hover/chip:bg-muted">
              <span className="truncate">{command}</span>
            </span>
          ) : detail ? (
            <span className="min-w-0 max-w-[55%] shrink truncate font-mono text-[12px] leading-[18px] text-foreground/85">{detail}</span>
          ) : null}
          {trail}
          {expandable && (
            <span className="flex size-[18px] shrink-0 items-center justify-center text-muted-foreground/80 opacity-0 transition-opacity duration-150 group-hover/chip:opacity-100">
              {open ? <ChevronDown className="size-3" aria-hidden /> : <ChevronRight className="size-3" aria-hidden />}
            </span>
          )}
        </button>
      </div>
      {expandable && (
        <div className={cn('grid transition-[grid-template-rows,opacity]', FOLD, open ? 'grid-rows-[1fr] opacity-100' : 'pointer-events-none grid-rows-[0fr] opacity-0')}>
          <div className="min-h-0 overflow-hidden">
            <div style={{ paddingLeft: bodyPadLeft }}><div className="flex min-w-0 flex-col pb-1">{open && body}</div></div>
          </div>
        </div>
      )}
    </div>
  )
}

/** The model's progress note, as a "Thought process" chip: open while it streams, folded after. */
function ThoughtRow({ node, first, last }: { node: TraceNode; first: boolean; last: boolean }) {
  const active = node.status === 'running'
  const [manual, setManual] = React.useState(false)
  const [secs, setSecs] = React.useState(0)
  React.useEffect(() => {
    if (!active) return
    const start = Date.now()
    const t = setInterval(() => setSecs((Date.now() - start) / 1000), 100)
    return () => clearInterval(t)
  }, [active])
  const shown = node.durationMs != null ? node.durationMs / 1000 : secs
  // A locked thought only says that it is thinking; it never opens by itself.
  const open = node.locked ? manual : active || manual
  return (
    <ChipRow first={first} last={last} failed={false} label={node.locked && active ? 'Thinking…' : node.label || 'Thought process'}
      labelSuffix={shown > 0 ? <span className="font-mono text-[11px] tabular-nums text-muted-foreground/60">{shown.toFixed(1)}s</span> : undefined}
      icon={<Brain className="size-4 shrink-0 text-muted-foreground" aria-hidden />}
      active={!!node.locked && active} open={open} onToggle={() => (node.locked || !active) && setManual((v) => !v)} bodyPadLeft={ICON_LEFT + ICON_SIZE}
      body={node.locked ? <div className="pl-3"><LockedNotice /></div> : (
        <div className="max-h-[184px] overflow-y-auto py-1 pl-3 [scrollbar-width:none]">
          <p className="m-0 whitespace-pre-wrap text-[12.5px] leading-[20px] text-muted-foreground" style={{ animation: 'agent-fade 250ms cubic-bezier(0.23,1,0.32,1) both' }}>{node.text}</p>
        </div>
      )} />
  )
}

function ToolRow({ node, first, last }: { node: TraceNode; first: boolean; last: boolean }) {
  const [open, setOpen] = React.useState(false)
  const active = node.status === 'running'
  const failed = node.status === 'failed'
  const Icon = node.kind === 'exec' ? Terminal : node.kind === 'read' ? FileText : node.kind === 'search' ? Search : Wrench
  const hasBody = !!(node.locked || node.command || node.code || node.output || node.details?.length || node.invocation)
  return (
    <ChipRow first={first} last={last} failed={failed} label={node.label}
      icon={<Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />}
      detail={node.detail} file={node.file} command={node.command} active={active}
      open={open} onToggle={hasBody ? () => setOpen((v) => !v) : undefined}
      trail={node.durationMs != null && node.kind !== 'exec' ? <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground/50">{(node.durationMs / 1000).toFixed(1)}s</span> : undefined}
      body={node.locked ? <LockedNotice /> : hasBody ? (
        <>
          {node.command
            ? <div className="py-1"><TerminalCommand command={node.command} output={node.output} failed={failed} durationMs={node.durationMs} running={active} /></div>
            : node.code
              ? <div className="py-1"><CodeBlock code={node.code} lineStart={node.lineStart ?? 1} /></div>
              : node.output ? <OutputDetail lines={node.output.split('\n')} /> : null}
          {node.details && node.details.length > 0 && (
            <div className="flex max-h-[300px] flex-col overflow-auto py-[6px] font-mono text-[12px] text-muted-foreground">
              {node.details.map((l, i) => <div key={i} className="whitespace-pre" style={{ minHeight: LINE_H, lineHeight: `${LINE_H}px` }}>{l}</div>)}
            </div>
          )}
          {node.invocation && !node.command && <OutputDetail lines={node.invocation.split('\n')} />}
        </>
      ) : undefined} />
  )
}

/* ---------------------------------------------------------------- group */

/** A group header plus the rail tree. Open while `live`, folded once the turn settles (a click wins). */
export function LiveTrace({ nodes, live, className, summaryText }: { nodes: TraceNode[]; live: boolean; className?: string; /** replaces the generated English summary */ summaryText?: string }) {
  const [manual, setManual] = React.useState<boolean | null>(null)
  const expanded = manual ?? live
  const summary = summaryText ?? summarize(nodes)
  const lastActive = nodes.at(-1)?.status === 'running' ? nodes.at(-1) : undefined
  const title = summary || (live ? (lastActive?.kind === 'thought' ? 'Thinking…' : 'Working…') : nodes.some((n) => n.kind === 'thought') ? 'Thought it through' : 'Worked')
  return (
    <div className={cn('flex w-full select-none flex-col font-sans text-foreground', className)}>
      <button type="button" aria-expanded={expanded} onClick={() => setManual(!expanded)}
        className="group flex w-full cursor-pointer items-center gap-1.5 rounded-sm pr-1 text-left text-[12px] leading-[18px] text-muted-foreground transition-colors duration-150 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        style={{ height: GROUP_HEADER_H }}>
        <span className="relative h-[18px] w-[22px] shrink-0">
          <ChevronDown aria-hidden className={cn('absolute size-3.5 text-muted-foreground transition-transform ease-out', FOLD)} style={{ left: TRUNK_X - 7, top: 2, transform: `rotate(${expanded ? 0 : -90}deg)` }} />
        </span>
        <span className="min-w-0 truncate">{live ? <span className="agent-shimmer-text font-medium">{title}</span> : <span className="font-normal">{title}</span>}</span>
      </button>
      <div className={cn('grid transition-[grid-template-rows,opacity] ease-out', FOLD, expanded ? 'grid-rows-[1fr] opacity-100' : 'pointer-events-none grid-rows-[0fr] opacity-0')}>
        <div className="min-h-0 overflow-hidden">
          <div className="flex flex-col pt-0.5">
            {nodes.map((n, i) => n.kind === 'thought'
              ? <ThoughtRow key={n.id} node={n} first={i === 0} last={i === nodes.length - 1} />
              : <ToolRow key={n.id} node={n} first={i === 0} last={i === nodes.length - 1} />)}
          </div>
        </div>
      </div>
    </div>
  )
}
