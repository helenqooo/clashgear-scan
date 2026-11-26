// Nyx analyst chat (every key, on its own scans), a full-screen chat in the ChatGPT / Claude web layout: analyses
// and scanned files on the left (background-inbox lists), the conversation in the middle. Nyx reads the
// report and takes a first look (PE layout, strings); when the code itself needs reading it hands over to
// Rune, the reversing agent (rose), which steps in with its own block: a greeting, its disassemble /
// decompile steps on the rail and its report. Each note and tool call streams in as a rail row; free keys
// see which step ran but never its input or output (the server leaves them out).
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ArrowLeft, ArrowUp, FileText, FolderSearch, Loader, MessagesSquare, PanelLeft, Paperclip, Plus, Square, X } from 'lucide-react'
import { AiAvatar } from '@/components/ui/ai-avatar'
import { BrandMark } from '@/components/ui/brand'
import { BackgroundInbox, type BackgroundInboxItem } from '@/components/ui/background-inbox'
import { CodeBlock, LiveTrace, type TraceNode } from '@/components/ui/ai-agent-response'
import { Message, MessageBody, MessageContent, MessageStreamingCursor, MessageThread, MessageThreadScrollButton } from '@/components/ui/message-thread'
import { cn } from '@/lib/utils'
import { ApiError } from '@/lib/api'
import { scanApi, type AllChatRow, type ChatEvent, type ChatFull, type ChatRow, type ChatViewer, type RuneEntry, type ScanJobRow, type ScanReport } from '@/lib/scanApi'
import { RuneMascot } from '@/components/scan/RuneMascot'
import { GlitchText } from '@/components/scan/GlitchText'
import { AnalysisPanel } from '@/components/scan/AnalysisPanel'
import { NyxMisuseModal, type Misuse } from '@/components/scan/NyxMisuseModal'
import { preloadTurnstile } from '@/lib/turnstile'

type ToolPart = { kind: 'tool'; id: string; name: string; input?: any; ms?: number; error?: string; output?: string; rune?: RuneEntry }
type Part = { kind: 'note' | 'text'; key: string; text: string } | ToolPart
type Assistant = { kind: 'assistant'; parts: Part[]; running: boolean; error?: string; usd?: number }
type Item = { kind: 'user'; text: string; file?: string } | Assistant
type Attached = { id: string; name: string; uploading?: boolean }

const SPRING = { type: 'spring' as const, bounce: 0, duration: 0.35 }
const FILE_PREFIX = /^\[Ekli dosya: (.+?) · job_id=[^\]]*\]\n\n/
const NOTE_PREFIX = /^\[Nyx notu: [^\]]*\]\n\n/ // the strike record sent with a message that has no file
const DEFAULT_PROMPT = 'Bu dosyayı analiz et: ne olduğu, ne yaptığı, zararlı olup olmadığı, kanıtlar, IOC listesi ve öneriler.'
const parse = (s?: string) => { try { return s ? JSON.parse(s) : null } catch { return null } }
const ago = (t: number) => {
  const m = Math.round((Date.now() - t) / 60000)
  return m < 1 ? 'şimdi' : m < 60 ? `${m} dk` : m < 1440 ? `${Math.round(m / 60)} sa` : `${Math.round(m / 1440)} g`
}

/* ------------------------------------------------- tool call -> rail row */

// Reversing steps the server sent without input/output (free keys): the row says what is happening, nothing more.
const HIDDEN: Record<string, { kind: TraceNode['kind']; label: string; detail: string }> = {
  pe_layout: { kind: 'read', label: 'Parse PE', detail: 'dosya yapısı okunuyor' },
  disassemble: { kind: 'exec', label: 'Disassemble', detail: 'makine kodu çözülüyor' },
  decompile: { kind: 'exec', label: 'Decompile', detail: 'Ghidra ile fonksiyonlar okunuyor' },
  vmp_unpack: { kind: 'exec', label: 'VMP unpack', detail: 'izole sanal makinede açılıyor' },
  find_strings: { kind: 'search', label: 'Search strings', detail: 'metinler taranıyor' },
  read_bytes: { kind: 'read', label: 'Read bytes', detail: 'baytlar okunuyor' },
  search_bytes: { kind: 'search', label: 'Search bytes', detail: 'bayt deseni aranıyor' },
}

function toNode(t: ToolPart, names: Record<string, string>, live: boolean): TraceNode {
  const i = t.input || {}
  const file = i.job_id ? names[i.job_id] || i.job_id.slice(0, 10) : undefined
  const out = parse(t.output)
  const base = { id: t.id, status: t.error ? 'failed' : t.ms == null && live ? 'running' : 'done', durationMs: t.ms } as const
  const err = t.error ? `error: ${t.error}` : undefined
  const hidden = HIDDEN[t.name]
  // Free keys: the step's own words (`note`); older chats without one fall back to a generic line.
  if (hidden && !t.output && Object.keys(i).every((k) => k === 'job_id' || k === 'note')) return { ...base, kind: hidden.kind, label: hidden.label, detail: i.note || (t.input ? hidden.detail : undefined), locked: true }
  switch (t.name) {
    case 'set_verdict': {
      const v = (x?: string) => ({ malicious: 'Zararlı', pua: 'Hile aracı', clean: 'Temiz', suspicious: 'Şüpheli' } as Record<string, string>)[x || ''] || x || '?'
      return { ...base, kind: 'tool', label: 'Skor güncellendi', detail: out?.after ? `${out.before?.score ?? '—'} → ${out.after.score} · ${v(out.after.verdict)}` : i.verdict ? `${v(i.verdict)} · ${i.score}` : undefined, details: err ? [err] : out?.note ? [out.note] : undefined }
    }
    case 'vmp_unpack':
      return {
        ...base, kind: 'exec', label: 'VMP unpack', command: `vmp-unpack ${file || ''} --${i.mode || 'static'}`.replace(/\s+/g, ' '),
        output: err || (out ? [...(out.outputs || []).map((o: any) => `${o.tool} → ${o.job_id} (${o.size} B)`), ...Object.entries(out.logs || {}).map(([k, v]) => `--- ${k}\n${v}`), out.note || ''].join('\n') : undefined),
      }
    case 'extract_archive':
      return {
        ...base, kind: 'read', label: i.files ? 'Arşivden çıkar' : 'Arşivi aç', file,
        detail: !file ? (i.files ? String(i.files).split('|').length + ' dosya' : undefined) : undefined,
        details: err ? [err] : out?.error ? [out.error === 'password_required' ? 'şifreli arşiv' : out.error === 'wrong_password' ? 'şifre yanlış' : out.error]
          : out?.members ? [`${out.total} dosya${out.encrypted ? ' · şifreli' : ''}`, ...out.members.slice(0, 40).map((m: any) => `${m.name}  ${m.size} B`)]
          : out?.extracted ? out.extracted.map((x: any) => `${x.name} → analiz başladı`) : undefined,
      }
    case 'propose_verdict':
      return { ...base, kind: 'tool', label: 'Karar önerdi', detail: i.verdict ? `${i.verdict} · ${i.score}` : undefined, details: i.reason ? [i.reason] : undefined }
    case 'decompile':
      return {
        ...base, kind: 'exec', label: 'Decompile',
        command: `ghidra ${file || ''} ${i.functions ? `--fn ${i.functions}` : '--map'}${i.filter ? ` --filter ${i.filter}` : ''}`.replace(/\s+/g, ' '),
        output: err || (out ? out.functions
          ? out.functions.map((f: any) => f.c ? `// ${f.name} @ ${f.addr}\n${f.c}` : `${f.addr}  ${f.name}  ${(f.calls || []).join(', ')}`).join('\n')
          : `${out.status}${out.elapsed_s != null ? ` · ${out.elapsed_s}s` : ''}` : undefined),
      }
    case 'disassemble':
      return { ...base, kind: 'exec', label: 'Disassemble', command: `disasm ${file || ''} --at ${i.at || 'entry'} -n ${i.count || 80}${i.bits ? ` --bits ${i.bits}` : ''}`.replace(/\s+/g, ' '), output: err || out?.listing }
    case 'get_report':
      return {
        ...base, kind: 'read', label: 'Read report', file,
        details: err ? [err] : out ? [
          `${out.file_name} · ${out.verdict || out.status} · score ${out.score ?? '—'}`,
          `sha256 ${out.sha256}`,
          ...(out.sources || []).map((s: any) => `L${s.layer}  ${String(s.source).padEnd(18)} ${s.status}${s.summary?.verdict ? ` · ${s.summary.verdict}` : ''}${s.summary?.family ? ` · ${s.summary.family}` : ''}`),
          ...(out.unpacked_children || []).map((c: any) => `child  ${c.file_name} · ${c.verdict ?? '…'}`),
        ] : undefined,
      }
    case 'pe_layout':
      return {
        ...base, kind: 'read', label: 'Parse PE', file,
        code: err || (out ? out.pe === false ? `not a PE file\n\n${out.head_hex}` : [
          `${out.bits}-bit  image_base ${out.image_base}  entry ${out.entry_va}${out.dotnet ? '  .NET' : ''}`, '',
          'SECTIONS', ...(out.sections || []).map((s: any) => `  ${String(s.name).padEnd(10)} va ${s.va}  vsize ${s.vsize}  raw ${s.raw_offset}+${s.raw_size}  ${s.flags}`), '',
          'IMPORTS', ...(out.imports || []).flatMap((d: any) => [`  ${d.dll}`, ...d.funcs.slice(0, 40).map((f: any) => `    ${f.iat_va}  ${f.name}`)]),
          ...(out.exports?.length ? ['', 'EXPORTS', ...out.exports.map((e: any) => `  ${e.va}  ${e.name}`)] : []),
        ].join('\n') : undefined),
      }
    case 'read_bytes':
      return { ...base, kind: 'read', label: 'Read bytes', file: `${file || 'sample'} @ ${i.at || 'off:0'} · ${i.length || 256} B`, code: err || out?.hexdump || out?.text }
    case 'find_strings':
      return {
        ...base, kind: 'search', label: 'Search strings', detail: `${i.pattern ? `/${i.pattern}/` : 'all strings'}${file ? ` in ${file}` : ''}`,
        details: err ? [err] : out ? [`${out.returned}/${out.total_matches} matches`, ...out.strings.map((s: any) => `${s.va || s.off}  ${s.enc === 'utf16' ? 'L' : ' '} ${s.s}`)] : undefined,
      }
    case 'search_bytes':
      return { ...base, kind: 'search', label: 'Search bytes', detail: `${i.hex || JSON.stringify(i.text || '')}${file ? ` in ${file}` : ''}`, details: err ? [err] : out ? [`${out.hits.length} hits`, ...out.hits.map((h: any) => `${h.off}  ${h.va || ''}`)] : undefined }
    case 'list_jobs':
      return { ...base, kind: 'tool', label: 'List scans', details: err ? [err] : Array.isArray(out) ? out.map((j: any) => `${j.job_id}  ${j.file_name}  ${j.verdict ?? j.status}`) : undefined }
    default:
      return { ...base, kind: 'tool', label: t.name, invocation: JSON.stringify(i, null, 2), output: err || t.output }
  }
}

/* ------------------------------------------------- answer markdown */

const MD = {
  p: ({ children }: { children?: ReactNode }) => <p className="my-3 leading-[24px] first:mt-0 last:mb-0">{children}</p>,
  h1: ({ children }: { children?: ReactNode }) => <p className="mb-2 mt-5 text-[18px] font-semibold leading-[26px] text-foreground first:mt-0">{children}</p>,
  h2: ({ children }: { children?: ReactNode }) => <p className="mb-2 mt-5 text-[16px] font-semibold leading-[24px] text-foreground first:mt-0">{children}</p>,
  h3: ({ children }: { children?: ReactNode }) => <p className="mb-1.5 mt-4 text-[14.5px] font-semibold text-foreground first:mt-0">{children}</p>,
  ul: ({ children }: { children?: ReactNode }) => <ul className="my-3 list-disc space-y-1 pl-5 marker:text-muted-foreground">{children}</ul>,
  ol: ({ children }: { children?: ReactNode }) => <ol className="my-3 list-decimal space-y-1 pl-5 marker:text-muted-foreground">{children}</ol>,
  strong: ({ children }: { children?: ReactNode }) => <strong className="font-semibold text-foreground">{children}</strong>,
  a: ({ children, href }: { children?: ReactNode; href?: string }) => <a href={href} target="_blank" rel="noreferrer noopener" className="underline decoration-foreground/30 underline-offset-2 hover:decoration-foreground/70">{children}</a>,
  pre: ({ children }: { children?: ReactNode }) => <>{children}</>,
  code: ({ children, className }: { children?: ReactNode; className?: string }) => {
    const text = String(children ?? '')
    if (className || text.includes('\n')) return <CodeBlock code={text} title={className?.replace('language-', '') || 'code'} className="my-3 bg-muted/30" maxH={520} />
    return <code className="rounded-sm bg-muted px-1 py-px font-mono text-[12.5px] text-foreground/90">{children}</code>
  },
  table: ({ children }: { children?: ReactNode }) => <div className="my-3 overflow-x-auto rounded-lg border border-border/70"><table className="w-full border-collapse text-[13px]">{children}</table></div>,
  th: ({ children }: { children?: ReactNode }) => <th className="border-b border-border/70 bg-muted/40 px-3 py-1.5 text-left font-medium text-foreground">{children}</th>,
  td: ({ children }: { children?: ReactNode }) => <td className="border-b border-border/40 px-3 py-1.5 align-top font-mono text-[12px]">{children}</td>,
  blockquote: ({ children }: { children?: ReactNode }) => <blockquote className="my-3 border-l-2 border-border pl-3 text-muted-foreground">{children}</blockquote>,
}

/** An agent's name whose letters flip in one after another; a new `name` flips the old one out first. */
function AgentName({ name, className }: { name: string; className?: string }) {
  return (
    <span className={cn('relative inline-flex [perspective:400px]', className)}>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span key={name} className="inline-flex" exit={{ opacity: 0, y: -8, filter: 'blur(4px)', transition: { duration: 0.18 } }}>
          {[...name].map((ch, i) => (
            <motion.span key={i} className="inline-block origin-bottom"
              initial={{ rotateX: -90, y: 6, opacity: 0, filter: 'blur(4px)' }}
              animate={{ rotateX: 0, y: 0, opacity: 1, filter: 'blur(0px)' }}
              transition={{ type: 'spring', bounce: 0.35, duration: 0.5, delay: i * 0.06 }}>{ch}</motion.span>
          ))}
        </motion.span>
      </AnimatePresence>
    </span>
  )
}

/** Who is talking in the thread, once the turn has two agents: Nyx (white, its avatar) or Rune (rose blob). */
function Speaker({ who, active = false, note }: { who: 'nyx' | 'rune'; active?: boolean; note?: string }) {
  return (
    <motion.div className="mb-1.5 flex items-center gap-2"
      initial={{ opacity: 0, y: 8, filter: 'blur(6px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
      transition={{ type: 'spring', bounce: 0.3, duration: 0.5 }}>
      {who === 'rune'
        ? <RuneMascot size={22} awake={active} />
        : <span className="flex size-[22px] items-center justify-center overflow-hidden"><AiAvatar size="sm" thinking={active} label="Nyx" className="scale-[0.7]" /></span>}
      <AgentName name={who === 'rune' ? 'Rune' : 'Nyx'} className={cn('text-[13.5px] font-semibold', who === 'rune' ? 'text-rose-400' : 'text-foreground')} />
      {note && <span className="agent-shimmer-text ml-auto text-[11.5px]">{note}</span>}
    </motion.div>
  )
}

/**
 * One ask_rune call as a conversation: Nyx's words to Rune, Rune stepping in (greeting, thinking phases and
 * tool steps; locked on free keys), any back-and-forth where Rune turns to Nyx (ask_nyx), then Rune's report.
 */
function RuneTurn({ part, names, live, full }: { part: ToolPart; names: Record<string, string>; live: boolean; full: boolean }) {
  const r = part.rune
  const working = live && !r?.report && !part.output && !part.error
  const steps = r?.steps || []
  const node = (s: (typeof steps)[number], idx: number): TraceNode => (s.name === 'thought'
    ? { id: s.id, kind: 'thought', label: 'Thought process', text: s.text || '', durationMs: s.ms, status: working && s.ms == null && idx === steps.length - 1 ? 'running' : 'done', locked: !full }
    : { ...toNode({ kind: 'tool', ...s }, names, working), ...(full ? {} : { locked: true }) })
  // The rail breaks where Rune talks to Nyx.
  const segments: ({ kind: 'trace'; nodes: TraceNode[] } | { kind: 'ask'; step: (typeof steps)[number] })[] = []
  steps.forEach((s, idx) => {
    if (s.name === 'ask_nyx') { segments.push({ kind: 'ask', step: s }); return }
    const last = segments.at(-1)
    if (last?.kind === 'trace') last.nodes.push(node(s, idx))
    else segments.push({ kind: 'trace', nodes: [node(s, idx)] })
  })
  const task = typeof part.input?.task === 'string' ? part.input.task : ''
  return (
    <div className="my-1 flex flex-col gap-3">
      {task && (
        <div>
          <Speaker who="nyx" />
          <p className="text-[14px] leading-[24px] text-foreground/90">{task}</p>
        </div>
      )}
      <motion.div
        initial={{ opacity: 0, y: 18, filter: 'blur(8px)' }}
        animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
        transition={{ type: 'spring', bounce: 0.25, duration: 0.6 }}
        className="flex flex-col gap-3">
        <div>
          <Speaker who="rune" active={working} note={working ? 'kodu inceliyor…' : undefined} />
          {r?.intro
            ? <p className="text-[14px] leading-[24px] text-foreground/90">{r.intro}</p>
            : working && <p className="agent-shimmer-text text-[13px]">Rune geliyor…</p>}
        </div>
        {segments.map((seg, i) => seg.kind === 'trace'
          ? <LiveTrace key={`t${i}`} nodes={seg.nodes} live={working && i === segments.length - 1} />
          : (
            <div key={seg.step.id} className="flex flex-col gap-3">
              {seg.step.message && <p className="text-[14px] leading-[24px] text-rose-200/90">{seg.step.message}</p>}
              <div>
                <Speaker who="nyx" active={!seg.step.answer && working} note={!seg.step.answer && working ? 'rapora bakıyor…' : undefined} />
                {seg.step.answer && <p className="text-[14px] leading-[24px] text-foreground/90">{seg.step.answer}</p>}
              </div>
              {(seg.step.answer && (i < segments.length - 1 || working || r?.report)) && <Speaker who="rune" active={working} />}
            </div>
          ))}
        {r?.report && (
          <MessageContent className="text-[14px] text-foreground/90">
            <ReactMarkdown remarkPlugins={[remarkGfm]} components={MD}>{r.report}</ReactMarkdown>
          </MessageContent>
        )}
        {part.error && <p className="text-[12.5px] text-amber-400">Rune bu sefer tamamlayamadı.</p>}
      </motion.div>
    </div>
  )
}

function AssistantTurn({ it, names, full }: { it: Assistant; names: Record<string, string>; full: boolean }) {
  // Consecutive notes and tool calls share one rail; text parts are the answer, in order. Rune's handover
  // (ask_rune) breaks out into its own block.
  const groups: ({ trace: TraceNode[]; key: string } | { text: string; key: string } | { rune: ToolPart; key: string })[] = []
  it.parts.forEach((p, idx) => {
    const last = groups.at(-1)
    if (p.kind === 'tool' && p.name === 'ask_rune') {
      groups.push({ rune: p, key: p.id })
      return
    }
    if (p.kind === 'text') {
      if (last && 'text' in last) last.text += p.text
      else groups.push({ text: p.text, key: p.key })
      return
    }
    const node: TraceNode = p.kind === 'tool'
      ? toNode(p, names, it.running)
      : { id: p.key, kind: 'thought', label: 'Thought process', text: p.text, status: it.running && idx === it.parts.length - 1 ? 'running' : 'done' }
    if (last && 'trace' in last) last.trace.push(node)
    else groups.push({ trace: [node], key: node.id })
  })
  const lastGroup = groups.at(-1)
  return (
    <Message role="assistant">
      <MessageBody className="gap-3">
        {it.running && !it.parts.length && <span className="agent-shimmer-text text-[12.5px] font-medium">Thinking…</span>}
        {groups.map((g, gi) => 'rune' in g
          ? <RuneTurn key={g.key} part={g.rune} names={names} live={it.running} full={full} />
          : 'trace' in g
          ? <LiveTrace key={g.key} nodes={g.trace} live={it.running && g === lastGroup} />
          : (
            <div key={g.key}>
              {/* Nyx's first words after Rune has spoken carry its name again. */}
              {'rune' in ([...groups.slice(0, gi)].reverse().find((x) => !('trace' in x)) || {}) && <Speaker who="nyx" />}
              <MessageContent className="text-[14px] text-foreground/90">
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={MD}>{g.text}</ReactMarkdown>
                {it.running && g === lastGroup && <MessageStreamingCursor />}
              </MessageContent>
            </div>
          ))}
        {it.error && <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[12.5px] text-amber-400">{it.error}</p>}
        {!it.running && it.usd != null && <p className="text-[10.5px] tabular-nums text-muted-foreground/50">${it.usd.toFixed(3)}</p>}
      </MessageBody>
    </Message>
  )
}

function fromHistory(chat: ChatFull): Item[] {
  const items: Item[] = []
  const tools = new Map<string, ToolPart>()
  chat.messages.forEach((m, mi) => {
    if (m.role === 'user') {
      for (const b of m.content) {
        if (b.type !== 'tool_result' || !b.tool_use_id) continue
        const t = tools.get(b.tool_use_id)
        const text = typeof b.content === 'string' ? b.content : Array.isArray(b.content) ? b.content.map((x: any) => x.text || '').join('') : ''
        if (t) { if (b.is_error) t.error = text; else t.output = text }
      }
      const text = m.content.filter((b) => b.type === 'text').map((b) => b.text || '').join('').replace(NOTE_PREFIX, '')
      if (text) {
        const f = text.match(FILE_PREFIX)
        items.push({ kind: 'user', text: f ? text.slice(f[0].length) : text, file: f?.[1] })
      }
      return
    }
    let a = items.at(-1)
    if (!a || a.kind !== 'assistant') { a = { kind: 'assistant', parts: [], running: false }; items.push(a) }
    const parts = (a as Assistant).parts
    m.content.forEach((b, bi) => {
      const key = `${mi}:${bi}`
      if (b.type === 'thinking' && b.thinking) parts.push({ kind: 'note', key, text: b.thinking })
      else if (b.type === 'text' && b.text) parts.push({ kind: 'text', key, text: b.text })
      else if (b.type === 'tool_use' && b.id && b.name !== 'end_chat') {
        const t: ToolPart = { kind: 'tool', id: b.id, name: b.name || '', input: b.input, ms: chat.tool_ms[b.id] ?? 0, rune: chat.rune?.[b.id] }
        tools.set(b.id, t)
        parts.push(t)
      }
    })
  })
  return items
}

/* ------------------------------------------------- page */

export default function ScanChat() {
  const nav = useNavigate()
  const { id: routeId } = useParams()
  const [search] = useSearchParams()
  const [ready, setReady] = useState(false)
  const [chats, setChats] = useState<ChatRow[]>([])
  const [jobs, setJobs] = useState<ScanJobRow[]>([])
  const [chatId, setChatId] = useState<string | null>(routeId || null)
  const [items, setItems] = useState<Item[]>([])
  const [text, setText] = useState('')
  const [attached, setAttached] = useState<Attached | null>(null)
  const [sideOpen, setSideOpen] = useState(false)
  const [scanJobId, setScanJobId] = useState<string | null>(null)
  const [repTick, setRepTick] = useState(0) // bumped when Nyx + Rune change the file's verdict
  const abortRef = useRef<AbortController | null>(null)
  const chatIdRef = useRef<string | null>(routeId || null) // the chat this page shows, readable from async loops
  const [reconnecting, setReconnecting] = useState(false)
  const selfNav = useRef<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const taRef = useRef<HTMLTextAreaElement>(null)
  const running = items.some((i) => i.kind === 'assistant' && i.running)
  // Rune is on while an ask_rune call of the running turn has no result yet.
  const runeOn = running && items.some((i) => i.kind === 'assistant' && i.running && i.parts.some((p) => p.kind === 'tool' && p.name === 'ask_rune' && p.output == null && !p.error))
  // Set by the live events where Nyx hands over to Rune and Rune hands back: the header animates only then.
  const handoffAt = useRef(0)
  const handoff = Date.now() - handoffAt.current < 2000
  const names = useMemo(() => Object.fromEntries(jobs.map((j) => [j.id, j.file_name])), [jobs])
  const title = chats.find((c) => c.id === chatId)?.title

  const [quota, setQuota] = useState<{ left: number | null; limit: number | null } | null>(null)
  // Owner key: everyone's chats ("Herkes" tab), opened read-only and followed live.
  const [isOwnerKey, setIsOwnerKey] = useState(false)
  const [allChats, setAllChats] = useState<AllChatRow[]>([])
  const [viewer, setViewer] = useState<ChatViewer | null>(null)
  const seenAt = useRef(0)
  const followingRef = useRef(false)
  // Nyx closed this chat for misuse (the reason replaces the composer); a 2nd strike shows a warning window
  // and a 3rd the ban window, each only after Nyx's own closing message has been written.
  const [closedReason, setClosedReason] = useState<string | null>(null)
  const [misuse, setMisuse] = useState<Misuse | null>(null)
  const pendingMisuse = useRef<Misuse | null>(null)
  const misuseTimer = useRef(0)
  const applyMisuse = (m: Misuse) => {
    setClosedReason(m.reason)
    window.clearTimeout(misuseTimer.current)
    if (m.level >= 2) misuseTimer.current = window.setTimeout(() => setMisuse(m), m.level === 3 ? 5500 : 1500)
  }
  useEffect(() => () => window.clearTimeout(misuseTimer.current), [])
  const refreshLists = useCallback(() => {
    scanApi.chatQuota().then(setQuota).catch(() => {})
    scanApi.chats().then((d) => setChats(d.chats)).catch(() => {})
    scanApi.jobs().then((d) => setJobs(d.jobs)).catch(() => {})
  }, [])

  // Any signed-in key; shared keys also get the public-key notice.
  const [shared, setShared] = useState(false)
  useEffect(() => {
    scanApi.session().then((s) => {
      if (!s.authed) nav('/scan')
      else { setShared(!!s.shared); setIsOwnerKey(s.label === 'owner'); setReady(true); refreshLists() }
    }).catch(() => nav('/scan'))
  }, [nav, refreshLists])

  // Open the chat named in the URL (not the one this page just created mid-stream).
  useEffect(() => {
    if (!ready || (routeId && routeId === selfNav.current)) return
    setChatId(routeId || null)
    setClosedReason(null)
    if (!routeId) { setItems([]); setScanJobId(null); setViewer(null); return }
    chatIdRef.current = routeId
    scanApi.chat(routeId).then((d) => {
      setItems(fromHistory(d.chat)); setScanJobId(d.chat.job_id)
      setClosedReason(d.chat.closed ? d.chat.closed_reason || 'kötüye kullanım' : null)
      setViewer(d.chat.readonly && d.chat.viewer ? d.chat.viewer : null)
      seenAt.current = d.chat.updated_at
      if (d.chat.running) follow(routeId) // a turn still at work (or resumed after a restart): join it
    }).catch(() => nav('/scan/chat', { replace: true }))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeId, ready, nav])

  // ?job=<id> attaches a scanned file to the next message; &auto=1 (right after an upload) starts the analysis.
  const autoDone = useRef(false)
  useEffect(() => {
    const j = search.get('job')
    if (!j || !ready) return
    scanApi.report(j).then((r) => {
      const file = { id: r.job.id, name: r.job.file_name }
      if (search.get('auto') === '1' && !autoDone.current) {
        autoDone.current = true
        nav('/scan/chat', { replace: true })
        send(DEFAULT_PROMPT, file)
      } else { setAttached(file); setScanJobId(file.id) }
    }).catch(() => {})
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, ready])

  // The full report of the file this chat is about, refreshed while the scan runs (the left panel's categories).
  const [rep, setRep] = useState<ScanReport | null>(null)
  const [providerNames, setProviderNames] = useState<Record<string, string>>({})
  useEffect(() => {
    scanApi.info().then((i) => {
      setProviderNames(Object.fromEntries(i.providers.map((p) => [p.id, p.name])))
      if (i.turnstile_site_key) preloadTurnstile() // so the first message doesn't wait for Cloudflare's script
    }).catch(() => {})
  }, [])
  const nameOf = useCallback((s: string) => providerNames[s] || ({ local: 'ClashGear', claude: 'Nyx', malpedia: 'Malpedia' } as Record<string, string>)[s] || s, [providerNames])
  useEffect(() => {
    if (!scanJobId) { setRep(null); return }
    let stop = false, timer = 0
    const load = () => scanApi.report(scanJobId).then((r) => {
      if (stop) return
      setRep(r)
      if (r.job.status === 'running') timer = window.setTimeout(load, 4000)
      else refreshLists()
    }).catch(() => {})
    load()
    return () => { stop = true; window.clearTimeout(timer) }
  }, [scanJobId, refreshLists, repTick])
  const scan = rep && (() => {
    const live = rep.results.filter((x) => x.status !== 'disabled')
    return { id: rep.job.id, status: rep.job.status, verdict: rep.job.verdict, score: rep.job.score, done: live.filter((x) => !['queued', 'running'].includes(x.status)).length, total: live.length }
  })()
  const [tab, setTab] = useState<'analysis' | 'history' | 'all'>('history')
  useEffect(() => { setTab((t) => (t === 'all' ? t : scanJobId ? 'analysis' : 'history')) }, [scanJobId])

  // Owner: the everyone list refreshes while it is open.
  useEffect(() => {
    if (!isOwnerKey || tab !== 'all') return
    const load = () => scanApi.chatsAll().then((d) => setAllChats(d.chats)).catch(() => {})
    load()
    const t = window.setInterval(load, 8000)
    return () => window.clearInterval(t)
  }, [isOwnerKey, tab])
  // Read-only view of someone's chat: each turn's stream ends with it, so check for the user's next turn.
  useEffect(() => {
    if (!viewer || !chatId) return
    const t = window.setInterval(() => {
      if (followingRef.current || chatIdRef.current !== chatId) return
      scanApi.chat(chatId).then((d) => {
        if (d.chat.running) follow(chatId)
        else if (d.chat.updated_at !== seenAt.current) { seenAt.current = d.chat.updated_at; setItems(fromHistory(d.chat)) }
      }).catch(() => {})
    }, 4000)
    return () => window.clearInterval(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewer, chatId])

  const patchAssistant = (fn: (a: Assistant) => void) => setItems((prev) => {
    const a = prev.at(-1)
    if (!a || a.kind !== 'assistant') return prev
    const copy = { ...a, parts: a.parts.map((p) => ({ ...p })) }
    fn(copy)
    return [...prev.slice(0, -1), copy]
  })
  const toolOf = (a: Assistant, id: string) => a.parts.find((p) => p.kind === 'tool' && p.id === id) as ToolPart | undefined

  const onEvent = (ev: ChatEvent) => {
    switch (ev.type) {
      case 'sync': {
        // the saved transcript; a running turn keeps an open assistant item for the live events
        const next = fromHistory(ev.chat)
        if (ev.chat.running) {
          const last = next.at(-1)
          if (last?.kind === 'assistant') last.running = true
          else next.push({ kind: 'assistant', parts: [], running: true })
        }
        setItems(next)
        if (ev.chat.closed && !ev.chat.running) setClosedReason(ev.chat.closed_reason || 'kötüye kullanım')
        break
      }
      case 'misuse':
        pendingMisuse.current = { level: ev.level, reason: ev.reason, behavior: ev.behavior }
        break
      case 'chat':
        chatIdRef.current = ev.id
        setChatId(ev.id)
        if (ev.id !== routeId) { selfNav.current = ev.id; nav(`/scan/chat/${ev.id}`, { replace: true }) }
        refreshLists()
        break
      case 'note': case 'text':
        patchAssistant((a) => {
          const p = a.parts.find((x) => x.kind === ev.type && x.key === ev.key) as Extract<Part, { key: string }> | undefined
          if (p) p.text += ev.text
          else a.parts.push({ kind: ev.type, key: ev.key, text: ev.text })
        })
        break
      case 'tool_start':
        if (ev.name === 'end_chat') break
        patchAssistant((a) => { if (!toolOf(a, ev.id)) a.parts.push({ kind: 'tool', id: ev.id, name: ev.name }) })
        break
      case 'tool_input':
        if (ev.name === 'end_chat') break
        patchAssistant((a) => { const t = toolOf(a, ev.id); if (t) t.input = ev.input; else a.parts.push({ kind: 'tool', id: ev.id, name: ev.name, input: ev.input }) })
        break
      case 'tool_done':
        if (ev.name === 'ask_rune') handoffAt.current = Date.now() // Rune hands back to Nyx
        patchAssistant((a) => { const t = toolOf(a, ev.id); if (t) { t.ms = ev.ms; t.error = ev.error; t.output = ev.output } })
        break
      // Rune's block under its ask_rune call (copied on every change so React sees it)
      case 'rune_start':
        handoffAt.current = Date.now() // Nyx hands over to Rune
        patchAssistant((a) => { const t = toolOf(a, ev.parent); if (t) t.rune = { intro: '', steps: [], report: '' } })
        break
      case 'rune_text': case 'rune_report':
        patchAssistant((a) => {
          const t = toolOf(a, ev.parent)
          if (!t) return
          const r = t.rune || { intro: '', steps: [], report: '' }
          t.rune = ev.type === 'rune_text' ? { ...r, intro: r.intro + ev.text } : { ...r, report: ev.text }
        })
        break
      case 'sub_tool_start':
        patchAssistant((a) => {
          const t = toolOf(a, ev.parent)
          if (!t) return
          const r = t.rune || { intro: '', steps: [], report: '' }
          t.rune = { ...r, steps: [...r.steps, { id: ev.id, name: ev.name, input: ev.input }] }
        })
        break
      case 'rune_ask': case 'nyx_reply':
        patchAssistant((a) => {
          const t = toolOf(a, ev.parent)
          if (!t) return
          const r = t.rune || { intro: '', steps: [], report: '' }
          const field = ev.type === 'rune_ask' ? 'message' : 'answer'
          const steps = r.steps.some((s) => s.id === ev.id)
            ? r.steps.map((s) => (s.id === ev.id ? { ...s, name: 'ask_nyx', [field]: ev.text } : s))
            : [...r.steps, { id: ev.id, name: 'ask_nyx', [field]: ev.text }]
          t.rune = { ...r, steps }
        })
        break
      case 'sub_tool_input':
        patchAssistant((a) => {
          const t = toolOf(a, ev.parent)
          if (!t?.rune) return
          t.rune = { ...t.rune, steps: t.rune.steps.map((s) => (s.id === ev.id ? { ...s, input: ev.input } : s)) }
        })
        break
      case 'rune_note': case 'rune_note_done':
        patchAssistant((a) => {
          const t = toolOf(a, ev.parent)
          if (!t) return
          const r = t.rune || { intro: '', steps: [], report: '' }
          const has = r.steps.some((s) => s.id === ev.id)
          const steps = has
            ? r.steps.map((s) => (s.id !== ev.id ? s : ev.type === 'rune_note' ? { ...s, text: (s.text || '') + ev.text } : { ...s, ms: ev.ms }))
            : [...r.steps, { id: ev.id, name: 'thought', text: ev.type === 'rune_note' ? ev.text : '', ...(ev.type === 'rune_note_done' ? { ms: ev.ms } : {}) }]
          t.rune = { ...r, steps }
        })
        break
      case 'sub_tool_done':
        patchAssistant((a) => {
          const t = toolOf(a, ev.parent)
          if (!t?.rune) return
          t.rune = { ...t.rune, steps: t.rune.steps.map((s) => (s.id === ev.id ? { ...s, ms: ev.ms, error: ev.error, output: ev.output } : s)) }
        })
        break
      case 'verdict':
        setRepTick((t) => t + 1)
        break
      case 'error':
        patchAssistant((a) => { a.error = ev.message })
        break
      case 'done':
        patchAssistant((a) => { a.running = false; a.usd = ev.usd })
        if (pendingMisuse.current) { applyMisuse(pendingMisuse.current); pendingMisuse.current = null }
        break
    }
  }

  const send = async (preset?: string, presetFile?: Attached) => {
    const file = presetFile ?? attached
    // A file with no question means "analyse it".
    const msg = (preset ?? text).trim() || (file ? DEFAULT_PROMPT : '')
    if (!msg || running || file?.uploading) return
    if (quota?.left === 0) { if (file) setAttached(file); return }
    if (!preset) setText('')
    setAttached(null)
    if (file) setScanJobId(file.id)
    setItems((prev) => [...prev, { kind: 'user', text: msg, file: file?.name }, { kind: 'assistant', parts: [], running: true }])
    const ctrl = new AbortController()
    abortRef.current = ctrl
    let done = false
    let refused = false
    try {
      // Free keys prove a real browser (Cloudflare Turnstile) on every message; the owner key doesn't need to.
      let cf_token: string | null = null
      if (!isOwnerKey) {
        try { cf_token = await scanApi.nyxToken(msg) } catch { throw new ApiError('captcha', 403, 'captcha_required') }
      }
      await scanApi.chatTurn({ chat_id: chatIdRef.current, text: msg, job_id: file?.id, auto: !chatIdRef.current && msg === DEFAULT_PROMPT, cf_token }, (ev) => { if (ev.type === 'done') done = true; onEvent(ev) }, ctrl.signal)
    } catch (e) {
      if (e instanceof ApiError) {
        refused = true
        // VPN: the 'İyi deneme, federal!' window explains it; take the unsent turn back and keep the text
        if (e.code === 'vpn_blocked') { setItems((prev) => prev.slice(0, -2)); setText(msg) }
        // Banned from Nyx: take the turn back and show the ban window again.
        else if (e.code === 'nyx_banned') {
          setItems((prev) => prev.slice(0, -2))
          const m = (e.body as { misuse?: Partial<Misuse> } | undefined)?.misuse
          setMisuse({ level: 3, reason: m?.reason || 'kötüye kullanım', behavior: m?.behavior || '' })
        } else if (e.code === 'chat_closed') { setItems((prev) => prev.slice(0, -2)); setClosedReason((r) => r || 'kötüye kullanım') }
        else patchAssistant((a) => { a.running = false; a.error = e.code === 'chat_ip_quota_exceeded' ? `Bugünkü ${quota?.limit ?? 10} Nyx mesaj hakkını kullandın. Yarın tekrar dene.` : e.code === 'chat_quota_exceeded' ? 'Bu anahtarın bugünkü Nyx mesaj hakkı doldu. Yarın tekrar dene.' : e.code === 'too_fast' ? 'Biraz yavaş: mesajlar arasında birkaç saniye bekle.' : e.code === 'message_too_long' ? 'Mesaj çok uzun (en fazla 3000 karakter). Kod ya da dosya içeriğini yapıştırmak yerine dosyayı yükle.' : e.code === 'automation_detected' ? 'Bu mesaj otomatik bir araçtan gelmiş gibi görünüyor, gönderilmedi. Nyx\'e normal bir tarayıcıdan kendi sorunu yaz.' : e.code === 'captcha_required' ? 'Tarayıcı doğrulaması geçilemedi. Sayfayı yenileyip tekrar dene (reklam engelleyici Cloudflare doğrulamasını engelliyor olabilir).' : e.code === 'browser_required' ?'Nyx\'e sadece ClashGear Scan sayfasından yazılabilir. Sayfayı yenileyip tekrar dene.' : e.code === 'job_not_found' ? 'Bu dosyaya erişimin yok.' : e.code === 'turn_running' ? 'Nyx bu sohbette hâlâ çalışıyor.' : 'İstek reddedildi.' })
      }
    } finally {
      if (abortRef.current === ctrl) abortRef.current = null
    }
    // The stream dropped before the turn finished (a restart, a network blip): the turn goes on server-side, so re-attach.
    if (!done && !refused && !ctrl.signal.aborted && chatIdRef.current) await follow(chatIdRef.current)
    else if (ctrl.signal.aborted) patchAssistant((a) => { if (a.running) { a.running = false; a.error = a.error || 'Durduruldu.' } })
    refreshLists()
  }

  /** Follows a chat's running turn, re-attaching every few seconds while the backend is away (up to ~6 min). */
  const follow = async (id: string) => {
    followingRef.current = true
    try { await followLoop(id) } finally { followingRef.current = false }
  }
  const followLoop = async (id: string) => {
    for (let attempt = 0; attempt < 120; attempt++) {
      if (chatIdRef.current !== id) return
      const ctrl = new AbortController()
      abortRef.current = ctrl
      let done = false
      try {
        await scanApi.chatStream(id, (ev) => { setReconnecting(false); if (ev.type === 'done') done = true; onEvent(ev) }, ctrl.signal)
      } catch { /* backend down: retry */ }
      if (abortRef.current === ctrl) abortRef.current = null
      if (done || ctrl.signal.aborted || chatIdRef.current !== id) { setReconnecting(false); refreshLists(); return }
      setReconnecting(true)
      await new Promise((r) => setTimeout(r, 3000))
    }
    setReconnecting(false)
    patchAssistant((a) => { if (a.running) { a.running = false; a.error = 'Bağlantı kurulamadı. Sayfayı yenileyince Nyx kaldığı yerden görünecek.' } })
  }

  // Stop: ends the turn on the server, then drops the local stream.
  const stop = () => {
    if (chatIdRef.current) scanApi.chatStop(chatIdRef.current).catch(() => {})
    abortRef.current?.abort()
  }

  const upload = async (f: File) => {
    setAttached({ id: '', name: f.name, uploading: true })
    try {
      const r = await scanApi.upload(f, false)
      setAttached({ id: r.id, name: f.name })
      setScanJobId(r.id) // the categories start filling while the question is still being typed
      refreshLists()
    } catch (e) {
      setAttached(null)
      const code = e instanceof ApiError ? e.code : ''
      if (code !== 'vpn_blocked') alert(code === 'quota_exceeded' ? 'Günlük tarama kotası doldu.' : code === 'service_busy' ? 'Ücretsiz analizlerin bugünkü toplam sınırı doldu. Yarın tekrar dene.' : code === 'file_too_large' ? 'Dosya 100 MB sınırını aşıyor.' : 'Yükleme başarısız.')
    }
  }

  // Leaving a chat only stops following it; its turn keeps going on the server and is there when you come back.
  const newChat = () => { abortRef.current?.abort(); chatIdRef.current = null; selfNav.current = null; setItems([]); setChatId(null); setScanJobId(null); nav('/scan/chat'); setSideOpen(false); taRef.current?.focus() }
  const openChat = (id: string) => { abortRef.current?.abort(); chatIdRef.current = null; selfNav.current = null; nav(`/scan/chat/${id}`); setSideOpen(false) }
  const removeChat = async (id: string) => {
    await scanApi.deleteChat(id).catch(() => {})
    if (id === chatId) newChat()
    refreshLists()
  }
  const pickJob = (id: string) => {
    const j = jobs.find((x) => x.id === id)
    if (j) { setAttached({ id: j.id, name: j.file_name }); setScanJobId(j.id) }
    setSideOpen(false)
    taRef.current?.focus()
  }

  // the textarea grows with its content
  useEffect(() => {
    const ta = taRef.current
    if (!ta) return
    ta.style.height = '0px'
    ta.style.height = `${Math.min(ta.scrollHeight, 240)}px`
  }, [text])

  if (!ready) return <div className="scan-dark dark grid h-[100dvh] place-items-center bg-background"><Loader className="size-5 animate-spin text-muted-foreground" /></div>

  const chatItems: BackgroundInboxItem[] = chats.map((c) => ({
    id: c.id, title: c.title, detail: c.job_id ? names[c.job_id] : undefined, time: ago(c.updated_at), active: c.id === chatId,
    status: c.id === chatId && running ? 'running' : 'ready',
  }))
  const jobItems: BackgroundInboxItem[] = jobs.map((j) => ({
    id: j.id, title: j.file_name, time: ago(j.created_at), status: j.status === 'running' ? 'running' : 'ready',
    detail: j.status === 'running' ? 'Taranıyor…' : `${j.verdict === 'malicious' ? 'Zararlı' : j.verdict === 'suspicious' ? 'Şüpheli' : j.verdict === 'pua' ? 'Hile aracı / PUA' : j.verdict === 'clean' ? 'Temiz' : 'Bilinmiyor'} · ${j.score ?? '—'}/100`,
  }))

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex h-14 shrink-0 items-center justify-between px-4">
        <Link to="/scan" className="flex items-center gap-2 text-[14px] font-semibold text-foreground"><BrandMark size={20} /> ClashGear <span className="font-normal text-muted-foreground">Scan</span></Link>
        <button type="button" onClick={() => setSideOpen(false)} className="rounded-md p-1 text-muted-foreground hover:bg-muted lg:hidden" aria-label="Kapat"><X className="size-4" /></button>
      </div>
      <div className="flex gap-2 px-3">
        <button type="button" onClick={newChat} className="press flex flex-1 items-center gap-2 rounded-xl border border-border px-3 py-2 text-[13px] text-foreground hover:bg-muted"><Plus className="size-4" /> Yeni analiz</button>
      </div>
      <div className={cn('mx-3 mt-3 grid rounded-lg bg-muted/50 p-0.5 text-[12.5px]', isOwnerKey ? 'grid-cols-3' : 'grid-cols-2')}>
        {(isOwnerKey ? (['analysis', 'history', 'all'] as const) : (['analysis', 'history'] as const)).map((k) => (
          <button key={k} type="button" onClick={() => setTab(k)} className={cn('rounded-md py-1.5 transition-colors', tab === k ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground')}>
            {k === 'analysis' ? <>Analiz{scan?.status === 'running' && <Loader className="ml-1.5 inline size-3 animate-spin text-blue-400" />}</> : k === 'history' ? 'Geçmiş'
              : <>Herkes{allChats.some((c) => c.running) && <span className="ml-1.5 inline-block size-1.5 animate-pulse rounded-full bg-[#d4ff3a] align-middle" />}</>}
          </button>
        ))}
      </div>
      {tab === 'all' ? (
        <div className="mt-3 min-h-0 flex-1 overflow-y-auto px-2 pb-3">
          <BackgroundInbox title="Tüm kullanıcıların sohbetleri" icon={<MessagesSquare className="size-4 text-muted-foreground" />}
            items={allChats.map((c) => ({
              id: c.id, title: c.file_name || c.title, time: ago(c.updated_at), active: c.id === chatId, status: c.running ? 'running' : 'ready',
              detail: `${c.key_label === 'self' ? 'ücretsiz' : c.key_label === 'owner' ? 'sen' : c.key_label || '?'}${c.key_prefix && c.key_label !== 'owner' ? ` ${c.key_prefix}…` : ''}${c.ip ? ` · ${c.ip}` : ''}${c.running ? ' · şu an yazıyor' : ''}`,
            }))}
            onSelect={openChat} className="bg-transparent p-0"
            empty={<p className="px-3 py-2 text-[12.5px] text-muted-foreground/70">Henüz sohbet yok.</p>} />
        </div>
      ) : tab === 'analysis' ? (
        <div className="mt-3 flex min-h-0 flex-1 flex-col">
          {rep ? <AnalysisPanel rep={rep} nameOf={nameOf} /> : (
            <div className="px-6 py-10 text-center text-[12.5px] leading-relaxed text-muted-foreground/70">
              Bir dosya yükle ya da Geçmiş'ten taranmış bir dosya seç. Servislerin sonuçları burada kategorilere ayrılıp canlı dolacak.
            </div>
          )}
        </div>
      ) : (
      <div className="mt-3 min-h-0 flex-1 space-y-3 overflow-y-auto px-2 pb-3">
        <BackgroundInbox title="Analizler" icon={<MessagesSquare className="size-4 text-muted-foreground" />} items={chatItems}
          onSelect={openChat} onDismiss={removeChat} className="bg-transparent p-0"
          empty={<p className="px-3 py-2 text-[12.5px] text-muted-foreground/70">Henüz analiz yok.</p>} />
        <BackgroundInbox title="Taranmış dosyalar" icon={<FolderSearch className="size-4 text-muted-foreground" />} items={jobItems}
          onSelect={pickJob} className="bg-transparent p-0"
          empty={<p className="px-3 py-2 text-[12.5px] text-muted-foreground/70">Taranmış dosya yok.</p>} />
      </div>
      )}
      <Link to="/scan/app" className="flex shrink-0 items-center gap-2 border-t border-border px-4 py-3 text-[12.5px] text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" /> Tarama paneli</Link>
    </div>
  )

  // Owner watching someone's chat: no composer, just who it belongs to and a stop button for a runaway turn.
  const viewerBar = viewer && (
    <div className="mx-auto flex w-full max-w-3xl flex-wrap items-center gap-3 rounded-2xl border border-[#d4ff3a]/25 bg-[#d4ff3a]/[0.06] px-4 py-3 text-[13px]">
      <span className={cn('size-2 shrink-0 rounded-full', running ? 'animate-pulse bg-[#d4ff3a]' : 'bg-muted-foreground/60')} />
      <span className="min-w-0 flex-1 text-foreground/90">
        <span className="font-semibold text-[#d4ff3a]">Salt okunur izleme</span> · {viewer.key_label === 'self' ? 'ücretsiz anahtar' : viewer.key_label}{viewer.key_prefix && viewer.key_label !== 'owner' ? ` (${viewer.key_prefix}…)` : ''}{viewer.ip ? ` · ${viewer.ip}` : ''}
        <span className="text-muted-foreground"> · {running ? 'Nyx şu an bu kullanıcıya yazıyor, canlı görüyorsun' : 'kullanıcı yeni mesaj atınca burada canlı akar'}</span>
      </span>
      {running && <button type="button" onClick={stop} className="press rounded-lg bg-white/10 px-3 py-1.5 text-xs font-semibold text-white hover:bg-white/15">Durdur</button>}
    </div>
  )

  // In place of the composer once Nyx has closed the chat.
  const closedBar = (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
      className="mx-auto flex w-full max-w-3xl items-center gap-3 rounded-[24px] border border-red-500/25 bg-red-500/[0.07] px-4 py-3.5 text-[13.5px]">
      <AiAvatar size="sm" label="Nyx" />
      <p className="min-w-0 flex-1 leading-snug text-foreground/90">
        Nyx bu sohbeti <b className="text-red-300">{closedReason}</b> tespit ettiği için sonlandırdı.
      </p>
      <button type="button" onClick={newChat} className="press shrink-0 rounded-full border border-border px-3 py-1.5 text-[12.5px] text-foreground hover:bg-muted">Yeni analiz</button>
    </motion.div>
  )

  const composer = (
    <div className="relative mx-auto w-full max-w-3xl">
      {shared && <p className="mb-2 px-2 text-center text-[11.5px] text-amber-400/90">Herkese açık anahtar: sohbetin sadece senin IP adresine açık, ama yüklediğin dosyalar anahtarı kullanan herkese görünür. Kişisel bilgi paylaşma.</p>}
      <div className="flex flex-col gap-1.5 rounded-[24px] border border-border bg-card p-2 shadow-[0_8px_30px_-12px_rgba(0,0,0,.7)] transition-colors focus-within:border-foreground/20">
        {attached && (
          <div className="flex px-1.5 pt-1">
            <span className="flex max-w-full items-center gap-2 rounded-xl border border-border bg-muted/50 px-3 py-2 text-xs text-foreground">
              {attached.uploading ? <Loader className="size-4 animate-spin text-muted-foreground" /> : <FileText className="size-4 text-muted-foreground" />}
              <span className="truncate">{attached.name}</span>
              {!attached.uploading && <button type="button" aria-label="Kaldır" onClick={() => setAttached(null)} className="text-muted-foreground hover:text-foreground"><X className="size-3.5" /></button>}
            </span>
          </div>
        )}
        <textarea ref={taRef} value={text} onChange={(e) => setText(e.target.value)} rows={1} placeholder="Nyx'e sor…" maxLength={isOwnerKey ? undefined : 3000}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send() } }}
          className="max-h-[240px] min-h-[44px] w-full resize-none bg-transparent px-2.5 py-2 text-[14.5px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none" />
        <div className="flex items-center gap-1">
          <input ref={fileRef} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = '' }} />
          <button type="button" onClick={() => fileRef.current?.click()} className="press flex items-center gap-1.5 rounded-full px-2.5 py-1.5 text-[12.5px] text-muted-foreground hover:bg-muted hover:text-foreground"><Paperclip className="size-4" /> Dosya ekle</button>
          {quota?.left != null
            ? <span className={cn('ml-auto mr-1 text-[11px] tabular-nums', quota.left === 0 ? 'text-amber-400' : 'text-muted-foreground/60')}>{quota.left === 0 ? 'Bugünkü mesaj hakkın doldu' : `Bugün ${quota.left}/${quota.limit} mesaj hakkın kaldı`}</span>
            : <span className="ml-auto mr-1 hidden text-[11px] text-muted-foreground/60 sm:inline">Enter gönderir · Shift+Enter yeni satır</span>}
          {running
            ? <button type="button" aria-label="Durdur" onClick={stop} className="press grid size-9 place-items-center rounded-full bg-foreground text-background"><Square className="size-3.5 fill-current" /></button>
            : <button type="button" aria-label="Gönder" disabled={(!text.trim() && !attached) || !!attached?.uploading || quota?.left === 0} onClick={() => send()} className="press grid size-9 place-items-center rounded-full bg-foreground text-background transition-opacity disabled:opacity-25"><ArrowUp className="size-4" /></button>}
        </div>
      </div>
    </div>
  )

  return (
    <div className="scan-dark dark flex h-[100dvh] overflow-hidden bg-background text-foreground">
      <aside className="hidden w-[340px] shrink-0 border-r border-border bg-card/40 lg:block xl:w-[380px]">{sidebar}</aside>
      <AnimatePresence>
        {sideOpen && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSideOpen(false)} className="fixed inset-0 z-30 bg-black/60 lg:hidden" />
            <motion.aside initial={{ x: -320 }} animate={{ x: 0 }} exit={{ x: -320 }} transition={SPRING} className="fixed inset-y-0 left-0 z-40 w-[min(360px,90vw)] border-r border-border bg-background lg:hidden">{sidebar}</motion.aside>
          </>
        )}
      </AnimatePresence>

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border px-4">
          <button type="button" onClick={() => setSideOpen(true)} className="rounded-md p-1.5 text-muted-foreground hover:bg-muted lg:hidden" aria-label="Menü"><PanelLeft className="size-4" /></button>
          {/* Nyx hands over: while Rune works, Rune (blob, name, title) takes Nyx's seat in the header. Only a
              live handover (or Rune handing back) breaks up; opening another chat swaps at once. */}
          <AnimatePresence mode="wait" initial={false}>
            <motion.span key={runeOn ? 'rune' : 'nyx'} className="flex shrink-0"
              initial={handoff ? { scale: 0.5, skewX: 35, opacity: 0, filter: 'blur(6px) hue-rotate(120deg)' } : false}
              animate={{ scale: 1, skewX: handoff ? [35, -18, 9, 0] : 0, opacity: 1, filter: 'blur(0px) hue-rotate(0deg)' }}
              exit={handoff ? { scale: 0.5, skewX: -35, x: [0, -3, 3, 0], opacity: 0, filter: 'blur(6px) hue-rotate(-120deg)', transition: { duration: 0.22 } } : { opacity: 0, transition: { duration: 0 } }}
              transition={handoff ? { duration: 0.5, ease: [0.22, 1, 0.36, 1] } : { duration: 0 }}>
              {runeOn ? <RuneMascot size={30} awake /> : <AiAvatar size="sm" thinking={running} label="Nyx" />}
            </motion.span>
          </AnimatePresence>
          <div className="min-w-0 leading-tight">
            <p className="flex min-w-0 items-baseline gap-1.5 text-[13.5px] font-semibold">
              <GlitchText text={runeOn ? 'Rune' : 'Nyx'} animate={handoff} className={cn('shrink-0', runeOn ? 'text-rose-400' : 'text-foreground')} />
              {title && <span className="truncate font-normal text-muted-foreground">· {title}</span>}
            </p>
            <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <span className={cn('size-1.5 shrink-0 rounded-full', runeOn ? 'animate-pulse bg-rose-400' : running ? 'animate-pulse bg-blue-400' : 'bg-emerald-400')} />
              <GlitchText text={reconnecting ? 'Yeniden bağlanıyor…' : runeOn ? 'ClashGear Tersine Mühendisi' : running ? 'Analiz ediyor' : 'ClashGear analisti'} animate={handoff} className={cn(runeOn && 'text-rose-400')} />
            </p>
          </div>
          {scan && (
            <Link to={`/scan/r/${scan.id}`} className="press ml-auto flex shrink-0 items-center gap-2 rounded-full border border-border px-3 py-1.5 text-[12px] text-muted-foreground hover:bg-muted hover:text-foreground">
              {scan.status === 'running' ? (
                <>
                  <Loader className="size-3.5 animate-spin text-blue-400" />
                  <span>Taranıyor</span>
                  <span className="relative h-1 w-16 overflow-hidden rounded-full bg-muted"><span className="absolute inset-y-0 left-0 rounded-full bg-blue-400 transition-[width] duration-500" style={{ width: `${scan.total ? (scan.done / scan.total) * 100 : 0}%` }} /></span>
                  <span className="tabular-nums">{scan.done}/{scan.total}</span>
                </>
              ) : (
                <>
                  <span className={cn('size-2 rounded-full', scan.verdict === 'malicious' ? 'bg-amber-500' : scan.verdict === 'suspicious' ? 'bg-amber-300' : scan.verdict === 'pua' ? 'bg-violet-400' : scan.verdict === 'clean' ? 'bg-emerald-400' : 'bg-muted-foreground')} />
                  <span className="text-foreground">{scan.verdict === 'malicious' ? 'Zararlı' : scan.verdict === 'suspicious' ? 'Şüpheli' : scan.verdict === 'pua' ? 'Hile aracı / PUA' : scan.verdict === 'clean' ? 'Temiz' : 'Bilinmiyor'}</span>
                  <span className="tabular-nums">{scan.score ?? '—'}/100</span>
                  <span className="hidden sm:inline">· Rapor</span>
                </>
              )}
            </Link>
          )}
        </header>

        {!items.length ? (
          <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-6 px-4">
            <AiAvatar size="lg" label="Nyx" />
            <p className="text-center text-[26px] font-semibold tracking-[-0.02em] text-foreground">Hangi dosyayı inceleyelim?</p>
            {viewer ? viewerBar : closedReason ? closedBar : composer}
            <div className="flex max-w-3xl flex-wrap justify-center gap-2">
              {['Bu dosya ne yapıyor? Adım adım anlat.', 'Kodun derinine in: Rune incelesin.', 'C2 adresleri ve IOC listesini çıkar.', 'Paketlenmiş mi? Unpack edilmiş haline bak.'].map((s) => (
                <button key={s} type="button" onClick={() => { setText(s); taRef.current?.focus() }} className="press rounded-full border border-border px-3 py-1.5 text-[12.5px] text-muted-foreground hover:bg-muted hover:text-foreground">{s}</button>
              ))}
            </div>
          </div>
        ) : (
          <>
            <MessageThread className="min-h-0 flex-1">
              <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 pb-4">
                {items.map((it, i) => it.kind === 'user' ? (
                  <Message key={i} role="user">
                    <MessageBody>
                      {it.file && <span className="flex items-center gap-2 rounded-xl border border-border bg-muted/40 px-3 py-2 text-xs text-foreground"><FileText className="size-4 text-muted-foreground" /> {it.file}</span>}
                      <MessageContent className="whitespace-pre-wrap rounded-2xl rounded-tr-md bg-muted px-4 py-2.5 text-[14px] text-foreground">{it.text}</MessageContent>
                    </MessageBody>
                  </Message>
                ) : <AssistantTurn key={i} it={it} names={names} full={isOwnerKey} />)}
              </div>
              <MessageThreadScrollButton />
            </MessageThread>
            <div className="shrink-0 px-3 pb-4 pt-1 sm:px-6">{viewer ? viewerBar : closedReason ? closedBar : composer}</div>
          </>
        )}
      </main>
      <NyxMisuseModal misuse={misuse} onClose={() => setMisuse(null)} />
    </div>
  )
}
