// Adapted from 21st.dev "File Dropzone" (@joyco): single-file drop area with size validation.
// The upstream use-file-upload hook is not in the registry, so drag/drop handling is inline here.
import { useRef, useState, type DragEvent } from 'react'
import { CircleAlert as AlertCircleIcon, File as FileIcon, Upload as UploadIcon, X as XIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'

export interface FileDropzoneProps {
  maxSizeMB?: number
  disabled?: boolean
  labels: { drop: string; any: string; select: string; tooLarge: string; remove: string }
  file: File | null
  onFile: (file: File | null) => void
}

const fmt = (n: number) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`)

export function FileDropzone({ maxSizeMB = 100, disabled, labels, file, onFile }: FileDropzoneProps) {
  const input = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState('')

  const accept = (f: File | undefined | null) => {
    if (!f) return
    if (f.size > maxSizeMB * 1024 * 1024) { setError(labels.tooLarge); return }
    setError('')
    onFile(f)
  }
  const stop = (e: DragEvent) => { e.preventDefault(); e.stopPropagation() }

  return (
    <div className="flex flex-col gap-4">
      <div className="relative">
        <div
          className="relative flex min-h-52 flex-col items-center justify-center overflow-hidden rounded-xl border border-dashed border-input p-4 transition-colors has-[input:focus]:border-ring has-[input:focus]:ring-[3px] has-[input:focus]:ring-ring/50 data-[dragging=true]:bg-accent/50"
          data-dragging={dragging || undefined}
          onDragEnter={(e) => { stop(e); if (!disabled) setDragging(true) }}
          onDragLeave={(e) => { stop(e); if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragging(false) }}
          onDragOver={stop}
          onDrop={(e) => { stop(e); setDragging(false); if (!disabled) accept(e.dataTransfer.files?.[0]) }}
        >
          <input ref={input} type="file" aria-label={labels.select} className="sr-only" disabled={disabled} onChange={(e) => { accept(e.target.files?.[0]); e.target.value = '' }} />
          {file ? (
            <div className="absolute inset-0 flex items-center justify-center p-4">
              <div className="flex flex-col items-center justify-center gap-2 text-center">
                <div aria-hidden className="flex size-16 shrink-0 items-center justify-center rounded-full border bg-background">
                  <FileIcon className="size-8 opacity-60" />
                </div>
                <p className="max-w-[18rem] truncate text-sm font-medium">{file.name}</p>
                <p className="text-xs text-muted-foreground">{fmt(file.size)}</p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center px-4 py-3 text-center">
              <div aria-hidden className="mb-2 flex size-11 shrink-0 items-center justify-center rounded-full border bg-background">
                <UploadIcon className="size-4 opacity-60" />
              </div>
              <p className="mb-1.5 text-sm font-medium">{labels.drop}</p>
              <p className="text-xs text-muted-foreground">{labels.any} (max. {maxSizeMB}MB)</p>
              <Button className="mt-4" variant="outline" onClick={() => input.current?.click()} disabled={disabled}>
                <UploadIcon aria-hidden className="-ms-1 size-4 opacity-60" />
                {labels.select}
              </Button>
            </div>
          )}
        </div>
        {file && !disabled && (
          <div className="absolute right-4 top-4">
            <button aria-label={labels.remove} type="button" onClick={() => onFile(null)} className="z-50 flex size-8 cursor-pointer items-center justify-center rounded-full bg-black/60 text-white outline-none transition-[color,box-shadow] hover:bg-black/80 focus-visible:ring-[3px] focus-visible:ring-ring/50">
              <XIcon aria-hidden className="size-4" />
            </button>
          </div>
        )}
      </div>
      {error && (
        <div className="flex items-center gap-1 text-xs text-destructive" role="alert">
          <AlertCircleIcon className="size-3 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  )
}
