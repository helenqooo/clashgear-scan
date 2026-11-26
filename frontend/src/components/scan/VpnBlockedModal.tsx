import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { SentinelEye } from '@/components/ui/sentinel-eye'

// Shown when the backend refuses a free-tier request coming through a VPN / proxy / relay / Tor
// (scanApi dispatches "cg-vpn-blocked" with what the server saw). Copy approved by the owner.
export type VpnInfo = { kind: 'vpn' | 'relay' | 'warp' | 'tor'; label: string | null; isp: string; country: string | null; sure: boolean }
export const VPN_EVENT = 'cg-vpn-blocked'

const countryName = (cc: string | null) => {
  if (!cc) return ''
  try { return new Intl.DisplayNames(['tr'], { type: 'region' }).of(cc) || cc } catch { return cc }
}

export function VpnBlockedModal() {
  const [info, setInfo] = useState<VpnInfo | null>(null)
  useEffect(() => {
    const on = (e: Event) => setInfo((e as CustomEvent<VpnInfo>).detail || { kind: 'vpn', label: null, isp: '', country: null, sure: false })
    window.addEventListener(VPN_EVENT, on)
    return () => window.removeEventListener(VPN_EVENT, on)
  }, [])

  const where = info && [
    info.kind === 'vpn' && info.label ? `muhtemelen ${info.label}` : info.label,
    info.isp,
    countryName(info.country),
  ].filter(Boolean).join(' · ')

  return createPortal(
    <AnimatePresence>
      {info && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="scan-dark dark fixed inset-0 z-[200] grid place-items-center bg-black/75 p-4 backdrop-blur-md" role="alertdialog" aria-modal="true" aria-labelledby="vpn-title">
          <motion.div initial={{ opacity: 0, y: 16, scale: 0.96, filter: 'blur(6px)' }} animate={{ opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }}
            transition={{ type: 'spring', bounce: 0.25, duration: 0.6 }}
            className="relative w-full max-w-md overflow-hidden rounded-3xl border border-[#d4ff3a]/25 bg-[#0d0f0b] p-6 text-left shadow-[0_30px_90px_-20px_rgba(212,255,58,0.25)]">
            <div aria-hidden className="pointer-events-none absolute -right-16 -top-16 size-48 rounded-full bg-[#d4ff3a]/15 blur-3xl" />
            <div className="-ml-4 -mt-2"><SentinelEye size={84} /></div>
            <h2 id="vpn-title" className="mt-2 text-2xl font-bold tracking-[-0.02em] text-white">İyi deneme, federal!</h2>
            {info.kind === 'tor' && <p className="mt-1 text-sm text-[#d4ff3a]">Tor'la dosya taramak… cidden mi?</p>}

            <div className="mt-4 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-neutral-500">Seni şuradan görüyoruz</p>
              <p className="mt-1 text-[15px] font-medium text-white">{where || 'VPN / proxy'}</p>
            </div>

            <p className="mt-4 text-sm leading-relaxed text-neutral-300">
              ClashGear Scan'i VPN, proxy ya da Tor arkasından kullanamazsın. Ücretsiz haklar bağlantı başına veriliyor; IP değiştirip limitleri sıfırlamak bu oyunun kuralı değil.
            </p>
            <p className="mt-3 text-sm leading-relaxed text-neutral-300">
              VPN'i kapat, sayfayı yenile, kaldığın yerden devam et. Gizliliğin için endişelenme: yüklediğin dosyalar, raporların ve Nyx sohbetlerin zaten sadece sana açık.
            </p>
            {info.kind === 'relay' && (
              <p className="mt-3 rounded-xl bg-[#d4ff3a]/10 px-3 py-2 text-[13px] text-[#e7ff9a]">Kapatmak için: <b>Ayarlar → adın → iCloud → Özel Geçiş → Kapat</b></p>
            )}
            {info.kind === 'warp' && (
              <p className="mt-3 rounded-xl bg-[#d4ff3a]/10 px-3 py-2 text-[13px] text-[#e7ff9a]">Kapatmak için: <b>1.1.1.1 uygulamasında WARP'ı kapat</b></p>
            )}

            <button type="button" onClick={() => setInfo(null)} autoFocus
              className="press mt-6 h-11 w-full rounded-xl bg-[#d4ff3a] text-sm font-bold text-black hover:bg-[#c6f02e]">
              Tamam, kapatıyorum
            </button>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  )
}
