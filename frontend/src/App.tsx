import { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Scan from '@/pages/Scan'
import { VpnBlockedModal } from '@/components/scan/VpnBlockedModal'
import { ScanGate } from '@/components/scan/ScanGate'

// The analyst chat and the live sandbox screen stay out of the main bundle.
const ScanChat = lazy(() => import('@/pages/ScanChat'))
const ScanLive = lazy(() => import('@/pages/ScanLive'))
const fallback = <div className="min-h-screen bg-[#0a0a0a]" />
const chat = <Suspense fallback={fallback}><ScanChat /></Suspense>

export default function App() {
  return (
    <>
      <VpnBlockedModal />
      <Routes>
        <Route path="/" element={<Navigate to="/scan" replace />} />
        <Route path="/scan" element={<ScanGate><Scan view="landing" /></ScanGate>} />
        <Route path="/scan/app" element={<ScanGate><Scan view="app" /></ScanGate>} />
        <Route path="/scan/r/:id" element={<ScanGate always><Scan view="report" /></ScanGate>} />
        <Route path="/scan/diff/:a/:b" element={<ScanGate always><Scan view="diff" /></ScanGate>} />
        <Route path="/scan/chat" element={<ScanGate>{chat}</ScanGate>} />
        <Route path="/scan/chat/:id" element={<ScanGate>{chat}</ScanGate>} />
        <Route path="/scan/live/:lid" element={<ScanGate><Suspense fallback={fallback}><ScanLive /></Suspense></ScanGate>} />
        <Route path="*" element={<Navigate to="/scan" replace />} />
      </Routes>
    </>
  )
}
