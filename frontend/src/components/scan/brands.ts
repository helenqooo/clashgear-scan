// Which company is behind each analysis source, for the logo strip. Several sources share a vendor
// (abuse.ch runs six of them), so the strip shows one logo per vendor. Logos are the vendors'
// favicons, self-hosted in public/scan-logos (the CSP only allows same-origin images).
import type { ScanProvider } from '@/lib/scanApi'

export type Brand = { slug: string; name: string; logo: string | null; enabled: boolean; count: number }

const BRAND_OF: Record<string, [string, string]> = {
  circl: ['circl', 'CIRCL'],
  virustotal: ['virustotal', 'VirusTotal'], vt_sandbox: ['virustotal', 'VirusTotal'], vt_ioc: ['virustotal', 'VirusTotal'],
  metadefender: ['opswat', 'OPSWAT MetaDefender'],
  opentip: ['kaspersky', 'Kaspersky OpenTIP'], opentip_ioc: ['kaspersky', 'Kaspersky OpenTIP'],
  sophos: ['sophos', 'Sophos Intelix'],
  cymru: ['cymru', 'Team Cymru'],
  reversinglabs: ['reversinglabs', 'ReversingLabs'],
  malwarebazaar: ['abusech', 'abuse.ch'], threatfox: ['abusech', 'abuse.ch'], urlhaus: ['abusech', 'abuse.ch'], yaraify: ['abusech', 'abuse.ch'],
  threatfox_ioc: ['abusech', 'abuse.ch'], urlhaus_ioc: ['abusech', 'abuse.ch'], feodo: ['abusech', 'abuse.ch'],
  hybrid_lookup: ['hybridanalysis', 'Hybrid Analysis'], hybrid_sandbox: ['hybridanalysis', 'Hybrid Analysis'],
  otx: ['alienvault', 'AlienVault OTX'], otx_ioc: ['alienvault', 'AlienVault OTX'],
  xforce: ['ibm', 'IBM X-Force'], xforce_ioc: ['ibm', 'IBM X-Force'],
  malshare: ['malshare', 'MalShare'],
  virusshare: ['virusshare', 'VirusShare'],
  threatminer: ['threatminer', 'ThreatMiner'],
  inquest: ['inquest', 'InQuest Labs'],
  unpacme: ['unpacme', 'UnpacMe'],
  filescan: ['filescan', 'Filescan.io'],
  triage: ['triage', 'Recorded Future Triage'],
  cape: ['cape', 'CAPE Sandbox'], honey: ['cape', 'CAPE Sandbox'],
  threatzone: ['threatzone', 'Threat.Zone'],
  anyrun: ['anyrun', 'ANY.RUN'],
  joe: ['joe', 'Joe Sandbox'],
  vmray: ['vmray', 'VMRay'],
  abuseipdb: ['abuseipdb', 'AbuseIPDB'],
  greynoise: ['greynoise', 'GreyNoise'],
  shodan: ['shodan', 'Shodan'],
  urlscan: ['urlscan', 'urlscan.io'],
  safebrowsing: ['google', 'Google Safe Browsing'],
  pulsedive: ['pulsedive', 'Pulsedive'],
  intezer: ['intezer', 'Intezer'],
}
// Files present in public/scan-logos (MalShare, ThreatMiner and CAPE publish no usable favicon).
const LOGO: Record<string, string> = Object.fromEntries(
  ['abusech', 'abuseipdb', 'alienvault', 'anthropic', 'anyrun', 'circl', 'cymru', 'filescan', 'google', 'greynoise', 'hybridanalysis', 'ibm', 'inquest', 'intezer', 'joe', 'kaspersky', 'opswat', 'pulsedive', 'reversinglabs', 'sophos', 'threatzone', 'triage', 'unpacme', 'urlscan', 'virusshare', 'virustotal', 'vmray']
    .map((s) => [s, `/scan-logos/${s}.png`]).concat([['shodan', '/scan-logos/shodan.jpg']]),
)

export function brandsOf(providers: ScanProvider[]): Brand[] {
  const map = new Map<string, Brand>()
  for (const p of providers) {
    const [slug, name] = BRAND_OF[p.id] || [p.id, p.name]
    const b = map.get(slug) || { slug, name, logo: LOGO[slug] || null, enabled: false, count: 0 }
    b.enabled ||= p.enabled
    b.count++
    map.set(slug, b)
  }
  map.set('anthropic', { slug: 'anthropic', name: 'Claude', logo: LOGO.anthropic, enabled: true, count: 1 })
  return [...map.values()]
}
