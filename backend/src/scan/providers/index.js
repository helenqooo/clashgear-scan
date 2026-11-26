// Every analysis source. A source runs only when all of its `env` variables are set, so adding a
// service later is just a .env line plus a backend restart.

import { virustotal, vtSandbox, vtIoc, linkReputation } from './virustotal.js'
import { circl, metadefender, opentip, opentipIoc, sophos, cymru, reversinglabs, xforce, xforceIoc } from './av.js'
import { malwarebazaar, threatfox, urlhaus, yaraify, threatfoxIoc, urlhausIoc, feodoTracker } from './abusech.js'
import { alienvault, alienvaultIoc, inquest, malshare, virusshare, threatminer, hybridLookup, abuseipdb, greynoise, shodan, urlscan, safebrowsing, pulsedive } from './intel.js'
import { triage, hybridSandbox, capeSandbox, honeyTrap, threatzone, anyrun, joe, vmray } from './sandbox.js'
import { unpacme, filescan, intezer } from './deep.js'
import { cgStatic } from './local.js'

export const PROVIDERS = [
  circl,
  virustotal, metadefender, opentip, sophos, cymru, reversinglabs,
  malwarebazaar, threatfox, urlhaus, hybridLookup, alienvault, xforce, malshare, virusshare, threatminer,
  yaraify, inquest, cgStatic,
  unpacme,
  filescan,
  triage, hybridSandbox, capeSandbox, honeyTrap, threatzone, vtSandbox, anyrun, joe, vmray,
  vtIoc, opentipIoc, xforceIoc, threatfoxIoc, urlhausIoc, feodoTracker, alienvaultIoc, abuseipdb, greynoise, shodan, urlscan, safebrowsing, pulsedive,
  intezer, linkReputation,
]

export const enabled = (p) => p.env.every((k) => !!process.env[k]?.trim())

export const LAYERS = [
  { n: 1, id: 'identity' },
  { n: 2, id: 'known_good' },
  { n: 3, id: 'multi_av' },
  { n: 4, id: 'intel' },
  { n: 5, id: 'static' },
  { n: 6, id: 'unpack' },
  { n: 7, id: 'deobfuscation' },
  { n: 8, id: 'sandbox' },
  { n: 9, id: 'network' },
  { n: 10, id: 'genetics_ai' },
]

/** Public list for the landing page and the panel: what exists and what is switched on. */
export function describeProviders() {
  return PROVIDERS.map((p) => ({ id: p.id, name: p.name, layer: p.layer, kind: p.kind, paid: !!p.paid, enabled: enabled(p) }))
}
