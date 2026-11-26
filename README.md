# ClashGear Scan

Multi-layer threat analysis for files and links. Upload a suspicious file and it goes through a 10-layer pipeline
(hash identity, known-good lookup, multi-engine antivirus, threat-intel feeds, static deep scan, automatic unpacking,
deobfuscation and config extraction, VM sandboxes, network/IOC enrichment) that queries about 40 external security
services. An AI analyst, **Nyx** (Claude), then reads the evidence and writes a plain-language report.

Design rules:

- **Nothing is executed on the web server.** Detonation happens only on isolated sandbox VMs (your own CAPE box and/or
  hosted sandboxes) reached through their APIs or an SSH tunnel.
- **Code decides the verdict, the AI explains it.** The threat score is computed from the services' results in
  `backend/src/scan/score.js`; Nyx comments next to it but cannot change it.
- **Access is key-gated.** Keys are stored as SHA-256 hashes, with per-key daily quotas and expiry.

## Layout

| Path | What it is |
|---|---|
| `backend/src/scan/` | The product: routes (`index.js`), jobs and storage, scoring, the provider adapters (`providers/`), Nyx chat and tools, Token Trap (`honey.js`), live sandbox screen, SSRF-guarded link fetch |
| `backend/src/{config,store}.js`, `backend/server.example.js` | Small stand-ins for the host app: config, sqlite handle, admin session, Fastify boot |
| `frontend/` | React + Vite pages: landing, upload, reports, diff, Nyx chat, live sandbox |
| `sidecars/cg-static/` | Static engines (YARA-Forge, capa, FLOSS, DIE, ssdeep/TLSH, config extraction, olevba, androguard/jadx). Samples are parsed, never run |
| `sidecars/cg-fetch/` | Link fetcher with SSRF guard and an iptables egress fence |
| `sidecars/cg-honey/` | **Token Trap**: a CAPE auxiliary module that plants unique fake credentials (browser, Discord, Steam, wallets) in the guest and reports which ones the sample read or exfiltrated; plus a fake ip-api responder so stealers don't bail on a data-centre IP |

No keys, hosts or database files are included. Every value that has to be filled in is empty in `backend/.env.example`.

## Setup

Node 24+ (the backend uses the built-in `node:sqlite`).

```bash
# backend
cd backend
npm install
cp .env.example .env          # set ADMIN_PASSWORD, SESSION_SECRET and the provider keys you have
npm start                     # http://127.0.0.1:8787

# mint an access key (printed once)
node -e "import('./src/scan/db.js').then(m => console.log(m.createKey({ label: 'owner', dailyQuota: 1000 })))"

# frontend
cd ../frontend
npm install
npm run dev                   # http://localhost:5180/scan (proxies /api to the backend)
```

Every provider is optional: a layer whose key is missing is skipped. The sidecars are only needed if you run your
own CAPE sandbox; see the header comment of each file for how it is deployed.

## Responsible use

This is a defensive tool. Only analyse files you are allowed to handle, keep sandbox VMs isolated from your own
networks, and follow each provider's terms of service (some forbid uploading files you do not own).

## License

[GNU AGPL-3.0](LICENSE). If you run a modified version as a network service, you must offer its source to its users.
