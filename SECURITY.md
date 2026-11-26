# Security policy

ClashGear Scan handles untrusted files and talks to many third-party services, so security reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer within 7 days.
Fixes are released as soon as they are ready, and reporters are credited unless they ask not to be.

## In scope

- `backend/` (upload handling, access keys and sessions, SSRF guards, provider calls, the AI analyst's tool use)
- `frontend/`
- `sidecars/` (link fetcher, static engines, Token Trap bait profile)

## Out of scope

- Vulnerabilities in the third-party services Scan queries (report those to the vendor)
- Malware samples themselves
- Denial of service through volume alone
