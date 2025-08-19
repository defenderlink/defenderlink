# DefenderLink — Netlify Functions Backend

## Env vars (Netlify → Site settings → Environment)
- `VIRUSTOTAL_API_KEY` (required)
- `GOOGLE_SAFE_BROWSING_KEY` (recommended)

## Endpoints
- POST `/api/check-url` → `{ "url": "https://example.com" }`
- POST `/api/check-file` → raw bytes with `Content-Type: application/octet-stream`

## Notes
- OpenPhish/PhishTank used as public feeds; may be rate-limited.
- DNS/HEAD heuristics included; WHOIS only for report.
