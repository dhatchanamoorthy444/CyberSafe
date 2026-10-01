# CyberSafe — Architecture

## System Overview

CyberSafe is an **offline URL risk screening engine** built as a production-grade serverless application. It uses deterministic lexical analysis — no network calls — to detect structural indicators of phishing, deception, and malicious URL patterns.

## Component Architecture

```
┌──────────────────────────────────────────────────────┐
│  Browser (Client)                                     │
│  - index.html (SPA)                                  │
│  - style.css (design tokens)                         │
│  - app.js (analysis flow + QR scanner)               │
│  - lucide icons (CDN)                                │
│  - html5-qrcode (QR scanner CDN)                    │
└──────────────┬───────────────────────────────────────┘
               │ fetch('/api/analyze', {url})
               ▼
┌──────────────────────────────────────────────────────┐
│  Vercel Edge (Serverless Function)                  │
│  api/analyze.py (Python, @vercel/python)               │
│  • Request validation                                  │
│  • CORS headers                                        │
│  • Call analyze_url()                                  │
│  • Persist to Supabase (best-effort, non-blocking)     │
│  • Safe logging (hash only)                            │
└──────────────┬───────────────────────────────────────┘
               │ analyze_url()
               ▼
┌──────────────────────────────────────────────────────┐
│  Offline Security Engine (Python)                    │
│  analyzer/                                            │
│  • parser.py         — URL structure (urllib.parse)  │
│  • hostname.py        — host syntax & patterns         │
│  • schemes.py         — dangerous / unusual schemes    │
│  • patterns.py        — path/query deception patterns  │
│  • ip_detection.py    — raw / obfuscated IPs           │
│  • lookalike.py       — brand impersonation          │
│  • shortening.py      — URL shortener detection        │
│  • risk_engine.py     — score aggregation & verdict     │
│  • models.py          — Finding, AnalysisResult        │
└──────────────────────────────────────────────────────┘
```

## Data Flow

1. **Input**: User submits URL string via form
2. **Validation**: API validates JSON, checks URL length (<4096), trims
3. **Parsing**: `SafeURLParser.parse(url_string)` → `ParsedURL`
4. **Analysis**: `RiskEngine.analyze()` runs all detectors sequentially
5. **Aggregation**: Findings summed with weights; verdict computed via thresholds
6. **Persistence** (optional): SHA-256 hash stored in Supabase `scan_history`
7. **Response**: JSON with verdict, score, findings list, parsed data
8. **Rendering**: Frontend displays verdict banner, URL anatomy, findings

## Security Model

### Zero Network Guarantee
- All URL processing uses `urllib.parse` (lexical, no sockets)
- No `urllib.request`, `requests`, `httpx`, `subprocess`, `os.system`
- No `eval()`, `exec()`, or dynamic code execution
- No external threat-intelligence APIs

### Credential Protection
- Supabase service-role key loaded from `os.environ` (Vercel environment)
- Key never exposed to frontend (no `window.supabase` initialization)
- Telemetry uses SHA-256 of URL — never stores full suspicious URL
- Row Level Security (RLS) enforced: public users cannot read `scan_history`

### Determinism Guarantee
- No random number generation in verdict logic
- No time-based or external-state dependencies
- Configurable weights in `RiskEngine.WEIGHTS` are constant
- Same URL produces identical findings on every call

## Verdict Logic

```
SAFE_MAX = 19
REVIEW_MAX = 49
SUSPICIOUS ≥ 50

Verdict rules (ordered by priority):
1. DANGEROUS_SCHEME (high) → SUSPICIOUS
2. AT_SYMBOL_DECEPTION (high) → SUSPICIOUS
3. LOOKALIKE_HOSTNAME (high, score≥40) + CREDENTIAL_PATH → SUSPICIOUS
4. Score ≥ 50 → SUSPICIOUS
5. Score ≥ 20 → REVIEW
6. Score < 20 → SAFE
```

## Score Transparency

Every finding contributes its weight to a running total, capped at 100. Example breakdown:

```
DANGEROUS_SCHEME:     +70  (high severity)
AT_SYMBOL_DECEPTION:   +60  (high severity)
CREDENTIAL_PATH:       +15  (medium severity)
-------------------------------
Raw total: 145 → capped to 100 → SUSPICIOUS
```

Weights are fully transparent in `analyzer/risk_engine.py`.

## Frontend Design System

Uses CSS custom properties (design tokens) for full theming:
- `--bg`: Background
- `--bg-surface`: Card surfaces
- `--border`: Borders and separators
- `--accent-primary`: Primary buttons
- Verdict colors (`--safe-*`, `--review-*`, `--suspicious-*`)
- Font pairing (Inter + JetBrains Mono)

Responsive layout: single column on mobile (<600px), two-column on desktop (analyzer + sidebar).

## QR Scanner Workflow

- Uses `html5-qrcode` library (CDN, deferred load)
- Requests camera access (`facingMode: 'environment'` for rear camera)
- Scans QR → populates URL input → auto-submits form
- Fails gracefully (user can close scanner and use manual input)
- No external server interaction: all processing is local to the browser

## Deployment Architecture

### Vercel Configuration (`vercel.json`)
- `/api/analyze` → `api/analyze.py` (Python serverless)
- `/` and `/*` → `frontend/` (static assets)
- Environment variables read from Vercel Settings (not `.env` in production)

### Supabase Schema
- `scan_history`: URL hash, hostname, scheme, verdict, score, finding count
- `profiles`: Per-user data (linked to auth uid)
- `trusted_domains`: Admin allowlist
- `scan_events`: Lightweight analytics (no URL content)
- All tables: `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- All policies use `service_role` for inserts, `authenticated` for reads
