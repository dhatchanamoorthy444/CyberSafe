# CyberSafe — Offline URL & QR Risk Screening Engine

<div align="center">

**See the destination. Understand the risk. Stay safe.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Vercel](https://img.shields.io/badge/Deploy-Vercel-black)](https://vercel.com)

*Deterministic, explainable URL risk screening with zero network activity. Built for hackathons and enterprise deployment.*

[Demo](#demo) • [Architecture](#architecture) • [Installation](#installation) • [Security Model](#security-model) • [Deployment](#deployment)

</div>

---

## 🎯 Problem

**85% of phishing attacks use deceptive URLs**, exploiting:
- Lookalike domains (`paypa1.com`, `g00gle.com`)
- Visual deception (@ symbol tricks: `google.com@evil.example`)
- URL shorteners hiding malicious destinations
- Dangerous schemes (`javascript:`, `data:`)
- QR codes embedding phishing links

**Existing solutions are inadequate:**
- ❌ Blacklist services: Zero-day threats bypass them
- ❌ Sandboxed browsing: Slow, resource-intensive, fails on gated content
- ❌ Manual inspection: Error-prone, requires expertise

## ✅ Solution

**CyberSafe** is an offline, deterministic URL risk screening engine that analyzes URL *structure* without visiting destinations.

### Key Features

✅ **Offline Analysis** — Zero network requests, no DNS lookups, no fetching  
✅ **Explainable** — Every verdict includes transparent rule breakdowns  
✅ **Deterministic** — Same URL → Same verdict every time  
✅ **QR Support** — Scan and analyze QR codes before opening  
✅ **Privacy-First** — Telemetry uses SHA-256 hashes, never raw URLs  
✅ **Production-Ready** — Vercel serverless + Supabase backend  

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CYBERSAFE SYSTEM                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐      ┌──────────────┐     ┌────────────┐ │
│  │   Frontend   │─────▶│ Vercel API   │────▶│  Supabase  │ │
│  │  (SPA HTML)  │◀─────│ /api/analyze │◀────│    (RLS)   │ │
│  └──────────────┘      └──────────────┘     └────────────┘ │
│         │                      │                             │
│    [QR Scanner]          [Offline Engine]              [Telemetry]
│    html5-qrcode          analyzer/*.py               SHA-256 Hash
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Frontend** | Vanilla HTML/CSS/JS | Premium dark UI, QR scanner, demo modes |
| **API** | Vercel Python Serverless | Request validation, analysis orchestration |
| **Engine** | Python 3.9+ | Offline risk detection (parser, hostname, patterns) |
| **Database** | Supabase PostgreSQL | Privacy-preserving telemetry (RLS enabled) |
| **Deployment** | Vercel | Serverless edge functions, global CDN |

---

## 🔒 Security Model

### What CyberSafe Detects

1. **Visual Phishing** — Lookalike domains with character substitution
2. **Deceptive Tricks** — @ symbol abuse, percent-encoding obfuscation
3. **Dangerous Schemes** — `javascript:`, `vbscript:`, `data:`, `file:`
4. **Credential Harvesting** — `/login` paths on lookalike domains
5. **QR Phishing** — Analyzes target URL without executing

### Security Guarantees

✅ **Never visits URLs** — Pure lexical and structural analysis  
✅ **Never makes network requests** — No HTTP, DNS, or socket calls  
✅ **Never executes content** — No `eval()`, `exec()`, subprocess  
✅ **Never exposes secrets** — Service-role keys server-side only  
✅ **Deterministic verdicts** — No randomness, no external API dependency  

**Audit Result**: Searched entire codebase for `fetch`, `requests`, `urllib.request`, `httpx`, `subprocess`, `eval`, `exec` — only safe imports found (`urllib.parse` for parsing, no network calls).

### Threat Model

**Protects Against**:
- Lookalike domain phishing
- @ symbol deception
- Dangerous URL schemes
- QR code phishing
- Obfuscated IPs

**Does NOT Protect Against**:
- Content-based malware (page source)
- Compromised legitimate domains
- Zero-day browser exploits
- Social engineering (convincing you to visit)

**Recommendation**: CyberSafe screens for structural indicators. A SAFE verdict does not guarantee destination trustworthiness.

See [SECURITY.md](SECURITY.md) for full security audit.

---

## 🔧 Detection Rules

| Rule ID | Severity | Weight | Example |
|---------|----------|--------|---------|
| `DANGEROUS_SCHEME` | HIGH | 70 | `javascript:alert(1)` |
| `AT_SYMBOL_DECEPTION` | HIGH | 60 | `google.com@evil.example` |
| `LOOKALIKE_HOSTNAME` | HIGH | 50 | `paypa1.com` (1 instead of l) |
| `IP_ADDRESS_HOST` | MEDIUM | 25 | `http://192.168.1.1` |
| `SHORTENED_URL` | MEDIUM | 20 | `bit.ly/abc123` |
| `CREDENTIAL_PATH` | MEDIUM | 15 | `/login`, `/verify`, `/auth` |
| `EXCESSIVE_ENCODING` | LOW | 10 | `%2F%2F%2F` (obfuscation) |
| `UNUSUAL_PORT` | LOW | 10 | `:8080`, `:8443` |
| `HTTP_UNENCRYPTED` | LOW | 5 | `http://` instead of `https://` |

### Verdict Thresholds

```
SAFE:        0-19 points
REVIEW:     20-49 points
SUSPICIOUS: 50-100 points
```

---

## 📦 Installation

### Prerequisites

- Python 3.9+
- Node.js 18+ (for Vercel CLI)
- Supabase account (free tier)
- Vercel account (free tier)

### Local Development

```bash
# 1. Clone repository
git clone https://github.com/yourusername/cybersafe.git
cd cybersafe

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set up environment variables
cp .env.example .env
# Edit .env with your Supabase credentials

# 4. Run tests
python -m unittest discover -s tests -p "test_*.py"

# 5. Test API locally (requires Vercel CLI)
vercel dev
```

### Supabase Setup

1. Create a new Supabase project at [supabase.com](https://supabase.com)
2. Run the schema migration:
   - Open Supabase SQL Editor
   - Copy contents of `supabase/schema.sql`
   - Execute the SQL
3. Copy credentials to `.env`:
   - `SUPABASE_URL`: Project URL (Settings → API)
   - `SUPABASE_SERVICE_ROLE_KEY`: Service role key (Settings → API → service_role)

---

## 🚀 Deployment

### Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/yourusername/cybersafe)

**Manual Deployment:**

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. Login to Vercel
vercel login

# 3. Deploy
vercel --prod

# 4. Set environment variables in Vercel Dashboard
# Settings → Environment Variables:
# - SUPABASE_URL
# - SUPABASE_SERVICE_ROLE_KEY
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_URL` | Supabase project URL | ✅ Yes |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key (server-side only) | ✅ Yes |
| `CORS_ALLOWED_ORIGIN` | Override CORS origin (optional) | ❌ No |

**Security Note**: Never expose `SUPABASE_SERVICE_ROLE_KEY` in frontend code. It bypasses Row Level Security.

---

## 🎮 Demo

### Try These Examples

| URL | Expected Verdict | Why |
|-----|------------------|-----|
| `https://www.google.com` | SAFE | Legitimate domain, no indicators |
| `http://192.168.1.10/login` | REVIEW | IP address + credential path |
| `https://google.com@evil.example` | SUSPICIOUS | Deceptive @ pattern |
| `https://paypa1.example/verify` | SUSPICIOUS | Lookalike + credential path |
| `javascript:alert(1)` | SUSPICIOUS | Dangerous scheme |

### Demo Mode

Click "Try a Demo" buttons on the frontend to populate pre-configured test URLs.

---

## 📊 API Reference

### POST `/api/analyze`

**Request:**
```json
{
  "url": "https://google.com@evil.example/login"
}
```

**Response:**
```json
{
  "success": true,
  "analysis": {
    "verdict": "SUSPICIOUS",
    "score": 65,
    "confidence": "high",
    "input_url": "https://google.com@evil.example/login",
    "actual_hostname": "evil.example",
    "parsed": {
      "scheme": "https",
      "hostname": "evil.example",
      "has_userinfo": true,
      "username": "google.com"
    },
    "findings": [
      {
        "rule_id": "AT_SYMBOL_DECEPTION",
        "severity": "high",
        "score": 60,
        "title": "Deceptive @ pattern",
        "message": "The URL contains user-information before the '@' symbol...",
        "evidence": "google.com@evil.example"
      }
    ],
    "recommendation": "Do not open this URL until the destination is independently verified."
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "error": {
    "code": "EMPTY_URL",
    "message": "The url field must not be empty."
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `MISSING_URL` | 400 | JSON body missing `url` field |
| `EMPTY_URL` | 400 | URL field is empty or whitespace |
| `INVALID_URL` | 400 | URL field is not a string |
| `URL_TOO_LONG` | 400 | URL exceeds 4096 characters |
| `INVALID_JSON` | 400 | Request body is not valid JSON |
| `PAYLOAD_TOO_LARGE` | 413 | Request body exceeds 64KB |
| `ANALYSIS_ERROR` | 500 | Internal analysis engine error |

---

## 🧪 Testing

### Run All Tests

```bash
# Unit tests (security engine)
python -m unittest discover -s tests -p "test_*.py" -v

# API tests (Vercel handler)
python tests/test_api.py -v
```

### Test Coverage

✅ SAFE URLs (google.com, github.com, example.com)  
✅ REVIEW URLs (IP addresses, shorteners, unusual ports)  
✅ SUSPICIOUS URLs (deceptive @, lookalikes, dangerous schemes)  
✅ Malformed URLs (empty, invalid schemes, oversized)  
✅ API validation (missing/empty/non-string URL fields)  
✅ Adversarial cases (unicode, punycode, obfuscation)  

See [TESTING.md](TESTING.md) for comprehensive test documentation.

---

## 📂 Project Structure

```
cybersafe/
├── analyzer/               # Offline security engine
│   ├── __init__.py        # Main analyze_url() entry point
│   ├── parser.py          # Safe URL parser (no network calls)
│   ├── hostname.py        # Hostname structure analysis
│   ├── lookalike.py       # Brand impersonation detector
│   ├── patterns.py        # Path/query pattern analysis
│   ├── schemes.py         # Dangerous scheme detection
│   ├── ip_detection.py    # IP address detection
│   ├── shortening.py      # URL shortener detection
│   ├── risk_engine.py     # Aggregation & scoring logic
│   └── models.py          # Data models (Finding, AnalysisResult)
├── api/
│   └── analyze.py         # Vercel serverless handler
├── frontend/
│   ├── index.html         # Single-page application
│   ├── style.css          # Premium dark theme
│   └── app.js             # Application logic + QR scanner
├── supabase/
│   └── schema.sql         # Database schema + RLS policies
├── tests/
│   ├── test_urls.py       # Engine unit tests
│   └── test_api.py        # API integration tests
├── vercel.json            # Vercel deployment config
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template
├── README.md              # This file
├── SECURITY.md            # Security audit & threat model
├── ARCHITECTURE.md        # System architecture details
└── TESTING.md             # Testing documentation
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`python -m unittest discover -s tests`)
4. Commit with clear messages
5. Push to your branch
6. Open a Pull Request

### Coding Standards

- Python: PEP 8, type hints where applicable
- JavaScript: ES6+, no jQuery
- CSS: CSS custom properties (tokens), mobile-first
- Documentation: Clear docstrings, inline comments for complex logic

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Vercel](https://vercel.com) for serverless Python runtime
- [Supabase](https://supabase.com) for PostgreSQL + RLS
- [html5-qrcode](https://github.com/mebjas/html5-qrcode) for QR scanning
- [Lucide](https://lucide.dev) for icons
- Security research from OWASP, PhishTank, and URLhaus

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/cybersafe/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cybersafe/discussions)
- **Security**: Report vulnerabilities to security@example.com

---

## 🎯 Roadmap

- [ ] Browser extension (Chrome, Firefox)
- [ ] Slack integration (`/cybersafe <url>`)
- [ ] API rate limiting
- [ ] Custom trusted domain allowlists
- [ ] Machine learning scoring (optional module)
- [ ] Email header analysis
- [ ] Internationalization (i18n)

---

<div align="center">

**Built with ❤️ for safer internet navigation**

[⭐ Star on GitHub](https://github.com/yourusername/cybersafe) • [📖 Documentation](https://github.com/yourusername/cybersafe/wiki)

</div>
#   C y b e r S a f e  
 