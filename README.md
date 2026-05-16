# CTI Hub — Multi-Engine Cyber Threat Intelligence Platform

A self-hosted, open-source threat intelligence aggregator that queries multiple CTI engines in parallel and correlates results into a unified verdict. Designed to integrate with any SIEM tool.

<img width="1440" height="859" alt="Screenshot 2026-05-16 at 1 55 13 PM" src="https://github.com/user-attachments/assets/47425085-7062-4378-98d5-8edfb6c95b9a" />


---

## Features

- **Multi-engine scanning** — Hash, IP, URL, and domain analysis across 9+ CTI engines simultaneously
- **Dynamic engine management** — Add, remove, and configure any CTI engine through the admin UI
- **CAPA integration** — Static binary analysis with MITRE ATT&CK mapping (optional)
- **Authentication** — JWT-based login with admin and analyst roles
- **SIEM integration** — Ships results to Elasticsearch for Kibana dashboards
- **Docker-ready** — One command to deploy anywhere
- **Plug-and-play** — Works standalone or alongside any existing SIEM

---

## Supported CTI Engines (default)

| Engine | Types | Free Tier |
|---|---|---|
| VirusTotal | Hash, IP, URL, Domain | 4 req/min |
| AbuseIPDB | IP | 1,000 req/day |
| Shodan | IP | 100 credits/month |
| OTX AlienVault | Hash, IP, URL, Domain | Unlimited |
| URLScan.io | URL, Domain | 100 scans/day |
| GreyNoise | IP | 100 IPs/day |
| MalwareBazaar | Hash | Free |
| ThreatFox | Hash, IP, URL, Domain | Free |
| Hybrid Analysis | Hash | 200 req/day (vetting required) |
| **CAPA** | File | Free (self-hosted) |

> You can add any additional CTI engine through the Admin panel — no code changes needed.

---

## Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/VB-1405/CTI-Hub
cd cti-hub

# 2. Start
docker compose up -d

# 3. Open http://localhost:5000/setup
#    Create your admin account

# 4. Go to Admin → API Engines
#    Add your API keys
```

That's it. The dashboard is at `http://localhost:5000`.

---

## Quick Start (without Docker)

```bash
# 1. Clone
git clone https://github.com/VB-1405/CTI-Hub
cd cti-hub

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python backend.py

# 4. Open http://localhost:5000/setup
```

---

## Architecture

```
Browser
  └── Login page (/login)
  └── Dashboard (/) — requires auth
  └── Admin panel (/admin) — admin only

Flask Backend (backend.py)
  ├── JWT Authentication
  ├── Dynamic engine management (config.json)
  ├── CTI API calls (server-side, keys never in browser)
  ├── CAPA subprocess (optional)
  └── Elasticsearch shipping (optional)

Data files (gitignored)
  ├── config.json  — engine config + API keys
  ├── users.json   — hashed user passwords
  └── .jwt_secret  — JWT signing key
```

---

## CAPA Setup

CAPA performs static malware analysis and maps capabilities to MITRE ATT&CK.

```bash
# Linux ARM64 (Raspberry Pi)
wget https://github.com/mandiant/capa/releases/latest/download/capa-linux-arm64
chmod +x capa-linux-arm64 && sudo mv capi-linux-arm64 /usr/local/bin/capa

# Linux x86_64
wget https://github.com/mandiant/capa/releases/latest/download/capa-linux
chmod +x capa-linux && sudo mv capa-linux /usr/local/bin/capa

# Verify
capa --version
```

Then in CTI Hub Admin → CAPA → set binary path → enable → test.

---

## Elasticsearch / SIEM Integration

CTI Hub can ship every scan result to Elasticsearch automatically:

1. Admin → Elasticsearch → enable and configure connection
2. Every scan creates a document in the `cti-scans` index
3. Build Kibana dashboards on top of the `cti-scans` data view

### Document schema

```json
{
  "@timestamp": "2026-05-07T10:00:00Z",
  "target": "185.220.101.45",
  "target_type": "ip",
  "verdict": "MALICIOUS",
  "threat_score": 0.84,
  "engines_total": 6,
  "engines_hit": 4,
  "analyst": "analyst01",
  "results": {
    "virustotal": "MALICIOUS",
    "abuseipdb": "MALICIOUS"
  },
  "techniques": [
    { "name": "T1027.005: Obfuscated Files", "severity": "high" }
  ]
}
```

---

## Adding Custom CTI Engines

No code needed. From Admin → API Engines → Add Engine:

| Field | Description |
|---|---|
| Engine ID | Unique identifier (e.g. `my_engine`) |
| Display Name | Shown in the UI |
| API Key | Stored server-side |
| Supports | Hash / IP / URL / Domain |

The engine will appear in scans automatically.

> For engines requiring custom request/response logic, add a handler in `backend.py` following the existing pattern.

---

## User Roles

| Role | Access |
|---|---|
| **Admin** | Full access — API keys, user management, all settings |
| **Analyst** | Scan only — no access to keys or admin panel |

---

## Nginx Reverse Proxy

See `nginx-example.conf` for a production-ready Nginx configuration that:
- Serves CTI Hub at `/cti/`
- Works with both local and Tailscale IPs
- Allows large file uploads for CAPA analysis

---

## Security Notes

- API keys are stored in `config.json` on the server — never sent to the browser
- `config.json` and `users.json` are in `.gitignore` — never committed
- Passwords are hashed with bcrypt
- Sessions expire after 8 hours (configurable)
- All scan endpoints require authentication

---

## Project Structure

```
cti-hub/
├── backend.py          # Flask backend — all logic
├── requirements.txt    # Python dependencies
├── Dockerfile          # Container definition
├── docker-compose.yml  # One-command deployment
├── nginx-example.conf  # Nginx reverse proxy config
├── .gitignore          # Protects secrets from git
├── static/
│   ├── index.html      # Main dashboard
│   ├── login.html      # Login page
│   ├── admin.html      # Admin panel
│   └── setup.html      # First-run setup
└── README.md
```

---

## Built With

- **Flask** — Python web framework
- **PyJWT** — JWT authentication
- **bcrypt** — Password hashing
- **Gunicorn** — Production WSGI server
- **Docker** — Containerization

CTI engines: VirusTotal, AbuseIPDB, Shodan, OTX AlienVault, URLScan.io, GreyNoise, MalwareBazaar, ThreatFox, Hybrid Analysis, CAPA (Mandiant)

---

## License

MIT License — free to use, modify, and distribute.

---

## Contributing

Pull requests welcome. To add a new built-in CTI engine:

1. Add engine definition to `DEFAULT_CONFIG['engines']` in `backend.py`
2. Add a `_enginename(k, value)` function following the existing pattern
3. Add a case in `run_builtin_engine()`
4. Submit a PR

---

*Built as part of a Smart SIEM graduate research project.*
