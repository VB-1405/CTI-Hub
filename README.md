# CTI Hub — Multi-Engine Cyber Threat Intelligence Platform

A self-hosted, open-source threat intelligence aggregator that queries multiple CTI engines in parallel and correlates results into a unified verdict. Designed to integrate with any SIEM tool — Elastic Stack, Splunk, or MISP.

<img width="1440" height="680" alt="Screenshot 2026-06-02 at 4 01 01 PM" src="https://github.com/user-attachments/assets/57b70771-3e50-43ae-9186-c9c124440cc0" />

---

## Features

- **Multi-engine scanning** — Hash, IP, URL, and domain analysis across 9+ CTI engines simultaneously
- **Dynamic engine management** — Add, remove, and configure any CTI engine through the admin UI — no code changes needed
- **Scan History** — SQLite-backed case management with search, filters, and analyst notes
- **Authentication** — JWT-based login with Admin and Analyst roles
- **CAPA integration** — Static binary analysis with MITRE ATT&CK mapping (optional)
- **Elasticsearch / Kibana** — Ships results to ELK for dashboard correlation
- **Splunk HEC** — Ships results to Splunk via HTTP Event Collector
- **MISP integration** — Self-hosted threat intelligence, fully offline-capable
- **Webhook Alerts** — Slack, Discord, or Teams alerts when threat score exceeds threshold
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
| MISP | Hash, IP, URL, Domain | Free (self-hosted) |
| **CAPA** | File | Free (self-hosted) |

> Add any additional CTI engine through the Admin panel — no code changes needed.

---

## Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/VB-1405/CTI-Hub.git
cd CTI-Hub

# 2. Start
docker compose up -d

# 3. Open http://localhost:5000/setup
#    Create your admin account

# 4. Go to Admin → API Engines
#    Add your API keys
```

The dashboard is at `http://localhost:5000`.

---

## Quick Start (without Docker)

```bash
# 1. Clone
git clone https://github.com/VB-1405/CTI-Hub.git
cd CTI-Hub

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python3 backend.py

# 4. Open http://localhost:5000/setup
```

---

## Architecture

```
Browser
  ├── /setup      — First-run admin account creation
  ├── /login      — Authentication
  ├── /           — Main dashboard (requires auth)
  ├── /history    — Scan history & case management
  └── /admin      — Admin panel (admin only)

Flask Backend (backend.py)
  ├── JWT Authentication (bcrypt passwords, 8hr sessions)
  ├── Dynamic engine management (config.json)
  ├── CTI API calls (server-side, keys never in browser)
  ├── SQLite scan history (scans.db)
  ├── CAPA subprocess (optional)
  ├── Elasticsearch shipping (optional)
  ├── Splunk HEC shipping (optional)
  ├── MISP queries (optional)
  └── Webhook alerts (optional)

Data files (gitignored — never committed)
  ├── config.json  — engine config + API keys
  ├── users.json   — bcrypt hashed passwords
  ├── scans.db     — SQLite scan history
  └── .jwt_secret  — JWT signing key
```

---

## User Roles

| Role | Access |
|---|---|
| **Admin** | Full access — API keys, user management, SIEM config, all settings |
| **Analyst** | Scan + history only — no access to keys or admin panel |

---

## Scan History

Every scan is automatically saved to a local SQLite database. Access at `/history`:

- Search by target, IP, hash, or URL
- Filter by verdict (Malicious / Suspicious / Clean)
- Click any row to see full engine results and CAPA techniques
- Add analyst investigation notes per scan
- Stats bar showing totals and average threat score

---

## CAPA Setup

CAPA performs static malware analysis and maps capabilities to MITRE ATT&CK.

```bash
# Linux ARM64 (Raspberry Pi)
wget https://github.com/mandiant/capa/releases/latest/download/capa-linux-arm64
chmod +x capa-linux-arm64 && sudo mv capa-linux-arm64 /usr/local/bin/capa

# Linux x86_64
wget https://github.com/mandiant/capa/releases/latest/download/capa-linux
chmod +x capa-linux && sudo mv capa-linux /usr/local/bin/capa

# Verify
capa --version
```

Then: Admin → CAPA → set binary path → enable → test.

---

## Elasticsearch / Kibana Integration

CTI Hub ships every scan result to Elasticsearch automatically:

1. Admin → Elasticsearch → enable and configure connection
2. Every scan creates a document in the `cti-scans` index
3. Build Kibana dashboards on the `cti-scans` data view

See [docs/LOGSTASH_PIPELINE.md](docs/LOGSTASH_PIPELINE.md) for a full Logstash pipeline guide including endpoint correlation.

**Document schema:**
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

## Splunk Integration

CTI Hub ships scan results to Splunk via HTTP Event Collector (HEC).

1. In Splunk: Settings → Data Inputs → HTTP Event Collector → create token
2. Admin → Splunk HEC → configure HEC URL, token, and index
3. Every scan creates a Splunk event with `sourcetype=cti_hub`
4. Test connection directly from the admin panel

See [docs/SPLUNK_PIPELINE.md](docs/SPLUNK_PIPELINE.md) for full Splunk dashboard queries and alert setup.

**Example Splunk search:**
```splunk
index=cti_hub sourcetype=cti_hub verdict=MALICIOUS
| table _time target target_type threat_score analyst
| sort -_time
```

---

## MISP Integration

Connect to a self-hosted MISP instance for fully offline threat intelligence — no external API calls needed.

1. Admin → MISP → configure your MISP URL and API key
2. MISP appears as an engine in the scanner alongside external services
3. Queries MISP attributes for any hash, IP, URL, or domain

**Quick MISP Docker install:**
```bash
git clone https://github.com/MISP/misp-docker
cd misp-docker && cp template.env .env
docker compose up -d
# Get API key: MISP → Administration → List Auth Keys
```

---

## Webhook Alerts

Fire Slack, Discord, or Microsoft Teams alerts automatically when a scan exceeds your threat threshold.

1. Admin → Webhooks → configure webhook URL and platform
2. Set threshold (e.g. `0.7` = alert when threat score ≥ 70%)
3. Alerts fire in the background — never blocks scan results
4. Test button to verify webhook is working

Supports: Slack, Discord, Microsoft Teams, Generic JSON.

---

## Adding Custom CTI Engines

No code needed. Admin → API Engines → Add Engine:

| Field | Description |
|---|---|
| Engine ID | Unique identifier (e.g. `my_engine`) |
| Display Name | Shown in the UI |
| API Key | Stored server-side, never in browser |
| Supports | Hash / IP / URL / Domain |

The engine appears in scans automatically. For engines requiring custom request/response parsing, add a handler in `backend.py` following the existing pattern and submit a PR.

---

## Nginx Reverse Proxy

See `nginx-example.conf` for a production-ready configuration that:
- Serves CTI Hub at `/cti/`
- Works with both local and Tailscale/VPN IPs
- Allows large file uploads for CAPA analysis (35MB limit)
- Supports long timeout for CAPA on low-power hardware (Raspberry Pi)

---

## Security Notes

- API keys stored in `config.json` server-side — never sent to the browser
- `config.json`, `users.json`, `scans.db`, `.jwt_secret` are in `.gitignore` — never committed
- Passwords hashed with bcrypt
- JWT sessions expire after 8 hours (configurable)
- All scan and history endpoints require authentication

---

## Project Structure

```
CTI-Hub/
├── backend.py              # Flask backend — all logic
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container definition
├── docker-compose.yml      # One-command deployment
├── nginx-example.conf      # Nginx reverse proxy config
├── .gitignore              # Protects secrets from git
├── static/
│   ├── index.html          # Main dashboard
│   ├── login.html          # Login page
│   ├── admin.html          # Admin panel
│   ├── setup.html          # First-run setup
│   └── history.html        # Scan history & case management
├── docs/
│   ├── LOGSTASH_PIPELINE.md  # ELK/Logstash integration guide
│   └── SPLUNK_PIPELINE.md    # Splunk HEC integration guide
└── README.md
```

---

## Built With

- **Flask** — Python web framework
- **PyJWT** — JWT authentication
- **bcrypt** — Password hashing
- **SQLite** — Local scan history
- **Gunicorn** — Production WSGI server
- **Docker** — Containerization

CTI Engines: VirusTotal · AbuseIPDB · Shodan · OTX AlienVault · URLScan.io · GreyNoise · MalwareBazaar · ThreatFox · Hybrid Analysis · MISP · CAPA (Mandiant)

---

## Roadmap

- [ ] MFA with Google Authenticator / Authy (TOTP)
- [ ] SIEM connectors — Splunk TA, Microsoft Sentinel playbook
- [ ] Custom engine templates (webhook-based, no-code)
- [ ] Case management — link multiple scans into an investigation
- [ ] API rate limit monitoring per engine

---

## Contributing

Pull requests welcome. To add a new built-in CTI engine:

1. Add engine definition to `DEFAULT_CONFIG['engines']` in `backend.py`
2. Add a `_enginename(k, value)` function following the existing pattern
3. Add a case in `run_builtin_engine()`
4. Submit a PR

---

## License

MIT License — free to use, modify, and distribute.
