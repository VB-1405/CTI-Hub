# Logstash Pipeline Integration Guide

This guide explains how to build a Logstash pipeline that feeds data into CTI Hub's Elasticsearch index, enabling correlation between your SIEM logs and CTI scan results in Kibana.

---

## Architecture

```
Elastic Agent (endpoints)
        │
        ▼
    Logstash
        │
        ├──→ Elasticsearch (logs-* indices)     ← your normal SIEM logs
        │
        └──→ Elasticsearch (cti-scans index)    ← CTI Hub results
                    │
                    ▼
              Kibana Dashboard
              (correlate logs + CTI results)
```

---

## Prerequisites

- Elasticsearch running (local or remote)
- Logstash installed
- CTI Hub running with Elasticsearch shipping enabled
- Elastic Agent installed on endpoints (optional but recommended)

---

## Step 1 — Install Logstash

### On Raspberry Pi / Debian / Ubuntu:
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install logstash -y
```

### Verify:
```bash
sudo /usr/share/logstash/bin/logstash --version
```

---

## Step 2 — Create the CTI Hub Pipeline

Create the pipeline config file:
```bash
sudo nano /etc/logstash/conf.d/cti-hub.conf
```

Paste this configuration:

```
# ─────────────────────────────────────────────────────────────
# CTI Hub — Logstash Pipeline
# Receives logs from Elastic Agents and ships to Elasticsearch
# ─────────────────────────────────────────────────────────────

input {
  # Receive logs from Elastic Agents via Beats protocol
  beats {
    port => 5044
    ssl  => false
  }

  # Optional: receive syslog from network devices
  # syslog {
  #   port => 5140
  #   type => "syslog"
  # }
}

filter {
  # ── Enrich with GeoIP data ──────────────────────────────────
  if [source][ip] {
    geoip {
      source => "[source][ip]"
      target => "[source][geo]"
    }
  }

  if [destination][ip] {
    geoip {
      source => "[destination][ip]"
      target => "[destination][geo]"
    }
  }

  # ── Tag suspicious events for CTI correlation ───────────────
  if [event][category] == "network" and [network][direction] == "egress" {
    mutate {
      add_tag => ["outbound-connection", "cti-candidate"]
    }
  }

  if [event][category] == "file" and [event][action] == "creation" {
    mutate {
      add_tag => ["file-creation", "cti-candidate"]
    }
  }

  # ── Parse DNS queries for domain reputation check ───────────
  if [dns][question][name] {
    mutate {
      add_field => { "cti_check_domain" => "%{[dns][question][name]}" }
      add_tag   => ["dns-query", "cti-candidate"]
    }
  }

  # ── Timestamp normalization ──────────────────────────────────
  date {
    match => ["@timestamp", "ISO8601"]
    target => "@timestamp"
  }
}

output {
  # ── Primary: ship all logs to main SIEM index ───────────────
  elasticsearch {
    hosts    => ["https://localhost:9200"]
    user     => "elastic"
    password => "YOUR_ELASTIC_PASSWORD"
    ssl_certificate_verification => false
    index    => "logs-%{+YYYY.MM.dd}"
  }

  # ── Secondary: ship CTI candidates to separate index ────────
  # These are events that should be investigated via CTI Hub
  if "cti-candidate" in [tags] {
    elasticsearch {
      hosts    => ["https://localhost:9200"]
      user     => "elastic"
      password => "YOUR_ELASTIC_PASSWORD"
      ssl_certificate_verification => false
      index    => "cti-candidates-%{+YYYY.MM.dd}"
      document_type => "_doc"
    }
  }

  # ── Debug: print to stdout during testing ───────────────────
  # Remove this in production
  # stdout { codec => rubydebug }
}
```

Replace `YOUR_ELASTIC_PASSWORD` with your actual password.

---

## Step 3 — Configure Logstash Pipelines

Edit the pipelines config:
```bash
sudo nano /etc/logstash/pipelines.yml
```

Add:
```yaml
- pipeline.id: cti-hub
  path.config: "/etc/logstash/conf.d/cti-hub.conf"
  pipeline.workers: 2
```

---

## Step 4 — Start Logstash

```bash
sudo systemctl enable logstash
sudo systemctl start logstash
sudo systemctl status logstash
```

Check logs:
```bash
sudo journalctl -u logstash -f
```

---

## Step 5 — Configure Elastic Agent to send to Logstash

On each endpoint running Elastic Agent, update the Fleet output to point to Logstash:

1. Go to Kibana → Fleet → Settings → Outputs
2. Click **Add output**
3. Type: **Logstash**
4. Hosts: `your-siem-server:5044`
5. Save and apply to your agent policy

Or if using standalone agent, edit `/etc/elastic-agent/elastic-agent.yml`:
```yaml
outputs:
  default:
    type: logstash
    hosts: ["your-siem-server:5044"]
```

---

## Step 6 — Enable CTI Hub Elasticsearch Shipping

In CTI Hub Admin Panel → Elasticsearch:

| Field | Value |
|---|---|
| URL | `https://your-elasticsearch:9200` |
| Username | `elastic` |
| Password | your password |
| Index | `cti-scans` |
| Verify SSL | off (unless you have proper certs) |
| Enable | ✓ |

Every scan will now create a document in the `cti-scans` index.

---

## Step 7 — Build the Kibana Correlation Dashboard

### Create data views in Kibana:

1. Stack Management → Data Views → Create data view
   - Name: `SIEM Logs` | Pattern: `logs-*`
2. Stack Management → Data Views → Create data view
   - Name: `CTI Scans` | Pattern: `cti-scans*`
3. Stack Management → Data Views → Create data view
   - Name: `CTI Candidates` | Pattern: `cti-candidates-*`

### Recommended dashboard panels:

**Panel 1 — CTI Verdict Distribution**
- Type: Donut
- Data view: CTI Scans
- Slice by: `verdict.keyword`

**Panel 2 — Threat Score Over Time**
- Type: Line
- Data view: CTI Scans
- X: `@timestamp`, Y: Average of `threat_score`

**Panel 3 — SIEM Events Over Time**
- Type: Bar
- Data view: SIEM Logs
- X: `@timestamp`, breakdown by `event.category`

**Panel 4 — MITRE ATT&CK Techniques**
- Type: Table
- Data view: CTI Scans
- Filter: `techniques.name: T1*`
- Rows: `techniques.name`, `techniques.severity`

**Panel 5 — Top Malicious Targets**
- Type: Horizontal bar
- Data view: CTI Scans
- Filter: `verdict: MALICIOUS`
- Y: `target.keyword` (Top 10), X: Average `threat_score`

**Panel 6 — Scan History**
- Type: Table
- Data view: CTI Scans
- Columns: `@timestamp`, `target`, `target_type`, `verdict`, `threat_score`, `analyst`

---

## Step 8 — Correlate SIEM Alerts with CTI Results

Use KQL in Kibana Discover to correlate:

```kql
# Find all network connections to IPs flagged as MALICIOUS in CTI Hub
destination.ip: (185.220.101.45 OR 194.165.16.11)

# Find file events for hashes detected by CTI Hub
file.hash.sha256: "ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9"

# Find all high-severity alerts from the last 24 hours
event.severity >= 70 and @timestamp > now-24h
```

---

## Logstash → CTI Hub Workflow

When Logstash tags an event as `cti-candidate`:

1. Analyst sees the event in Kibana Discover
2. Copies the IP/hash/domain from the event
3. Pastes into CTI Hub
4. CTI Hub queries all 9 engines in parallel
5. Result is shipped back to `cti-scans` index
6. Kibana dashboard updates automatically

This creates a complete **detect → investigate → document** workflow.

---

## Troubleshooting

**Logstash won't start:**
```bash
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/cti-hub.conf
```

**Elastic Agent not connecting to Logstash:**
```bash
# Check port is open
sudo ss -tlnp | grep 5044

# Check firewall
sudo ufw allow 5044
```

**CTI scans not appearing in Kibana:**
```bash
# Verify documents exist
curl -k -u elastic:PASSWORD "https://localhost:9200/cti-scans/_count"
```

**Logstash authentication failing:**
- Verify credentials in `cti-hub.conf`
- Check Elasticsearch is running: `sudo systemctl status elasticsearch`

---

## Security Recommendations

- Use TLS for Logstash beats input in production
- Store Elasticsearch credentials in Logstash keystore:
  ```bash
  sudo /usr/share/logstash/bin/logstash-keystore create
  sudo /usr/share/logstash/bin/logstash-keystore add ES_PASSWORD
  ```
  Then use `${ES_PASSWORD}` in your config instead of plaintext
- Restrict Logstash port 5044 to trusted hosts only via firewall
- Use a dedicated Elasticsearch user with minimum required permissions for Logstash

---

*CTI Hub — https://github.com/VB-1405/CTI-Hub*
