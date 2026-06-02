# Splunk HEC Integration Guide

This guide shows how to connect CTI Hub to Splunk via HTTP Event Collector (HEC), enabling CTI scan results to appear alongside your SIEM data in Splunk dashboards.

---

## Architecture

```
CTI Hub (scan result)
        │
        ▼
  Splunk HEC (port 8088)
        │
        ▼
  Splunk Index: cti_hub
        │
        ▼
  Splunk Dashboard + Alerts
```

Every scan from CTI Hub creates a Splunk event with `sourcetype=cti_hub`, making it searchable and correlatable with your existing SIEM data.

---

## Step 1 — Enable HTTP Event Collector in Splunk

### Splunk Enterprise / Splunk Free:
1. Go to **Settings → Data Inputs → HTTP Event Collector**
2. Click **Global Settings**
3. Set **All Tokens** to **Enabled**
4. Default port: `8088`
5. Click **Save**

### Splunk Cloud:
- HEC is enabled by default
- Port is `443` with path `/services/collector/event`

---

## Step 2 — Create a CTI Hub HEC Token

1. Go to **Settings → Data Inputs → HTTP Event Collector**
2. Click **New Token**
3. Fill in:
   - **Name**: `CTI Hub`
   - **Source type**: `cti_hub` (create new)
   - **Index**: Create a new index called `cti_hub`
4. Click **Review** → **Submit**
5. **Copy the token** — you'll need it in CTI Hub

---

## Step 3 — Create the cti_hub Index

1. Go to **Settings → Indexes → New Index**
2. Index name: `cti_hub`
3. Data type: Events
4. Leave defaults → **Save**

---

## Step 4 — Configure CTI Hub

1. Open CTI Hub → **Admin** → **Splunk HEC**
2. Fill in:
   - **HEC URL**: `https://your-splunk:8088/services/collector/event`
   - **HEC Token**: paste the token from Step 2
   - **Index**: `cti_hub`
   - **Verify SSL**: off (unless you have proper certs)
   - **Enable**: toggle on
3. Click **Save**
4. Click **Test Connection** — should return success

---

## Step 5 — Verify Data is Arriving

In Splunk Search:
```splunk
index=cti_hub sourcetype=cti_hub
| head 10
```

You should see events like:
```json
{
  "@timestamp": "2026-05-16T20:00:00Z",
  "target": "185.220.101.45",
  "target_type": "ip",
  "verdict": "MALICIOUS",
  "threat_score": 0.84,
  "engines_total": 6,
  "engines_hit": 4,
  "analyst": "analyst01",
  "results": {
    "virustotal": "MALICIOUS",
    "abuseipdb": "MALICIOUS",
    "greynoise": "SUSPICIOUS"
  }
}
```

---

## Step 6 — Build Splunk Dashboard

### Create a new dashboard:
1. Go to **Dashboards → Create New Dashboard**
2. Name: `CTI Hub — Threat Intelligence`
3. Add these panels:

---

### Panel 1: Total Scans (Single Value)
```splunk
index=cti_hub sourcetype=cti_hub earliest=-30d
| stats count as "Total Scans"
```

---

### Panel 2: Verdict Distribution (Pie Chart)
```splunk
index=cti_hub sourcetype=cti_hub earliest=-30d
| stats count by verdict
| sort -count
```

---

### Panel 3: Threat Score Over Time (Line Chart)
```splunk
index=cti_hub sourcetype=cti_hub earliest=-7d
| timechart avg(threat_score) as "Avg Threat Score"
```

---

### Panel 4: Top Malicious Targets (Bar Chart)
```splunk
index=cti_hub sourcetype=cti_hub verdict=MALICIOUS earliest=-30d
| stats avg(threat_score) as score count by target
| sort -score
| head 10
```

---

### Panel 5: Scans by Analyst (Bar Chart)
```splunk
index=cti_hub sourcetype=cti_hub earliest=-30d
| stats count by analyst
| sort -count
```

---

### Panel 6: Recent Scan History (Table)
```splunk
index=cti_hub sourcetype=cti_hub earliest=-24h
| table _time target target_type verdict threat_score analyst
| sort -_time
```

---

### Panel 7: Engine Hit Rate (Bar Chart)
```splunk
index=cti_hub sourcetype=cti_hub earliest=-30d
| eval hit_rate = engines_hit / engines_total * 100
| stats avg(hit_rate) as "Avg Hit Rate %" by target_type
```

---

## Step 7 — Splunk Alerts

### Alert: High Threat Score Detected
```splunk
index=cti_hub sourcetype=cti_hub threat_score>=0.7
| table _time target target_type verdict threat_score analyst
```
- Schedule: Every 5 minutes
- Trigger: Number of results > 0
- Action: Send email / Slack webhook

### Alert: Multiple Engines Flagging Same Target
```splunk
index=cti_hub sourcetype=cti_hub engines_hit>=4
| stats count by target verdict
| where count >= 2
```

---

## Step 8 — Correlate with SIEM Logs

If you're also sending endpoint logs to Splunk via Elastic Agent or Splunk Universal Forwarder, you can correlate CTI results with SIEM events:

```splunk
| join type=left target
    [search index=cti_hub sourcetype=cti_hub verdict=MALICIOUS
     | stats max(threat_score) as cti_score by target
     | rename target as dest_ip]
index=main sourcetype=*
| where isnotnull(cti_score)
| table _time src_ip dest_ip action cti_score
```

This query joins network events where the destination IP was flagged as MALICIOUS in CTI Hub — showing exactly which endpoints connected to known-bad IPs.

---

## Splunk Universal Forwarder → CTI Hub

For a complete SOC pipeline:

```
Endpoints (Splunk UF)
        │
        ▼
Splunk Indexer ←──────────────────────────┐
        │                                  │
        ▼                                  │
Splunk SIEM (network events)               │
        │                                  │
        │ Analyst sees suspicious IP        │
        │                                  │
        ▼                                  │
    CTI Hub ──(scan result via HEC)────────┘
```

---

## Splunk Add-on (Optional)

For advanced integration, you can create a Splunk Technology Add-on (TA) that:
- Defines the `cti_hub` sourcetype with proper field extractions
- Adds CIM (Common Information Model) compliance
- Enables automatic field aliasing for correlation

Basic `props.conf` for `$SPLUNK_HOME/etc/apps/cti_hub/default/`:
```ini
[cti_hub]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "@timestamp"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
TRUNCATE = 10000

FIELDALIAS-target_ip = target AS dest_ip
FIELDALIAS-score     = threat_score AS risk_score
```

---

## Troubleshooting

**HEC returning 400 Bad Request:**
- Check token is correct
- Verify index `cti_hub` exists in Splunk

**Data not appearing in search:**
- Check index name matches exactly (case-sensitive)
- Try `index=* sourcetype=cti_hub` to find it

**SSL errors:**
- Set Verify SSL to off in CTI Hub admin
- Or add your Splunk certificate to the trusted store

**Test connection succeeds but no data:**
- Run a scan in CTI Hub — HEC only sends on actual scan results

---

*CTI Hub — https://github.com/VB-1405/CTI-Hub*
