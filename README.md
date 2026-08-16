# OSINT Pivot Engine

> Drop in one indicator. Get back a scored, cross-referenced threat assessment.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![CLI](https://img.shields.io/badge/Interface-CLI-brightgreen)
![Connectors](https://img.shields.io/badge/Connectors-11-blue)
![MCP](https://img.shields.io/badge/MCP-optional-purple)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)

---

## The Problem

Even with automated collection and triage in place, pivoting across sources is still manual. Tab by tab, source by source, copy-paste by copy-paste. Under incident pressure that is where things get missed.

A single indicator can touch VirusTotal, Shodan, passive DNS, certificate transparency, MITRE ATT&CK, and dark web indexes. Chaining those lookups by hand costs time an analyst does not have.

This handles that layer, so the analyst spends their time on judgment instead of data collection.

---

## Who It's For

Solo analysts, small SOCs without a commercial TIP budget, students, CTF players, and researchers. If you already have Recorded Future or Anomali, you have this and more. If you don't, this closes a real gap using free and low-cost API tiers.

---

## What It Does

- **Automated pivot chaining** — one seed indicator fans out across eleven sources in parallel, then follows what it finds: IPs to domains, domains to certificates, hashes to related samples, all without input
- **Threat group profiling that doesn't dead-end** — query an adversary by name for full ATT&CK technique mappings, aliases, and tooling, then watch it chain that group's malware into MalwareBazaar to surface samples circulating right now. Living-off-the-land binaries are filtered out using MITRE's own software classification, so pivots aren't wasted on `netsh` and `ipconfig`
- **Layered confidence scoring** — an ML score from features trained on real ThreatFox IOCs, blended with a graph score from relationship topology and a temporal score for campaign recency, then adjusted down for shared infrastructure like CDNs and Tor exits
- **Early warning** — flags when related samples anywhere in the pivot chain were captured within the last seven days, which usually means an active campaign rather than a historical artifact
- **Deterministic findings** — every finding is read directly from connector output, so two runs on the same data produce the same findings. The only model call in an investigation is the closing summary
- **STIX 2.1 export** — hand any investigation to MISP, OpenCTI, Splunk, or any TAXII-compatible platform

---

## How It Works

```
Seed Indicator (IP / Domain / Hash / Email / Username / Threat Group / Malware Family)
      |
      v
Type Detection
      |
      v
Pivot Chain Executor  --  eleven connectors fire in parallel
      |
      v
Deterministic Findings Extraction
      |
      v
Discovered indicators queued  --  loop until depth cap or queue empty
      |
      v
ML + Graph + Temporal Scoring, adjusted for infrastructure context
      |
      v
Analyst summary (single LLM call)
      |
      v
Terminal output, JSON, or STIX 2.1 bundle
```

The pivot loop itself is plain Python — no model decides where to go next. That keeps runs reproducible, fast, and cheap: one API call per investigation regardless of depth.

---

## Connectors

| Source | Contribution |
|--------|-------------|
| VirusTotal | Detection consensus, file reputation, malware family classification |
| Shodan | Open ports, banners, hosting ASN, exposed services |
| Censys | Certificate transparency, subdomain discovery, geolocation, ASN |
| PassiveDNS (Mnemonic) | Historical DNS resolution, IP-to-domain and domain-to-IP mapping |
| WHOIS | Registrar, registration date, expiration, nameservers |
| MalwareBazaar | Hash triage, family classification, related sample clustering |
| URLhaus | Live malicious URLs, delivery infrastructure per malware family |
| AlienVault OTX | Community pulse intelligence, targeted countries, campaign context |
| MITRE ATT&CK | TTP mapping, threat group profiling, malware attribution |
| Ahmia | Dark web index search across .onion space |
| SpiderFoot | Email and username footprint enrichment (requires `--deep`) |

---

## Supported Indicator Types

| Type | Example |
|------|---------|
| IPv4 | `185.220.101.45` |
| Domain | `paypal-login-secure.com` |
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14d04` |
| SHA256 | `a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f` |
| Threat Group | `Lazarus Group` |
| Malware Family | `WannaCry` |
| Email | `analyst@example.com` |
| Username | `threat_actor_handle` |

---

## Setup

**Requirements**

- Python 3.10+
- API keys for Anthropic, VirusTotal, Shodan, Censys, abuse.ch, and AlienVault OTX. Free tiers work for all of them

**Install**

```bash
git clone https://github.com/Edi-San24/osint-pivot-engine
cd osint-pivot-engine
pip install -r requirements.txt
playwright install chromium
```

**Configure**

```bash
cp .env.example .env
```

Then fill in your keys. The MITRE ATT&CK STIX bundle downloads and caches to `data/` automatically on first run.

**Run**

```bash
python main.py --seed "your-indicator-here"
```

---

## Usage

```bash
# Basic investigation
python main.py --seed "185.220.101.45"

# Threat group profiling, chained into live samples
python main.py --seed "Lazarus Group"

# Save full results to JSON
python main.py --seed "paypal-login-secure.com" --output results.json

# Export a STIX 2.1 bundle
python main.py --seed "db349b97c37d22f5ea1d1841e3c89eb4" --export-stix investigation.json

# Override pivot depth (default 3)
python main.py --seed "suspicious-domain.com" --depth 5

# Enable SpiderFoot for email and username seeds
python main.py --seed "analyst@example.com" --deep
```

---

## Example Output

```
══════════════════════════════════════
OSINT PIVOT ENGINE
── Autonomous Threat Intelligence · v1.2.0
══════════════════════════════════════
Seed: Lazarus Group

   Pivots run       3
   Findings         22
   ML Score         0.9556
   Context Score    0.9556
   Risk Level       HIGH

Investigation Summary:
THREAT LEVEL: HIGH — Confirmed Lazarus Group (DPRK state-sponsored)
tooling with two fully-detected malicious samples tied to MagicRAT
and WannaCry.

The seed maps to MITRE ATT&CK group G0032 (aliases HIDDEN COBRA,
ZINC, Labyrinth Chollima, Diamond Sleet) with 119 mapped techniques
and 28 associated software entries. Both pivoted hashes are
unambiguously malicious: the MagicRAT sample (41/41 VT detections)
is exclusively attributed to Lazarus and appears in 25 OTX pulses,
while the WannaCry sample (50/50 VT detections) is one of 10 recent
dionaea-tagged samples showing the family remains actively collected
in the wild.
```

---

## Optional: MCP Server

The CLI above is the primary interface and needs nothing beyond Python and API keys. If you happen to use Claude Code or Claude Desktop, the engine also runs as an MCP server so you can drive it conversationally. This is a convenience layer, not a requirement.

`.mcp.json` is included — point the paths at your checkout and reconnect your client.

| Tool | Purpose |
|------|---------|
| `investigate` | Full pivot chain, returns scores, findings, and summary |
| `detect_indicator_type` | Classify an indicator with no network calls |
| `get_raw_pivot_data` | Drill into one connector's raw output from a cached run |
| `export_stix` | Write a STIX 2.1 bundle for a completed investigation |

Raw connector payloads are cached rather than returned, so drilling into detail never re-spends rate-limited quota.

---

## Development

To retrain the scoring models:

```bash
pip install -r requirements-dev.txt
python -m core.trainer
```

Training data collection lives in `scripts/collect_training_data.py`. Experiment tracking runs through MLflow.

---

## Project Status

Active development. The core pipeline is complete and tested against live threat infrastructure.

**Complete**

- Stateful pivot loop with autonomous queue management and deduplication
- Eleven connectors wired and tested
- Deterministic findings extraction across all sources
- Threat group profiling with MITRE-classified malware chaining
- Hash pivot chaining via malware family tag clustering
- Layered ML, graph, temporal, and context scoring, calibrated against measured distributions
- Early warning detection across the full pivot chain
- MCP server for Claude Code and Claude Desktop
- STIX 2.1 export and JSON output
- MLflow experiment tracking

**Roadmap**

- Broaden threat group chaining beyond top-ranked tooling
- Retrain scoring models on an expanded labelled set
- Test suite
