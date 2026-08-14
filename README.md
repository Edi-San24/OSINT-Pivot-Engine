# OSINT Pivot Engine

> An AI agent that handles the pivot work so analysts can focus on what matters.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-1.2+-green)
![Claude](https://img.shields.io/badge/Claude-Fable%205-orange)
![MCP](https://img.shields.io/badge/MCP-Server-purple)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)

---

## The Problem

CTI analysts face a persistent bottleneck: even with automated collection and triage pipelines, pivoting across sources still happens manually. Tab by tab, source by source, copy-paste by copy-paste. Under time pressure, that is where key insights get missed. A single indicator can touch VirusTotal, Shodan, PassiveDNS, certificate transparency logs, MITRE ATT&CK, and dark web indexes. Manually chaining those lookups takes time an analyst during an active incident does not have.

The OSINT Pivot Engine handles that layer so the analyst can focus on judgment, not data collection.

---

## What It Does

- **Automated pivot chaining:** drop a seed indicator and the agent queries eleven OSINT sources in parallel, then chains from IPs to domains to certificates to related malware samples without manual input
- **Threat group profiling with live chaining:** query by adversary name and get full MITRE ATT&CK TTP mappings, aliases and tooling — then the engine chains that group's malware into MalwareBazaar to surface samples circulating right now, filtering out living-off-the-land binaries so pivots are not wasted on `netsh` and `ipconfig`
- **Layered confidence scoring:** an ML score from features trained on real ThreatFox IOCs, blended with a graph score from relationship topology and a temporal score for campaign recency, then adjusted for shared infrastructure like CDNs and Tor exit nodes
- **Hash pivot chaining:** seed a file hash, get VT detections and MalwareBazaar metadata, then chain into related samples via malware family tag clustering
- **Deterministic findings:** every finding is derived directly from connector output, so results are reproducible and the only model call in an investigation is the final analyst summary
- **MCP server:** drive the whole engine from Claude Code or Claude Desktop conversationally, instead of the CLI
- **STIX 2.1 export:** package any investigation as a structured bundle importable by MISP, OpenCTI, Splunk, or any TAXII-compatible TIP

---

## How It Works

```
Seed Indicator (IP / Domain / Hash / Email / Username / Threat Group / Malware Family)
      |
      v
Type Detection
      |
      v
Pivot Chain Executor  ──  eleven connectors fire in parallel
      |
      v
Deterministic Findings Extraction
      |
      v
Discovered indicators queued  ──  loop until depth cap or queue empty
      |
      v
ML + Graph + Temporal Scoring, adjusted by infrastructure context
      |
      v
Claude (Fable 5) writes the analyst summary
      |
      v
Terminal output, JSON, or STIX 2.1 bundle
```

The pivot loop is deterministic. The model is used once per investigation, for the summary, which keeps runs reproducible and cheap.

---

## Connectors

| Source | Contribution |
|--------|-------------|
| VirusTotal | Malicious vote consensus, file reputation, malware family classification |
| Shodan | Open ports, banners, hosting ASN, exposed services |
| Censys | Certificate transparency, subdomain discovery, geolocation, ASN |
| PassiveDNS (Mnemonic) | Historical DNS resolution, IP-to-domain and domain-to-IP mapping |
| WHOIS | Registrar, registration date, expiration, nameservers |
| MalwareBazaar | Hash triage, malware family classification, related sample clustering |
| URLhaus | Live malicious URLs, delivery infrastructure per malware family |
| AlienVault OTX | Community pulse intelligence, targeted countries, campaign context |
| MITRE ATT&CK | TTP mapping, threat group profiling, malware family attribution |
| Ahmia | Dark web index search for indicator mentions across .onion space |
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

## Usage

### CLI

```bash
# Basic investigation
python main.py --seed "185.220.101.45"

# Threat group profiling, chained into live samples
python main.py --seed "Lazarus Group"

# Save full results to JSON
python main.py --seed "paypal-login-secure.com" --output results.json

# Export as STIX 2.1 bundle
python main.py --seed "db349b97c37d22f5ea1d1841e3c89eb4" --export-stix investigation.json

# Override pivot depth
python main.py --seed "suspicious-domain.com" --depth 5

# Enable SpiderFoot for email and username seeds
python main.py --seed "analyst@example.com" --deep
```

### MCP Server

The engine also runs as an MCP server, so you can drive it conversationally from Claude Code or Claude Desktop. `.mcp.json` is included; point the paths at your checkout and reconnect your client.

| Tool | Purpose |
|------|---------|
| `investigate` | Full pivot chain, returns scores, findings and summary |
| `detect_indicator_type` | Classify an indicator with no network calls |
| `get_raw_pivot_data` | Drill into one connector's raw output from a cached run |
| `export_stix` | Write a STIX 2.1 bundle for a completed investigation |

Raw connector payloads are omitted from `investigate` and cached instead, so drilling into detail never re-spends rate-limited API quota.

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

## Setup

**Requirements**

- Python 3.10+
- API keys for: Anthropic, VirusTotal, Shodan, Censys, abuse.ch, AlienVault OTX

**Install**

```bash
git clone https://github.com/Edi-San24/osint-pivot-engine
cd osint-pivot-engine
pip install -r requirements.txt
playwright install chromium
```

To retrain the scoring models, also install the training extras:

```bash
pip install -r requirements-dev.txt
```

**Configure**

Copy `.env.example` to `.env` and fill in your keys:

```
ANTHROPIC_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
CENSYS_API_KEY=
THREATFOX_API_KEY=
OTX_API_KEY=
WHOISXML_API_KEY=
```

The MITRE ATT&CK STIX bundle downloads and caches to `data/` on first run.

**Run**

```bash
python main.py --seed "your-indicator-here"
```

---

## Project Status

Active development. Core pipeline is complete and tested against live threat infrastructure.

**Complete**

- LangGraph agent with stateful pivot loop and autonomous queue management
- Eleven connectors wired and tested
- Deterministic findings extraction across all sources
- Threat group profiling with MITRE-classified malware chaining
- Hash pivot chaining via MalwareBazaar tag clustering
- Layered ML, graph, temporal and context confidence scoring, calibrated against the real ATT&CK group distribution
- MCP server for Claude Code and Claude Desktop
- MLflow experiment tracking
- STIX 2.1 export
- Rich CLI with color-coded risk levels and JSON export
- Dark web connector via Playwright headless browser

**Roadmap**

- PyPI packaging
- Broaden threat group chaining beyond the top-ranked tooling
- Retrain scoring models on an expanded labelled set
- Test suite
