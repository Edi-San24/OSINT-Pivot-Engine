# OSINT Pivot Engine

> An AI agent that handles the pivot work so analysts can focus on what matters.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-green)
![Claude](https://img.shields.io/badge/Claude-Sonnet-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)

---

## The Problem

CTI analysts face a persistent bottleneck: even with automated collection and triage pipelines, pivoting across sources still happens manually. Tab by tab, source by source, copy-paste by copy-paste. Under time pressure, that is where key insights get missed. A single indicator can touch VirusTotal, Shodan, PassiveDNS, certificate transparency logs, MITRE ATT&CK, and dark web indexes. Manually chaining those lookups takes time an analyst during an active incident does not have.

The OSINT Pivot Engine handles that layer so the analyst can focus on judgment, not data collection.

---

## What It Does

- **Automated pivot chaining:** drop a seed indicator and the agent queries across OSINT sources automatically, chaining from IPs to domains to certificates to related malware samples without manual input
- **Threat group profiling:** query by adversary name and surface full MITRE ATT&CK TTP mappings, aliases, and associated malware families
- **Dual confidence scoring:** raw ML score based on feature patterns trained on real ThreatFox IOCs, plus a context-adjusted score that accounts for shared infrastructure like CDNs and Tor exit nodes
- **Hash pivot chaining:** seed a file hash, get VT detections and MalwareBazaar metadata, then automatically chain into related samples via malware family tag clustering
- **STIX 2.1 export:** package any investigation as a structured STIX bundle importable by MISP, OpenCTI, Splunk, or any TAXII-compatible TIP
- **Analyst-ready output:** structured investigation summary with threat assessment, visibility gaps, and recommended actions written for a SOC analyst making a fast decision

---

## How It Works

```
Seed Indicator (IP / Domain / Hash / Threat Group)
      |
      v
Type Detection
      |
      v
LangGraph AI Agent (Claude Sonnet)
      |
      v
Pivot Chain Executor (connectors fire across all relevant sources)
      |
      v
Discovered indicators queued (agent follows the chain autonomously)
      |
      v
ML Scoring + Context Layer
      |
      v
Investigation Summary + optional STIX 2.1 export
```

---

## Connectors

| Source | Contribution |
|--------|-------------|
| VirusTotal | Malicious vote consensus, file reputation, malware family classification |
| Shodan | Open ports, banners, hosting ASN, exposed services |
| PassiveDNS (Mnemonic) | Historical DNS resolution records, IP-to-domain and domain-to-IP mapping |
| WHOIS | Registrar, registration date, expiration, nameservers |
| crt.sh | Certificate transparency logs, subdomain discovery |
| Ahmia | Dark web index search for indicator mentions across .onion space |
| MITRE ATT&CK | TTP mapping, threat group profiling, malware family attribution |
| MalwareBazaar | Hash triage, malware family classification, related sample clustering |

---

## Supported Indicator Types

| Type | Example |
|------|---------|
| IPv4 | `185.220.101.45` |
| Domain | `paypal-login-secure.com` |
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14d0` |
| SHA256 | `a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f` |
| Threat Group | `Lazarus Group` |

---

## Usage

```bash
# Basic investigation
python main.py --seed "185.220.101.45"

# Save full results to JSON
python main.py --seed "paypal-login-secure.com" --output results.json

# Export as STIX 2.1 bundle
python main.py --seed "db349b97c37d22f5ea1d1841e3c89eb4" --export-stix investigation.json

# Override pivot depth
python main.py --seed "suspicious-domain.com" --depth 5

# Threat group TTP profiling
python main.py --seed "Lazarus Group"
```

---

## Example Output

```
══════════════════════════════════════
OSINT PIVOT ENGINE
── Autonomous Threat Intelligence · v1.0
══════════════════════════════════════
Seed: db349b97c37d22f5ea1d1841e3c89eb4

   Pivots run       3
   Findings         13
   ML Score         0.9977  (raw feature pattern match)
   Context Score    0.9977  (adjusted for infrastructure type)
   Infrastructure   unknown
   Risk Level       HIGH

Investigation Summary:
Confirmed WannaCry ransomware (68/68 VT detections). Pivoting via
MalwareBazaar tag clustering surfaced 10 related samples captured
by honeypot sensors within the last 48 hours, confirming active
SMBv1 scanning in the wild. MITRE ATT&CK attributes to Lazarus
Group (HIDDEN COBRA / ZINC / Diamond Sleet) with 16 mapped
techniques including EternalBlue lateral movement (T1210) and
data encryption for impact (T1486).
```

---

## Setup

**Requirements**

- Python 3.10+
- Playwright (for dark web connector)
- API keys for: VirusTotal, Shodan, Censys, Anthropic, MalwareBazaar (abuse.ch)

**Install**

```bash
git clone https://github.com/Edi-San24/osint-pivot-engine
cd osint-pivot-engine
pip install -r requirements.txt
playwright install chromium
```

**Configure**

Copy `.env.example` to `.env` and fill in your API keys:

```
ANTHROPIC_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
CENSYS_API_KEY=
THREATFOX_API_KEY=
```

**Run**

```bash
python main.py --seed "your-indicator-here"
```

---

## Project Status

Active development. Core pipeline is complete and tested against live threat infrastructure.

**Complete**
- LangGraph agent with stateful pivot loop and autonomous queue management
- All eight connectors wired and tested
- Hash pivot chaining via MalwareBazaar tag clustering
- Threat group profiling via MITRE ATT&CK
- Dual ML + context confidence scoring
- MLflow experiment tracking
- STIX 2.1 export
- Rich CLI with color-coded risk levels and JSON export
- Dark web connector via Playwright headless browser

**Roadmap**
- Graph-based anomaly scoring via Node2Vec
- Temporal modeling for early-warning spike detection
- NER-based automatic threat actor extraction from pivot results
- URLhaus connector
- PyPI packaging
---


