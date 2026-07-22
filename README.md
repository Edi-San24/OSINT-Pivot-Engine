# OSINT Pivot Engine

> An AI agent that handles the pivot work so analysts can focus on what matters.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-green)
![Claude](https://img.shields.io/badge/Claude-Sonnet-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)

---

## The Problem

CTI analysts face a persistent bottleneck: even with automated collection and triage pipelines, pivoting across sources still happens manually — tab by tab, source by source, copy-paste by copy-paste. Under time pressure, that's where key insights get missed. A single indicator can touch VirusTotal, Shodan, PassiveDNS, certificate transparency logs, and dark web indexes — and manually chaining those lookups takes time an analyst during an active incident doesn't have. The OSINT Pivot Engine was built to handle that layer so the analyst can focus on judgment, not data collection.

---

## What It Does

- **Automated pivot chain** — drop a seed indicator and the agent automatically queries across open source intelligence sources, chaining from discovered IPs to domains to certificates without manual input
- **Dual confidence scoring** — generates a raw ML score based on feature patterns trained on real ThreatFox IOCs, plus a context-adjusted score that accounts for shared infrastructure like CDNs and Tor exit nodes where false positives are common
- **Analyst-ready output** — produces a structured investigation summary with threat assessment, visibility gaps, and recommended actions — written for a SOC analyst who needs to make a fast, informed decision

---

## How It Works

```
Seed Indicator
      ↓
Type Detection (IP / Domain / Hash / Email)
      ↓
LangGraph Agent
      ↓
Pivot Chain Executor → Connectors fire in parallel
      ↓
Discovered indicators added to queue → agent follows the chain
      ↓
ML Scoring + Context Layer
      ↓
Claude Sonnet generates investigation summary
      ↓
Rich terminal output + optional JSON export
```

---

## Connectors

| Source | Contribution |
|--------|-------------|
| VirusTotal | Malicious vote consensus, file reputation, domain/IP detections |
| Shodan | Open ports, banners, hosting ASN, exposed services |
| PassiveDNS (Mnemonic) | Historical DNS resolution records, IP-to-domain and domain-to-IP mapping |
| WHOIS | Registrar, registration date, expiration, nameservers |
| crt.sh | Certificate transparency logs, subdomain discovery |
| Ahmia (via Playwright) | Dark web index search for indicator mentions across .onion space |

---

## Project Status

Actively building. This project is under active development — not abandoned, just not done.

**Complete**
- LangGraph agent with stateful pivot loop
- Queue-based indicator chaining — agent follows discovered indicators automatically
- All six connectors wired and tested against live threat infrastructure
- Dual ML + context confidence scoring
- MLflow experiment tracking
- Rich CLI with color-coded risk levels, spinner, and JSON export
- Dark web connector via Playwright headless browser

**In Progress**
- MITRE ATT&CK connector — map findings to known threat actor TTPs
- STIX 2.1 export — package investigation output as shareable threat intelligence
- MalwareBazaar connector — hash triage and malware family classification
- WhoisXML connector — historical WHOIS and subdomain enrichment
- README and documentation

---

## Coming Soon

- MITRE ATT&CK threat actor and TTP mapping
- STIX 2.1 export for structured intelligence sharing
- MalwareBazaar hash connector
- WhoisXML historical enrichment
- Example investigation outputs
- Full setup guide

---

## Setup

> Full setup instructions coming soon. Project requires Python 3.10+, API keys for VirusTotal, Shodan, and Anthropic, and Playwright for the dark web connector.

---

*Built as part of an ongoing exploration into human-centered AI for threat intelligence. The agent handles the pivot work. The judgment stays with the analyst.*