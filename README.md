# OSINT Pivot Engine

> Drop in one indicator. Get back a scored, cross-referenced threat assessment.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Version](https://img.shields.io/badge/Version-1.3.0-blue)
![Interface](https://img.shields.io/badge/Interface-TUI%20%2B%20CLI-brightgreen)
![Connectors](https://img.shields.io/badge/Connectors-14-blue)
![MCP](https://img.shields.io/badge/MCP-optional-purple)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

Pivoting across sources is still manual work — tab by tab, copy-paste by copy-paste — and under incident pressure that is where things get missed. One indicator can touch VirusTotal, Shodan, passive DNS, certificate transparency, ThreatFox, ATT&CK and dark web indexes. This chains those lookups so the analyst spends their time on judgement instead of collection.

Built for solo analysts, small SOCs without a TIP budget, students and researchers. If you already run Recorded Future or Anomali, you have this and more. If you don't, this closes the gap on free API tiers.

**Triage, not attribution.** It tells you where to look next. It does not tell you who did it.

---

## What It Does

- **Chains pivots automatically** — one seed fans out across 14 sources in parallel, then follows what it finds: IPs to domains, domains to certificates, hashes to related samples, URLs to the payloads they served
- **Profiles threat groups without dead-ending** — full ATT&CK technique mappings and aliases, chained into MalwareBazaar for samples circulating now. Living-off-the-land binaries are filtered out using MITRE's own classification, so pivots aren't wasted on `netsh`
- **Scores in layers** — an ML score per indicator type, blended with graph topology and campaign recency, then adjusted down for shared infrastructure like CDNs and Tor exits
- **Reports absence as absence** — an indicator no source has seen returns `UNKNOWN`, never `LOW`. A failed lookup is never silently scored as a clean result
- **Protects bystanders when publishing** — the STIX/OTX exporter drops indicators that would take innocent co-tenants with them, and records every exclusion in a local audit file
- **Stays deterministic** — findings are read directly from connector output, so two runs on the same data agree. The only model call is the closing summary

---

## How It Works

```
Seed (IP / Domain / URL / Hash / Email / Username / Threat Group / Malware Family)
   -> type detection
   -> pivot chain executor — 14 connectors in parallel
   -> deterministic findings extraction
   -> discovered indicators queued, loop until depth cap or queue empty
   -> ML + graph + temporal scoring, adjusted for infrastructure context
   -> analyst summary (single LLM call)
   -> terminal, JSON, or STIX 2.1
```

The pivot loop is plain Python. No model decides where to go next, which keeps runs reproducible and cheap: one API call per investigation regardless of depth.

---

## Connectors

| Source | Contribution |
|---|---|
| VirusTotal | Detection consensus, file reputation, family classification |
| ThreatFox | Current C2 listings, malware family, confidence, compromised-host flag |
| Shodan | Open ports, banners, hosting ASN, exposed services |
| Censys / crt.sh | Certificate transparency, subdomain discovery, geolocation, ASN |
| PassiveDNS (Mnemonic) | Historical resolution, IP-to-domain and domain-to-IP |
| Live DNS | Current A/MX/NS records and wildcard-zone detection |
| RDAP | Registration date and registrar, structured, no key required |
| WHOIS | Port-43 fallback for ccTLDs with no RDAP service |
| MalwareBazaar | Hash triage, family classification, sample clustering |
| URLhaus | Live malicious URLs, delivery infrastructure per family |
| AlienVault OTX | Community pulses, targeted countries, campaign context |
| MITRE ATT&CK | TTP mapping, group profiling, malware attribution |
| Ahmia | Dark web index search across .onion space |
| SpiderFoot | Email and username footprint (requires `--deep`) |

Licensed sources (DomainTools, DNSDB) are supported but not included. They enrich the written report only and never feed the scoring features, so the engine behaves identically without them.

**Indicator types:** IPv4, domain, URL, MD5/SHA1/SHA256, threat group, malware family, email, username.

---

## Setup

Python 3.10+. Free API tiers work for everything.

```bash
git clone https://github.com/Edi-San24/osint-pivot-engine
cd osint-pivot-engine
pip install -r requirements.txt
playwright install chromium
python main.py
```

Just start it. If `.env` is missing or a key is blank, a setup wizard walks you through the credentials, marks which are required, and writes `.env` for you.

Required: VirusTotal, abuse.ch (ThreatFox/MalwareBazaar), OTX. Optional: Anthropic (writes the summary), Shodan, Censys, SpiderFoot. Anything you skip means those lookups return nothing rather than breaking the run. The ATT&CK STIX bundle caches to `data/` on first run.

---

## Usage

Run with no arguments for the terminal UI — three panels, every option a toggle. Pass any flag for the non-interactive CLI.

```bash
python main.py --seed "185.220.101.45"                     # basic investigation
python main.py --seed "Lazarus Group"                      # group profiling, chained to live samples
python main.py --seed "http://host.tld:8080/path"          # URL seed, port and path preserved
python main.py --seed "example.com" --depth 5 -o out.json  # deeper, saved to JSON
python main.py --seed "analyst@example.com" --deep         # SpiderFoot for email/username
python main.py --seed "185.220.101.45" --verbose           # show how the score was derived
```

TUI keys: `Enter` run · `ctrl+p` pick a discovered indicator to pivot into · `ctrl+l` clear · `Escape` quit.

**Publishing.** Build an OTX pulse or STIX bundle from a saved investigation:

```bash
python -m core.stix_exporter investigation.json \
  --title "..." --description @desc.txt --tags "a,b" --attack-ids "T1071.001" -o pulse.json
```

This writes `pulse.json` to upload and `pulse.audit.json` to keep. The audit records what was excluded and why — usually co-tenants who would be caught by a block. Indicators named only in the description are flagged, because OTX extracts those too.

---

## Scoring, and What It Can't Do

Infrastructure indicators are scored by a gradient-boosting model; threat groups, malware families, hashes and identities are scored from evidence directly (ATT&CK coverage, sample volume, detection counts).

The domain model reads **infrastructure shape** — registration age, nameserver count, MX presence, wildcard zones, DNS record count. It deliberately excludes the VirusTotal columns, which are three views of one number and alone score AUC 0.96: a model leaning on them cannot say anything VirusTotal hasn't already said, and inherits its blind spots.

**5-fold ROC-AUC 0.878 ± 0.037** on 383 labelled domains. `confidence_score` **ranks, it does not calibrate** — `0.67` is not "67% likely malicious". Rather than dress it up, each domain score carries `band_precision`: what its band was measured to mean out-of-fold across eight resampled splits.

| band | measured malicious rate | read it as |
|---|---|---|
| HIGH `≥ 0.7` | **89%** ± 0.8 | trustworthy; act on it |
| MEDIUM `0.4–0.7` | **43%** ± 5.9 | a coin flip; needs a human |
| LOW `< 0.4` | **20%** ± 1.0 | **not an all-clear** |

**LOW is the one to read carefully.** One in five indicators scored LOW is malicious, and no threshold repairs it — even below `0.10` the rate is still 16%. This model can say something looks like attacker infrastructure; it cannot clear anything. Post-hoc calibration was tried and rejected: Platt scaling made expected calibration error *worse* (0.057 → 0.079) and isotonic bought 0.007 at the cost of AUC. At 383 rows both fit noise, so reporting the measured rate is the honest option.

Rates are conditional on a near 50/50 training distribution, so treat them as the model's discrimination, not a population probability.

Two known blind spots, both pinned in the test suite:

- **Compromised legitimate sites are missed.** Their infrastructure is genuinely benign; the maliciousness is in served content, which no feature observes.
- **Bulk hosting is over-flagged**, for the mirror-image reason — attackers rent bulk hosting.

---

## Optional: Org Profile

By default the engine tells you what an indicator is. An org profile also tells you whether it matters to you.

```bash
cp org_profile.example.yaml org_profile.yaml
```

`netblocks` catches an investigated IP that is one of your own hosts · `asns` your own hosting · `domains` lookalikes impersonating you · `sectors` and `countries` reporting that names you as a target · `mitigated_techniques` ATT&CK coverage gaps. All optional.

`OWN ASSET` is the one to watch for — it means something you were investigating as an external threat is your own infrastructure, which is a different situation entirely.

The file is gitignored, and the engine only reports matches it can prove. A stale netblock list gets you silence, never a wrong all-clear.

---

## Optional: MCP Server

For Claude Code and Claude Desktop. `.mcp.json` is included and uses relative paths, so it works from the repo root without editing.

| Tool | Purpose |
|---|---|
| `investigate` | Full pivot chain — scores, findings, summary |
| `detect_indicator_type` | Classify an indicator, no network calls |
| `get_raw_pivot_data` | Drill into one connector's raw output from a cached run |
| `export_stix` | Write a STIX 2.1 bundle |

Raw payloads are cached rather than returned, so drilling into detail never re-spends quota.

---

## Development

```bash
pip install -r requirements-dev.txt
python tests/test_domain_model.py          # regression suite
```

The domain training set ships in `data/training_data_domains_v2.csv` — 383 labelled domains, provenance and limitations in `data/README.md`. Models are **not** committed: a `.joblib` is a pickle, and loading one from a pull request is arbitrary code execution. Train your own, which reproduces the shipped predictions byte-for-byte:

```bash
python core/trainer.py --dataset domain --data data/training_data_domains_v2.csv \
    --tag v2c --exclude harmless_votes,malicious_ratio,malicious_votes,urlhaus_listed
```

Collection is `scripts/collect_training_data.py` (`--dry-run` writes the benign sample for review before spending an hour of quota). Experiment tracking runs through MLflow.

---

## Status

Active development. Core pipeline complete and tested against live threat infrastructure.

**Done** — TUI with setup wizard and click-to-pivot · stateful pivot loop with dedup · 14 connectors · deterministic findings · group profiling with MITRE-classified chaining · layered ML/graph/temporal/context scoring · per-type scoring paths · early-warning detection · bystander-safe STIX/OTX export · MCP server · regression suite.

**Next** — name the malicious rows in the published dataset so both classes are auditable · broaden group chaining beyond top-ranked tooling · calibrate `confidence_score` · certificate enumeration that survives crt.sh outages.
