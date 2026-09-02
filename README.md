# OSINT Pivot Engine

> Drop in one indicator. Get back a scored, cross-referenced threat assessment.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Version](https://img.shields.io/badge/Version-1.3.0-blue)
![Interface](https://img.shields.io/badge/Interface-TUI%20%2B%20CLI-brightgreen)
![Connectors](https://img.shields.io/badge/Connectors-14-blue)
![MCP](https://img.shields.io/badge/MCP-optional-purple)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

You get a suspicious IP address. Checking it properly means VirusTotal, then Shodan, then passive DNS, then certificate records, then ThreatFox, then whatever those turn up next. Twenty browser tabs later you have lost the thread, and during an actual incident that is where things get missed.

This does the tab-opening for you. Give it one indicator, get back everything those sources know, what it found by following the trail, and a written assessment.

Built for people without a commercial threat intel platform: solo analysts, small security teams, students, researchers. If you already have Recorded Future or Anomali, you have this and more. If you don't, this covers a lot of the same ground using free API tiers.

**It helps you triage, not attribute.** It will tell you an indicator looks dangerous and where to look next. It will not tell you which group is behind it, and you should not use it as though it does.

---

## What It Does

- **Follows the trail on its own.** One indicator goes out to 14 sources at once, then chases whatever comes back: an IP to the domains hosted on it, a domain to its certificates, a file hash to related samples, a URL to the malware it delivered
- **Looks up threat groups by name.** Search "Lazarus Group" and get their known techniques and aliases from MITRE ATT&CK, plus samples of their malware currently circulating. It skips ordinary Windows tools like `netsh` that attackers borrow, so you don't waste lookups on them
- **Scores what it finds**, using a model suited to the indicator type, adjusted for how things connect to each other and how recently they were seen. Shared infrastructure like CDNs and Tor exits gets marked down, since plenty of innocent traffic lives there
- **Says "I don't know" when it doesn't.** If no source has ever seen an indicator, you get `UNKNOWN`, not `LOW`. A lookup that failed is never quietly reported as a clean result
- **Won't get bystanders blocked.** When you export findings to share, it holds back addresses that host innocent sites alongside the bad one, and writes down what it held back and why
- **Doesn't invent anything.** The findings are copied out of what each source actually returned, not generated, so the tool adds no guesswork of its own. Run the same indicator next week and the numbers may differ, but that is because the sources changed, not because the tool changed its mind. Only the closing summary is AI-written

---

## How It Works

```
   you type one indicator
   (IP, domain, URL, file hash, email, username, threat group, malware family)
            |
   it works out what kind of thing that is
            |
   asks all 14 sources at once
            |
   pulls the facts out of what came back
            |
   spots new indicators in those answers, and goes round again
   (until it hits the depth limit or runs out of leads)
            |
   scores everything it collected
            |
   writes the assessment
            |
   prints it, or saves it as JSON or STIX 2.1
```

Nothing in that loop is AI-driven. Ordinary code decides which lookup to run next, so investigations are repeatable and cost the same whether you go two hops deep or five. The only AI call is the summary at the end.

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

Just run it. The first time, a setup wizard asks for your API keys one at a time, tells you what each is for and whether you actually need it, and saves them for you.

You need VirusTotal, abuse.ch (covers ThreatFox and MalwareBazaar) and OTX. Optional: Anthropic to write the summaries, plus Shodan, Censys and SpiderFoot. Skipping an optional one just means those lookups come back empty; nothing breaks.

---

## Usage

Run it with no arguments and you get a full-screen terminal app, where every option is a toggle and you can click past investigations to reload them. Add any flag and you get the plain command-line version instead, which is what you want for scripting.

```bash
python main.py --seed "185.220.101.45"                     # basic investigation
python main.py --seed "Lazarus Group"                      # group profiling, chained to live samples
python main.py --seed "http://host.tld:8080/path"          # URL seed, port and path preserved
python main.py --seed "example.com" --depth 5 -o out.json  # deeper, saved to JSON
python main.py --seed "analyst@example.com" --deep         # SpiderFoot for email/username
python main.py --seed "185.220.101.45" --verbose           # show how the score was derived
```

In the terminal app: `Enter` runs it, `ctrl+p` lists every indicator the investigation turned up so you can jump straight into one, `ctrl+l` clears the screen, `Escape` quits.

**Sharing what you found.** Turn a saved investigation into an OTX pulse or a STIX bundle:

```bash
python -m core.stix_exporter investigation.json \
  --title "..." --description @desc.txt --tags "a,b" --attack-ids "T1071.001" -o pulse.json
```

You get two files. Upload `pulse.json`; keep `pulse.audit.json` for yourself. The audit file lists what was left out and why, which is usually innocent sites sharing an address with the malicious one. It also warns you if your write-up mentions an indicator you chose not to publish, because OTX scrapes those out of the description too.

---

## How to Read the Score

Every investigation ends with a score and a HIGH / MEDIUM / LOW label. Here is what those actually mean, measured rather than asserted.

**Domains** are scored by a model, and each band has a measured meaning:

| label | domains | what to do |
|---|---|---|
| **HIGH** | 89% were malicious | Act on it. |
| **MEDIUM** | 43% | The tool is unsure. Look yourself. |
| **LOW** | 20% | Nothing alarming found. **Not the same as safe.** |

Read that as "out of every 100 domains this tool called HIGH, 89 really were malicious."

**Addresses, hashes, threat groups and malware families** are scored from evidence instead, not by a model. The score tells you how much corroboration exists and from where, and the output names which sources answered. A source with nothing to report leaves the score alone rather than voting the indicator innocent.

**LOW does not mean clean.** One in five domains it scores LOW turns out to be malicious. The tool is good at spotting infrastructure that looks like an attacker built it, and bad at proving something is fine. So a LOW result means "nothing here stood out", not "this is safe to ignore." The CLI and TUI print that warning on every LOW result rather than leaving you to guess.

**MEDIUM means the tool is confused**, not that risk is moderate. Something landing in MEDIUM is no more likely to be malicious than an indicator picked at random. Treat it as "no useful opinion" and use your own judgement.

**There is no model for IP addresses, on purpose.** There was one, and it was retired after it turned out to be measuring the wrong thing entirely. See the technical detail below if you want the post-mortem.

### Two things it reliably gets wrong

**A hacked legitimate website slips past.** If someone breaks into a real company's site and serves malware from it, the site itself still looks completely normal: registered years ago, real mail server, stable DNS. The tool reads that shape and says it is fine. It never looks at what the page is actually serving.

**Bulk hosting gets over-flagged.** Cheap shared hosting looks like attacker infrastructure because attackers use cheap shared hosting. A legitimate hosting provider can come back MEDIUM.

Both are pinned in the test suite so a future change cannot quietly make them worse.

<details>
<summary>The technical detail, if you want it</summary>

Domains go through a gradient-boosting model. Everything else is scored directly from evidence: ATT&CK coverage for threat groups, sample volume for malware families, detection counts and catalogue presence for hashes, and feed corroboration for addresses.

Evidence scores combine by noisy-OR rather than by averaging, so each source can only raise confidence. Averaging was tried and it penalised silence: URLhaus answering "not found" about a command-and-control address dragged a confidence-100 ThreatFox listing down to MEDIUM, even though URLhaus tracks malware URLs and has no reason to know about a C2.

The domain model reads registration age, nameserver count, MX presence, wildcard zones and DNS record count. It deliberately excludes the VirusTotal columns. Those are three views of one number, and on their own they score AUC 0.96, so a model leaning on them just repeats what VirusTotal already told you and inherits its blind spots too.

5-fold ROC-AUC is 0.878 ± 0.037 on 383 labelled domains. The band percentages above are out-of-fold across eight resampled 5-fold splits.

`confidence_score` ranks, it does not calibrate: 0.67 is not "67% likely malicious". Proper calibration was attempted and abandoned. Platt scaling made the calibration error worse, isotonic gained almost nothing and cost accuracy, and at 383 rows both were fitting noise. Publishing the measured band rate is more honest than a transformed number that looks more precise than the data supports.

**Why the IP model was retired.** Its benign class was built by resolving domains to addresses, so every benign row was a mature multi-service host with names pointing at it, while every malicious row was a minimal single-purpose box pulled from a feed. Any feature correlating with "established host" then separated the two classes: `dns_record_count` scored AUC 0.139 and `total_open_ports` 0.299, both below the 0.5 of a useless feature and therefore inverted. It had learned to tell a busy server from a quiet one.

Rebuilding the benign class from ordinary business hosting fixed the balance and the inversion but introduced a 98% dependence on VirusTotal, and produced a live false negative: a confirmed Aisuru C2 scored 0.168 benign because eight domains pointed at it. Matched sampling against URLhaus payload hosts did not help either, since those are compromised routers rather than hosting businesses, so the pairing never matched.

Adding features would not have rescued it. Provider identity was the one candidate that escaped the confound, and it reduces to geography, since malicious skewed to Chinese cloud providers, so an ASN feature would flag legitimate businesses by where they happen to be hosted.

</details>

---

## Optional: Org Profile

By default the tool tells you whether an indicator is dangerous. Fill in a profile of your own organisation and it will also tell you whether it is dangerous *to you*.

```bash
cp org_profile.example.yaml org_profile.yaml
```

Fill in whichever you know, skip the rest:

| Field | Catches |
|---|---|
| `netblocks` | An IP you are investigating that turns out to be one of your own machines |
| `asns` | Infrastructure sitting in your own hosting |
| `domains` | Lookalike domains built to impersonate yours |
| `sectors`, `countries` | Reporting that names your industry or country as a target |
| `mitigated_techniques` | Attack techniques you have no defence against yet |

Watch for `OWN ASSET`. It means the thing you were investigating as an outside threat is actually your own machine, which is a very different problem and usually an urgent one.

The file is gitignored, since it describes your internal network. The tool only reports matches it can prove, so if your netblock list goes out of date you get silence rather than a false all-clear.

---

## Optional: MCP Server

For Claude Code and Claude Desktop. `.mcp.json` is included and uses relative paths, so it works from the repo root without editing.

| Tool | Purpose |
|---|---|
| `investigate` | Full pivot chain: scores, findings, summary |
| `detect_indicator_type` | Classify an indicator, no network calls |
| `get_raw_pivot_data` | Drill into one connector's raw output from a cached run |
| `export_stix` | Write a STIX 2.1 bundle |

Raw source data is cached rather than handed back, so digging into the detail never spends your API quota twice.

---

## Development

```bash
pip install -r requirements-dev.txt
python tests/test_domain_model.py          # regression suite
```

The training data ships with the repo: 383 labelled domains in `data/training_data_domains_v2.csv`, with where they came from and what is wrong with them in `data/README.md`.

The trained models are **not** included, on purpose. A model file is a Python pickle, and loading one from a stranger's pull request runs their code on your machine. Train your own instead. It reproduces the same predictions exactly:

```bash
python core/trainer.py --dataset domain --data data/training_data_domains_v2.csv \
    --tag v2c --exclude harmless_votes,malicious_ratio,malicious_votes,urlhaus_listed
```

To gather fresh training data, use `scripts/collect_training_data.py`. Run it with `--dry-run` first: it writes out the list of domains it plans to check so you can review them before committing an hour of API quota. Experiment tracking goes through MLflow.

---

## Status

Active development. Core pipeline complete and tested against live threat infrastructure.

**Done.** TUI with setup wizard and click-to-pivot · stateful pivot loop with dedup · 14 connectors · deterministic findings · group profiling with MITRE-classified chaining · layered ML/graph/temporal/context scoring · per-type scoring paths · early-warning detection · bystander-safe STIX/OTX export · MCP server · regression suite.

**Next.** Re-collect the IP training set against an ordinary-infrastructure benign class, the way the domain set was: its benign side still holds Tor exits and resolved household-name domains, and averages 4.5 VirusTotal detections against the malicious class's 6.0, which is close to no separation · publish it and name the malicious rows so both classes in both datasets are auditable · broaden group chaining beyond top-ranked tooling · certificate enumeration that survives crt.sh outages.
