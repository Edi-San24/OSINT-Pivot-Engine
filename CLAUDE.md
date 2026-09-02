# OSINT Pivot Engine

Autonomous threat-intelligence pivot engine. One seed indicator fans out across
14 public sources in parallel, chains into what it finds, scores the result, and
writes an analyst summary. v1.3.0. Triage, not attribution.

## Working rules

- **Never add `Co-Authored-By` to a commit.** The repo and the credit are the
  owner's.
- **Do not commit or push unless asked.** Work happens on `main`; no feature
  branches.
- **Comment style is short.** Two-line file headers, brief docstrings, comments
  only where the reason is not obvious from the code. No essay blocks. Comments
  earn their place by recording *why*, usually a bug that made the line
  necessary.
- **Verify before reporting.** Do not describe work that was not done, and do
  not report a fix without running it.
- **Read the whole error body before diagnosing.** A Censys 422 was called an
  "API contract change" from the status code alone; the body said "insufficient
  balance". A `.ch` domain slipped a leak check whose TLD allowlist was the bug.
- **Avoid em dashes in prose and comments.**
- Do not use subagents unless asked.

## How scoring routes

This changed substantially. Only domains have a model.

```
threat_group          -> score_threat_group   ATT&CK coverage
software              -> score_software       MalwareBazaar sample volume
hash                  -> score_hash           detections, catalogue, ATT&CK
email/username        -> score_identity       SpiderFoot findings
domain + model present-> score                gradient boosting, v2c
everything else       -> score_from_evidence  ThreatFox, URLhaus, VT, OTX
```

`score_from_evidence` covers addresses, URLs, and domains on a checkout with no
model installed, which is every fresh clone. Sources combine by **noisy-OR**, so
a source with nothing to report leaves the score alone. Averaging was tried and
rebuilt the absence bug: URLhaus answering "not found" about a C2 dragged a
ThreatFox confidence-100 listing to MEDIUM.

The domain model (`v2c`) deliberately excludes the VirusTotal columns. They are
three views of one number that alone scores AUC 0.96, so a model leaning on them
cannot say anything VirusTotal has not already said. 5-fold ROC-AUC 0.878 ±
0.037 on 383 domains, with measured band precisions in `core/risk.py`.

**There is no IP model, on purpose.** It was retired after its benign class
turned out to be built by resolving domains, which made every benign row a
mature multi-service host and every malicious row a minimal box from a feed. It
had learned to tell a busy server from a quiet one. Two rebuild attempts failed;
both are documented in `git log` so nobody repeats them.

## The recurring bug

**An empty result treated as a fact instead of an absence.** This has surfaced
roughly nine times. Whenever a source answers with silence, ask whether the code
is reading that as information. Instances found and fixed:

- score 0.0 rendering as LOW instead of UNKNOWN
- RDAP 404 reported as "not registered"
- zero passive DNS records read as "no co-tenants"
- stale 2019 records read as "current tenants"
- RDAP 4xx producing age 0, indistinguishable from registered-today
- Censys 422 diagnosed as an API change when it was a spent balance
- an unreachable threat feed producing an empty exclusion list
- graph and temporal scores of 0.0 subtracting from a confident model output
- an unregistered domain scoring 0.7507 HIGH on an all-zero feature vector
- RFC 5737 documentation space reporting LOW

Fixes live in `has_evidence`, the UNKNOWN paths in every scorer, the blending
floors in `graph_scorer`/`temporal_scorer`, and the all-zero and non-routable
guards in `scorer`.

## Layout

- `core/agent.py` LangGraph pivot loop, summary prompt, verdict logging
- `core/executor.py` connector fan-out, guarded licensed imports
- `core/scorer.py` all scoring paths, `score_any` is the entry point
- `core/risk.py` level mapping, thresholds, band precisions. Single source
- `core/features.py` the 14 domain features. Every one from a free source
- `core/stix_exporter.py` STIX and OTX pulses, bystander protection, leak check
- `core/relevance.py` + `core/hacktivist.py` org-relevance layer, inert without
  `org_profile.yaml`
- `core/disagreement.py` verdict log, agreement and accuracy with intervals
- `scripts/collect_training_data.py` dataset collection, `--dry-run` review gate
- `scripts/evaluate.py` labelled evaluation set, spends quota
- `tests/test_domain_model.py` regression suite, no pytest, exits non-zero

## Local-only, never committed

`connectors/domaintools.py`, `connectors/dnsdb.py`, `core/tier.py`. Each is
imported behind a guard so a public clone still runs: `executor.py` uses
try/except ImportError, `agent.py` uses a null-object tier stub returning
"open-source". **Keep those guards.** Verified by building a tree from
`git archive HEAD` and running it.

Licensed data enriches the report only and never feeds a feature. Verified: a
pivot carrying DomainTools risk scores and DNSDB counts produces a
byte-identical feature vector to the same pivot stripped.

No `.joblib` is tracked. A model file is a pickle, so loading one from a pull
request runs that author's code. Clones train from the published dataset, which
reproduces the shipped predictions exactly.

## Measured, 2 September 2026

Full labelled set, `scripts/evaluate.py`, 33 cases:

```
accuracy    30/33 = 91%   CI [76%, 97%]
  malicious 17/18
  benign    11/13
  unknown     2/2
score alone 25/33      agent 5 overrides, 3 fixed, 0 broke
```

Domains re-run after the evidence floor landed: malicious 8/8, up from 7/8. The
three compromised sites moved from agent-override to concur, so the score is now
right on its own and the LLM is no longer load-bearing for that blind spot.

Every remaining miss is a **false positive on legitimate infrastructure**, which
is the direction that harms a third party. There are no false negatives.

## Known limitations

- **The agent is non-deterministic, and this is now the largest single source of
  error.** On identical data and a byte-identical score of 0.157,
  dizaynholding.com drew LOW on one run and MEDIUM on the next.
  raspberryhillsshop.com drew HIGH on one run and no THREAT LEVEL line at all on
  the next. Nothing measures this. The evidence floor removed the LLM from one
  blind spot; the same reasoning applies elsewhere. Deterministic evidence should
  decide wherever it can, and the agent should be narrative rather than
  load-bearing.
- **Compromised legitimate sites** are invisible to the model, since their
  infrastructure is genuinely benign and the maliciousness is in served content.
  Feed evidence now floors the model, which fixes the listed ones deterministically.
  A compromised site no feed has caught yet is still missed.
- **Bulk hosting is over-flagged**, for the mirror-image reason.
- **`confidence_score` ranks, it does not calibrate.** Post-hoc calibration was
  tried and rejected: Platt made ECE worse, isotonic cost AUC, and at 383 rows
  both fit noise.
- **Agreement is not accuracy.** Two components can concur and both be wrong.
  Use `scripts/evaluate.py` for accuracy; the verdict log's `agreed` field is
  concurrence only.
- **Report intervals, not point estimates.** A 7-of-10 run was once quoted as
  "70% against a historical 32%" when the intervals overlapped at [40,89] and
  [20,47]. Detecting a shift that size needs about 26 cases per group.
- **13 benign evaluation cases is thin.** That is where false positives live,
  the direction that harms a third party, so it is the half to grow first.

## Open items

- `claude-fable-5-1` model bump in `core/agent.py` was uncommitted and is not
  mine; confirm before committing it.
- Four OTX pulses built and unuploaded: `aisuru_pulse.json` (9 valid IOCs,
  drop 178.128.173.150, OTX whitelists it), `clearfake_campaign_pulse.json` (24),
  `okami_pulse.json` (18), `rh_pulse.json` (1). Upload the pulse file only, never
  the `.audit.json`, which names co-hosted third parties.
- Grow the benign half of the evaluation set. 13 cases gives CI [58%, 96%], and
  benign is where false positives live.
- README rewrite in the style of the owner's `ioc-reputation-scorer`: three
  badges, one dense opening paragraph, short `Label - detail` bullets,
  code-forward, plain `Known Limitations` section.
- LinkedIn post drafted but unposted, thanking DomainTools and Ian Campbell, who
  arranged the access at BSides.
- Censys is out of credits; research access is being arranged. `high_risk_country`
  reads only from Censys and is therefore dead.
- `crt.sh` 502s frequently and has no fallback. DomainTools Iris `ssl_info`
  returns SANs and would close it where the tier allows.
- `connectors/passivedns.py` has no request timeout on either call.
- OTX search 504s with no retry; fixing it means raising
  `GROUP_DISCOVERY_TIMEOUT` past 75s since OTX measures 28-58s.
- No `org_profile.yaml`, so the whole relevance layer is inert. About ten lines
  of YAML from the example switches it on; `countries` and `sectors` alone
  unlock `targeting_overlap`.
- `sfp_accounts` is broken on SpiderFoot 3.5.0: dead WhatsMyName URL plus a
  schema migration. Username pivots are one source deep with that source down.

## Commands

Investigate, accepts URLs with ports and paths:
```
PYTHONPATH=. venv/bin/python main.py -s <seed> --depth 5 -o out.json
```

Build an OTX pulse. Writes the upload file plus a local `.audit.json` naming
what was excluded and why. **Read the leak warning every time**: OTX extracts
indicators from description prose, so naming an excluded address publishes it.
```
PYTHONPATH=. venv/bin/python -m core.stix_exporter inv.json \
  --title "..." --description @desc.txt --tags "a,b" --attack-ids "T1566" \
  --exclude "x" --include "y" -o pulse.json
```

Regression suite, seconds, no quota:
```
PYTHONPATH=. venv/bin/python tests/test_domain_model.py
```

Labelled accuracy run, one VirusTotal lookup per case:
```
PYTHONPATH=. venv/bin/python scripts/evaluate.py
```

Collect training data. `--dry-run` writes the benign shortlist for review before
an hour of quota is spent. VirusTotal free tier is 4/min **and 500/day**; the
daily cap is what actually bites.
```
PYTHONPATH=. venv/bin/python scripts/collect_training_data.py \
  --indicators domain --dry-run
```

Retrain the live domain model:
```
PYTHONPATH=. venv/bin/python core/trainer.py --dataset domain \
  --data data/training_data_domains_v2.csv --tag v2c \
  --exclude harmless_votes,malicious_ratio,malicious_votes,urlhaus_listed
```

Verdict log, agreement and accuracy:
```
PYTHONPATH=. venv/bin/python -m core.disagreement
```

TUI. **Restart it after code changes**; it caches imported modules and has
served stale results.
```
PYTHONPATH=. venv/bin/python tui.py
```

Fresh seeds: `threatfox.abuse.ch/browse/`, `urlhaus.abuse.ch/browse/`,
`otx.alienvault.com/browse/global/pulses`. ThreatFox `taginfo` and `malwareinfo`
queries are the best way to find a cluster rather than a single indicator.
