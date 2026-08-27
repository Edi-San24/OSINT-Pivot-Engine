# Domain training data

`training_data_domains_v2.csv` — 383 labeled domains, 193 malicious / 190 benign.
This is what `core/trainer.py --dataset domain` reads, and the only dataset in
the repo. Everything else under `data/` is local scratch.

Train the live model from it:

```
python core/trainer.py --dataset domain --data data/training_data_domains_v2.csv \
    --tag v2c --exclude harmless_votes,malicious_ratio,malicious_votes,urlhaus_listed
```

Training is deterministic — `random_state=42` throughout — so retraining from
this file reproduces the shipped model's predictions exactly. Models are not
committed: a `.joblib` is a pickle, and loading one from a pull request is
arbitrary code execution.

## How it was built

**Malicious** — recent domains from ThreatFox and URLhaus, both free and
same-day.

**Benign** — sampled from Tranco ranks 100k–1M, cross-checked against the full
ThreatFox and URLhaus lists, then reviewed by hand. Ordinary low-profile
businesses, deliberately not household names: a benign class of famous domains
is separable by VirusTotal vote count alone, and the first model trained that
way learned "is this domain well known" instead of "is this domain safe" and
scored a legitimate hosting provider at p=1.000 malicious.

Junk was removed by name — adult, piracy, and generated-looking domains — but
*not* by feature. Filtering benign candidates on age, nameserver count, or MX
would manufacture the separation the model is supposed to find. Domains that
merely look suspicious were kept: removing them costs stability, measured at
5-fold ROC-AUC 0.878 ± 0.037 with them against 0.876 ± 0.058 without.

## Known limitations

- **The malicious rows are unnamed.** Their `indicator` column reads `0` because
  they were collected before that column existed. You can audit the benign half
  domain by domain; you cannot audit the malicious half at all.
- **383 rows is small.** VirusTotal's free tier caps the day at 500 lookups,
  which is the binding constraint on growing it.
- **Benign labels are one analyst's judgement**, not an authority's.
- **Collected August 2026.** Domain age and reputation both drift.

## What a model trained on this can and cannot do

The shipped configuration excludes the VirusTotal columns. They are three views
of one number — `malicious_votes` and `malicious_ratio` correlate at 0.999 — and
any one of them alone scores AUC 0.96, so a model that keeps them mostly
restates VirusTotal and inherits its blind spots.

It scores **infrastructure**, which sets the boundary in both directions.
Purpose-built attacker infrastructure and long-lived criminal hosting are in
scope. Compromised legitimate sites are not: their infrastructure is genuinely
benign, and the maliciousness lives in served content that no feature here
observes. Bulk hosting providers are over-flagged for the mirror-image reason.

See `tests/test_domain_model.py` for both failure modes pinned against real
investigations.
