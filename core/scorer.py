# core/scorer.py
# Loads trained models and scores indicators at runtime.
# Returns a confidence score and anomaly flag for each pivot result.


import joblib
import numpy as np
import logging
from core import hacktivist
from core.features import extract_features
# Single source for the level mapping. scorer used to carry its own copy of
# both the (0.7, 0.4) default and the comparison, so changing one left the
# other silently disagreeing — the front end and the scorer already diverged
# that way once, calling the same 0.55 group HIGH on one side and MEDIUM on
# the other.
from core.risk import BASE_RATES, DEFAULT_THRESHOLDS, DOMAIN_BAND_PRECISION, score_to_risk
from config import MODEL_DIR

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Full marks on each component, set to the 95th percentile of the measured
# distribution across all ATT&CK groups. Must stay above the connector's
# truncation caps, or every well-documented group scores identically.
TECHNIQUE_FULL_MARKS = 78
SOFTWARE_FULL_MARKS = 23
ALIAS_FULL_MARKS = 9

# Sample volume earning full marks on a malware family pivot. Measured across
# established families: targeted ransomware sits around 27-80 while commodity
# malware runs into the thousands. Volume therefore marks whether a family is
# established, not how dangerous it is — severity comes from the tag signal —
# so this saturates early on purpose.
SAMPLE_VOLUME_FULL_MARKS = 50

# The live domain model. v2c is the variant trained without the VirusTotal
# features — those three columns are one number viewed three ways, and alone
# they score AUC 0.96, so a model leaning on them cannot say anything
# VirusTotal has not already said. briansclub.cm is the case: zero VirusTotal
# detections, called benign at p=0.010 by the VirusTotal-dependent variant and
# flagged at 0.962 by this one.
#
# Change this tag to swap variants; the models keep their own column lists, so
# nothing else needs touching.
DOMAIN_MODEL_TAG = "v2c"


class ConfidenceScorer:
    """
    Loads trained models and scores pivot results.
    Returns a confidence score between 0 and 1
    and an anomaly flag from Isolation Forest.
 
    Use score_any() as the single entry point — it routes
    to the correct scoring method based on indicator type.
    """
 
    def __init__(self, org_profile: dict | None = None):
        # Only used to score hacktivist targeting overlap. Passed in rather than
        # loaded here so core.agent stays the single place the profile is read.
        self.org_profile = org_profile
        self.gb_model, self.iso_forest = self._load_pair("")
        if self.gb_model is None:
            logger.error("Models not found. Run core/trainer.py first.")

        # Absent on a clone, since domain models are gitignored. Domains then
        # fall back to the IP model rather than going unscored.
        self.domain_gb, self.domain_iso = self._load_pair(f"_{DOMAIN_MODEL_TAG}_domain")
        if self.domain_gb is None:
            logger.info("No domain model; domain indicators use the IP model.")

    @staticmethod
    def _load_pair(suffix: str) -> tuple:
        """Loads a gradient boosting and isolation forest pair, (None, None) if absent."""
        try:
            return (
                joblib.load(f"{MODEL_DIR}/gradient_boosting{suffix}.joblib"),
                joblib.load(f"{MODEL_DIR}/isolation_forest{suffix}.joblib"),
            )
        except FileNotFoundError:
            return None, None

    def _risk_fields(self, score: float, thresholds: tuple = DEFAULT_THRESHOLDS) -> dict:
        """
        risk_level plus the thresholds used to reach it.

        These are calibrated per indicator type and were being thrown away: only
        confidence_score propagated, so the front end reapplied a global 0.7/0.4
        and could disagree with the level reported here. A community-scored group
        at 0.55 was HIGH to the scorer and MEDIUM on screen. Emitted as a list
        because the value round-trips through JSON.
        """
        return {
            "risk_level": score_to_risk(score, thresholds),
            "thresholds": list(thresholds),
        }
 
    def score(self, pivot_result: dict) -> dict:
        """
        ML-based scoring for infrastructure indicators — IP, domain, hash.

        Domains are scored by their own model where one is installed. The IP
        model reads three features from Shodan and Censys, which are IP services
        the domain pivot never calls, so on a domain a third of its input is
        structurally zero.
        """
        use_domain = pivot_result.get("type") == "domain" and self.domain_gb is not None
        gb = self.domain_gb if use_domain else self.gb_model
        iso = self.domain_iso if use_domain else self.iso_forest

        if not gb or not iso:
            return {"error": "Models not loaded. Run trainer first."}

        features = extract_features(pivot_result)

        import pandas as pd
        row = pd.DataFrame([features])

        # Columns come from each model rather than from FEATURE_COLUMNS. The two
        # drifted when FEATURE_COLUMNS grew to 14 while the IP model stayed at
        # the 7 it was fitted on, and every infrastructure score raised
        # ValueError until this started reading the model's own list.
        def matrix(model):
            return row.reindex(columns=list(model.feature_names_in_), fill_value=0).fillna(0)

        confidence_score = gb.predict_proba(matrix(gb))[0][1]
        is_anomaly = iso.predict(matrix(iso))[0] == -1

        # The measured meaning of the band, so the score reads as the model's
        # discrimination rather than as a probability. It is not calibrated:
        # 0.67 does not mean a 67% chance of being malicious, and the base rate
        # travels with it because a precision means nothing without its prior.
        #
        # Only the domain model has measured bands. Addresses route to score_ip
        # now, and any other type reaching here has no measurement behind it, so
        # it gets none rather than one borrowed from a different distribution.
        fields = self._risk_fields(confidence_score)
        if use_domain:
            fields["band_precision"] = DOMAIN_BAND_PRECISION.get(fields["risk_level"])
            fields["band_base_rate"] = BASE_RATES["domain"]

        return {
            "confidence_score": round(float(confidence_score), 4),
            "is_anomaly": is_anomaly,
            "model": f"domain_{DOMAIN_MODEL_TAG}" if use_domain else "ip",
            **fields,
            "features_used": features,
        }
 
    # Relevant, deduplicated pulses earning full marks when ATT&CK has nothing.
    # Measured on filtered counts: NoName057 27, Handala 25, KillNet 12,
    # CyberVolk 11. Modest on purpose — a genuinely new actor may have a handful
    # on day one, and the point is to register it exists at all.
    COMMUNITY_PULSE_FULL_MARKS = 15

    def _score_group_from_community(self, pivot_result: dict, results: dict) -> dict:
        """
        Scores a threat group that MITRE ATT&CK does not profile, from OTX pulse
        volume, distinct authors, and dark web mentions.

        Caps below the ATT&CK-backed range on purpose. Community reporting
        establishes that an actor is real and active; it does not carry the
        same evidentiary weight as a curated ATT&CK profile.

        Targeting overlap is deliberately not scored here. Measured against
        KillNet, a profile the crew names scored 0.75 and one it does not scored
        0.7025 — both HIGH, because the 0.75 cap swallows the term. It is routed
        through core.relevance instead, which is what relevance_level is for.
        """
        otx = results.get("otx_search", {})
        ahmia = results.get("ahmia", {})
        assessment = results.get("hacktivist", {}) or {}

        pulse_count = otx.get("pulse_count", 0) if isinstance(otx, dict) else 0
        authors = otx.get("distinct_authors", 0) if isinstance(otx, dict) else 0
        onion_hits = len(ahmia.get("results", []) or []) if isinstance(ahmia, dict) else 0
        is_hacktivist = bool(assessment.get("is_hacktivist"))
        otx_failed = isinstance(otx, dict) and "error" in otx

        # What the branch below can actually score from. The hacktivist branch
        # ignores onion hits, so they are not usable evidence there.
        scoreable = bool(pulse_count) or (bool(onion_hits) and not is_hacktivist)

        # A failed lookup is not an empty result, and neither is a clean bill.
        if otx_failed or not scoreable:
            reason = (
                "OTX pulse search failed, so community reporting could not be checked"
                if otx_failed else
                "No match in MITRE ATT&CK, OTX community reporting, or dark web indexes"
            )
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "is_hacktivist": is_hacktivist,
                "note": (
                    f"{reason}. Either the name is wrong, the source was "
                    "unavailable, or the actor is too new to have been written "
                    "up. This is an absence of data, not a clean bill."
                ),
            }

        # Volume says an actor is discussed; independent authors say it is not
        # one person's post amplified.
        volume = min(pulse_count / self.COMMUNITY_PULSE_FULL_MARKS, 1.0)
        corroboration = min(authors / 5, 1.0)

        if is_hacktivist:
            # These crews coordinate on Telegram, so onion hits are structurally
            # near zero and carrying that weight would only suppress the score.
            # It goes to corroboration instead.
            score = (volume * 0.55) + (corroboration * 0.45)
            basis = self._hacktivist_note(assessment, pulse_count, authors)
        else:
            underground = min(onion_hits / 5, 1.0)
            score = (volume * 0.45) + (corroboration * 0.35) + (underground * 0.20)
            basis = (
                f"{pulse_count} OTX pulses from {authors} authors, "
                f"{onion_hits} dark web mentions."
            )

        score = round(min(score, 0.75), 4)

        return {
            "confidence_score": score,
            "is_anomaly": False,
            **self._risk_fields(score, thresholds=(0.5, 0.25)),
            "pulse_count": pulse_count,
            "distinct_authors": authors,
            "onion_mentions": onion_hits,
            "is_hacktivist": is_hacktivist,
            "note": (
                f"Not in MITRE ATT&CK, scored from community reporting: {basis} "
                "Capped at 0.75 since community reporting is weaker evidence "
                "than a curated ATT&CK profile."
            ),
        }

    def _hacktivist_note(self, assessment: dict, pulse_count: int, authors: int) -> str:
        """One line on what the hacktivist read was scored from."""
        parts = [f"{pulse_count} OTX pulses from {authors} authors"]
        if assessment.get("alignments"):
            parts.append(f"assessed {', '.join(assessment['alignments'][:2])}")
        if assessment.get("activities"):
            parts.append(f"activity {', '.join(assessment['activities'][:3])}")
        parts.append("dark web weight reassigned, these crews are on Telegram")
        return "; ".join(parts) + "."

    def score_threat_group(self, pivot_result: dict) -> dict:
        """
        Scores a threat group pivot based on MITRE ATT&CK coverage.
        Bypasses ML models since infrastructure features don't apply.
        Tuned thresholds: HIGH >= 0.5, MEDIUM >= 0.3.
        """
        results = pivot_result.get("results", {})
        mitre = results.get("mitre", {})
 
        if not mitre.get("found"):
            # ATT&CK absence is not evidence of absence. Hacktivist crews and
            # newly named actors are routinely missing from it, so fall back to
            # community reporting rather than returning a flat zero that reads
            # as "harmless".
            return self._score_group_from_community(pivot_result, results)
 
        # True totals from the connector. The len() fallback is for older
        # cached results only, and undercounts.
        technique_count = mitre.get("technique_count", len(mitre.get("techniques", [])))
        software_count = mitre.get("software_count", len(mitre.get("software", [])))
        alias_count = len(mitre.get("aliases", []))

        technique_score = min(technique_count / TECHNIQUE_FULL_MARKS, 1.0)
        software_score = min(software_count / SOFTWARE_FULL_MARKS, 1.0)
        alias_score = min(alias_count / ALIAS_FULL_MARKS, 1.0)
 
        confidence_score = (
            technique_score * 0.5 +
            software_score * 0.3 +
            alias_score * 0.2
        )
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.65, 0.4)),
            "technique_count": technique_count,
            "software_count": software_count,
            "alias_count": alias_count,
            "note": "Score derived from MITRE ATT&CK coverage — technique breadth, tooling, and documentation depth.",
        }
 
    def score_software(self, pivot_result: dict) -> dict:
        """
        Scores a software/malware family pivot based on MalwareBazaar data.
        Uses sample count and average VT detection ratio as signals.
        """
        results = pivot_result.get("results", {})
        bazaar = results.get("malwarebazaar", {})
 
        if not bazaar.get("found"):
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "Malware family not found in MalwareBazaar."
            }
 
        samples = bazaar.get("samples", [])
        # True total from the connector. The len() fallback is for older cached
        # results only, and undercounts.
        sample_count = bazaar.get("sample_count", len(samples))

        sample_score = min(sample_count / SAMPLE_VOLUME_FULL_MARKS, 1.0)

        # Tag risk signal — ransomware/rat/stealer tags elevate score.
        # Measured over the samples actually returned, not the true total,
        # which would dilute the ratio toward zero.
        high_risk_tags = {"ransomware", "rat", "stealer", "backdoor", "loader", "worm", "rootkit"}
        tag_hits = 0
        for sample in samples:
            tags = {t.lower() for t in sample.get("tags", [])}
            if tags & high_risk_tags:
                tag_hits += 1
        tag_score = tag_hits / len(samples) if samples else 0.0

        confidence_score = (sample_score * 0.5) + (tag_score * 0.5)
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.65, 0.4)),
            "sample_count": sample_count,
            "note": "Score derived from MalwareBazaar sample volume and malware category tags.",
        }

    # VirusTotal detections earning full marks on an address. Deliberately low,
    # and much lower than the file threshold, because VirusTotal is slow on fresh
    # infrastructure: ten Aisuru C2 addresses that abuse.ch rated confidence 100
    # were carrying 1 to 3 detections out of roughly 52 engines.
    IP_DETECTION_FULL_MARKS = 6

    # URLhaus entries earning full marks. A host serving five known malware URLs
    # is a distribution point whatever else is true of it.
    IP_URL_FULL_MARKS = 5

    # Ceiling each source can reach on its own, combined by noisy-OR rather than
    # averaged.
    #
    # Averaging was the first attempt and it reproduced the bug this codebase
    # keeps finding. URLhaus answering "not found" scored zero and was folded
    # into the mean, which dragged a ThreatFox confidence-100 Cobalt Strike C2
    # down to 0.475 MEDIUM. But URLhaus tracks malware URLs, not C2 addresses,
    # so its silence about a C2 is expected and says nothing about the address.
    #
    # Noisy-OR treats each source as independent evidence FOR maliciousness. A
    # source with nothing to report contributes exactly nothing instead of
    # voting innocent, and corroboration accumulates.
    #
    # ThreatFox leads because it is curated, carries its own confidence and is
    # fastest on new infrastructure. VirusTotal sits third on purpose: weighting
    # it higher rebuilds the failure the domain model was redone to escape, where
    # the score could say nothing VirusTotal had not already said.
    IP_EVIDENCE_CEILINGS = {"threatfox": 0.80, "urlhaus": 0.70, "virustotal": 0.50, "otx": 0.30}

    def score_ip(self, pivot_result: dict) -> dict:
        """
        Scores an address from the evidence an IP pivot collects rather than
        from a model.

        The IP model it replaces never measured what it claimed to. Its benign
        class was built by resolving domains, so every benign row had domains
        pointing at it and mature multi-service hosting behind it, while every
        malicious row was a minimal single-purpose box from a feed. Any feature
        correlating with "established multi-service host" then separated the
        classes, which is why dns_record_count scored AUC 0.139 and
        total_open_ports 0.299 — both inverted, both artefacts of sampling.
        Matched sampling against URLhaus payload hosts did not fix it, because
        those are compromised routers rather than hosting businesses.

        Measured band precision said the same thing before the cause was known:
        every address published from this engine landed in the MEDIUM band, at
        0.95x the base rate, which is no information at all.
        """
        results = pivot_result.get("results", {})
        tf = results.get("threatfox", {}) or {}
        uh = results.get("urlhaus", {}) or {}
        vt = results.get("virustotal", {}) or {}
        otx = results.get("otx", {}) or {}

        # An error is an unanswered question. A zero from a source that did
        # answer is a finding. Conflating them is how an outage becomes a clean
        # bill of health.
        answered = {
            "threatfox": "error" not in tf and "found" in tf,
            "urlhaus": "error" not in uh and "found" in uh,
            "virustotal": "error" not in vt and "malicious_votes" in vt,
            "otx": "error" not in otx and otx.get("pulse_count") is not None,
        }

        if not any(answered.values()):
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "No source answered for this address.",
            }

        detections = vt.get("malicious_votes", 0) or 0
        url_count = int(uh.get("url_count") or 0) if uh.get("found") else 0
        pulses = otx.get("pulse_count") or 0

        signals = {
            "threatfox": (tf.get("max_confidence") or 0) / 100 if tf.get("found") else 0.0,
            "urlhaus": min(url_count / self.IP_URL_FULL_MARKS, 1.0),
            "virustotal": min(detections / self.IP_DETECTION_FULL_MARKS, 1.0),
            "otx": min(pulses / 5, 1.0),
        }

        # Noisy-OR over the sources that answered. A source that answered with
        # nothing found contributes a factor of 1 and leaves the score untouched,
        # rather than averaging it downward.
        remaining = 1.0
        for source, ceiling in self.IP_EVIDENCE_CEILINGS.items():
            if answered[source]:
                remaining *= 1.0 - ceiling * signals[source]
        confidence_score = 1.0 - remaining

        return {
            "confidence_score": round(float(confidence_score), 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.5, 0.25)),
            "sources_answered": sorted(k for k, v in answered.items() if v),
            "malware_families": tf.get("malware_families") or [],
            # ThreatFox's own call on whether the host was taken over rather than
            # provisioned. It changes the response, not the score: a compromised
            # host has an owner who is a victim and should be notified, not
            # blocklisted.
            "is_compromised": bool(tf.get("is_compromised")),
            "malicious_urls": url_count,
            "note": "Score derived from ThreatFox, URLhaus, VirusTotal and OTX evidence.",
        }

    # VirusTotal detections earning full marks on a file. Roughly 70 engines
    # scan a sample: established malware lands in the 55-70 range, while a one
    # or two vendor hit is more often a false positive than a find. Saturating
    # at 40 tops out a confidently detected sample without demanding unanimity.
    HASH_DETECTION_FULL_MARKS = 40

    def score_hash(self, pivot_result: dict) -> dict:
        """
        Scores a file hash from what a hash pivot actually collects: VirusTotal
        detections, MalwareBazaar corroboration, and ATT&CK coverage.

        Deliberately not routed through the infrastructure model. That model
        reads open ports, DNS records and hosting country, none of which a file
        has, so every hash landed on the same point in its feature space and
        scored identically — 0.956 for all fourteen across saved investigations.
        """
        results = pivot_result.get("results", {})
        vt = results.get("virustotal", {}) or {}
        bazaar = results.get("malwarebazaar", {}) or {}
        mitre = results.get("mitre", {}) or {}

        # An error is an unanswered question, not a verdict of zero detections.
        vt_answered = "error" not in vt and "malicious_votes" in vt
        detections = vt.get("malicious_votes", 0) if vt_answered else 0
        in_bazaar = bool(bazaar.get("found"))
        in_attack = bool(mitre.get("found"))

        # Silence from every source is not a clean bill of health. A hash nobody
        # has seen is unknown, and reporting LOW would read as "checked, fine".
        if not vt_answered and not in_bazaar and not in_attack:
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "No VirusTotal, MalwareBazaar or ATT&CK record for this hash.",
            }

        detection_score = min(detections / self.HASH_DETECTION_FULL_MARKS, 1.0)

        # Corroboration is scored separately because being catalogued by
        # MalwareBazaar or profiled in ATT&CK means a human classified the
        # sample, which a detection count on its own does not.
        high_risk_tags = {"ransomware", "rat", "stealer", "backdoor", "loader", "worm", "rootkit"}
        tags = {str(t).lower() for t in (bazaar.get("tags") or [])}

        corroboration = 0.0
        if in_bazaar:
            corroboration += 0.5
        if tags & high_risk_tags:
            corroboration += 0.25
        if in_attack:
            corroboration += 0.25

        confidence_score = (detection_score * 0.65) + (corroboration * 0.35)

        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.65, 0.4)),
            "detections": detections,
            "malware_family": vt.get("malware_family") or bazaar.get("malware_family"),
            "note": "Score derived from VirusTotal detections, MalwareBazaar catalogue and ATT&CK coverage.",
        }
 
    def score_identity(self, pivot_result: dict) -> dict:
        """
        Scores email and username pivots based on SpiderFoot findings.
        Returns 0.0 when --deep was not used and SpiderFoot was skipped.
        """
        results = pivot_result.get("results", {})
        spiderfoot = results.get("spiderfoot", {})
 
        if spiderfoot.get("skipped"):
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "SpiderFoot skipped — re-run with --deep for identity enrichment.",
            }
 
        finding_count = spiderfoot.get("finding_count", 0)
        scan_status = spiderfoot.get("scan_status", "")
 
        if scan_status == "TIMEOUT" or finding_count == 0:
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "SpiderFoot scan timed out or returned no findings.",
            }
 
        # More findings = more exposed footprint = higher risk
        confidence_score = min(finding_count / 50, 1.0)
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            **self._risk_fields(confidence_score, thresholds=(0.5, 0.3)),
            "finding_count": finding_count,
            "note": "Score derived from SpiderFoot identity footprint breadth.",
        }
 
    def score_any(self, pivot_result: dict) -> dict:
        """
        Centralized scoring router. Picks the right method based on
        indicator type so every pivot gets a meaningful score instead
        of defaulting to 0.0205 when infrastructure features are absent.
 
        Routing:
          threat_group -> score_threat_group (MITRE ATT&CK coverage)
          software     -> score_software     (MalwareBazaar sample volume)
          hash         -> score_hash         (detections, catalogue, ATT&CK)
          ipv4         -> score_ip           (ThreatFox, URLhaus, VT, OTX)
          email/username/filename -> score_identity (SpiderFoot findings)
          domain/other            -> score (ML model, infrastructure features)
        """
        indicator_type = pivot_result.get("type", "")

        if indicator_type == "threat_group":
            return self.score_threat_group(pivot_result)
        elif indicator_type == "software":
            return self.score_software(pivot_result)
        elif indicator_type == "hash":
            return self.score_hash(pivot_result)
        elif indicator_type == "ipv4":
            return self.score_ip(pivot_result)
        elif indicator_type in {"email", "username", "filename"}:
            return self.score_identity(pivot_result)
        else:
            return self.score(pivot_result)
 