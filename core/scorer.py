# core/scorer.py
# Loads trained models and scores indicators at runtime.
# Returns a confidence score and anomaly flag for each pivot result.


import joblib
import numpy as np
import logging
from core.features import extract_features
 
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)
 
MODEL_DIR = "models"
 
 
class ConfidenceScorer:
    """
    Loads trained models and scores pivot results.
    Returns a confidence score between 0 and 1
    and an anomaly flag from Isolation Forest.
 
    Use score_any() as the single entry point — it routes
    to the correct scoring method based on indicator type.
    """
 
    def __init__(self):
        try:
            self.gb_model = joblib.load(f"{MODEL_DIR}/gradient_boosting.joblib")
            self.iso_forest = joblib.load(f"{MODEL_DIR}/isolation_forest.joblib")
            logger.info("Confidence scoring models loaded successfully.")
        except FileNotFoundError:
            logger.error("Models not found. Run core/trainer.py first.")
            self.gb_model = None
            self.iso_forest = None
 
    def _risk_level(self, score: float, thresholds: tuple = (0.7, 0.4)) -> str:
        """Returns HIGH / MEDIUM / LOW based on score and thresholds."""
        high, medium = thresholds
        if score >= high:
            return "HIGH"
        elif score >= medium:
            return "MEDIUM"
        return "LOW"
 
    def score(self, pivot_result: dict) -> dict:
        """
        ML-based scoring for infrastructure indicators — IP, domain, hash.
        Uses Gradient Boosting + Isolation Forest trained on ThreatFox data.
        """
        if not self.gb_model or not self.iso_forest:
            return {"error": "Models not loaded. Run trainer first."}
 
        features = extract_features(pivot_result)
 
        import pandas as pd
        from core.features import FEATURE_COLUMNS
        X = pd.DataFrame([features])[FEATURE_COLUMNS]
 
        confidence_score = self.gb_model.predict_proba(X)[0][1]
        anomaly_flag = self.iso_forest.predict(X)[0]
        is_anomaly = anomaly_flag == -1
 
        return {
            "confidence_score": round(float(confidence_score), 4),
            "is_anomaly": is_anomaly,
            "risk_level": self._risk_level(confidence_score),
            "features_used": features,
        }
 
    def score_threat_group(self, pivot_result: dict) -> dict:
        """
        Scores a threat group pivot based on MITRE ATT&CK coverage.
        Bypasses ML models since infrastructure features don't apply.
        Tuned thresholds: HIGH >= 0.5, MEDIUM >= 0.3.
        """
        results = pivot_result.get("results", {})
        mitre = results.get("mitre", {})
 
        if not mitre.get("found"):
            return {
                "confidence_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "note": "Group not found in MITRE ATT&CK — query may need an alternate alias."
            }
 
        technique_count = len(mitre.get("techniques", []))
        software_count = len(mitre.get("software", []))
        alias_count = len(mitre.get("aliases", []))
 
        # Tightened denominators
        technique_score = min(technique_count / 20, 1.0)
        software_score = min(software_count / 12, 1.0)
        alias_score = min(alias_count / 8, 1.0)
 
        confidence_score = (
            technique_score * 0.5 +
            software_score * 0.3 +
            alias_score * 0.2
        )
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            "risk_level": self._risk_level(confidence_score, thresholds=(0.65, 0.4)),
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
        sample_count = len(samples)
 
        # Sample count signal — more samples = more widespread = higher risk
        sample_score = min(sample_count / 10, 1.0)
 
        # Tag risk signal — ransomware/rat/stealer tags elevate score
        high_risk_tags = {"ransomware", "rat", "stealer", "backdoor", "loader", "worm", "rootkit"}
        tag_hits = 0
        for sample in samples:
            tags = {t.lower() for t in sample.get("tags", [])}
            if tags & high_risk_tags:
                tag_hits += 1
        tag_score = min(tag_hits / max(sample_count, 1), 1.0)
 
        confidence_score = (sample_score * 0.5) + (tag_score * 0.5)
 
        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            "risk_level": self._risk_level(confidence_score, thresholds=(0.5, 0.3)),
            "sample_count": sample_count,
            "note": "Score derived from MalwareBazaar sample volume and malware category tags.",
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
            "risk_level": self._risk_level(confidence_score, thresholds=(0.5, 0.3)),
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
          email/username/filename -> score_identity (SpiderFoot findings)
          ipv4/domain/hash/other  -> score (ML model, infrastructure features)
        """
        indicator_type = pivot_result.get("type", "")
 
        if indicator_type == "threat_group":
            return self.score_threat_group(pivot_result)
        elif indicator_type == "software":
            return self.score_software(pivot_result)
        elif indicator_type in {"email", "username", "filename"}:
            return self.score_identity(pivot_result)
        else:
            return self.score(pivot_result)
 