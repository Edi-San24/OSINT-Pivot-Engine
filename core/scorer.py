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
    Returns a confidence score between 0 and 1. 
    And an anomaly flag from Isolation forest.
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
    
    def score(self, pivot_result: dict) -> dict:
        """
        Scores a signal pivot result and returns
        confidence score, anomaly flag and risk level.
        """

        if not self.gb_model or not self.iso_forest:
            return {"error": "Models not loaded. Run trainer first."}
        
        features = extract_features(pivot_result)
        
        import pandas as pd
        from core.features import FEATURE_COLUMNS
        X = pd.DataFrame([features])[FEATURE_COLUMNS]

        confidence_score = self.gb_model.predict_proba(X)[0][1]
        anomaly_flag = self.iso_forest.predict(X)[0]
        is_anomaly = True if anomaly_flag == -1 else False

        if confidence_score >= 0.7:
            risk_level = "HIGH"
        elif confidence_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "confidence_score": round(float(confidence_score), 4),
            "is_anomaly": is_anomaly,
            "risk_level": risk_level,
            "features_used": features
        }

    def score_threat_group(self, pivot_result: dict) -> dict:
        """
        Scores a threat group pivot result based on MITRE ATT&CK data.
        Bypasses ML models since infrastructure features don't apply.
        Returns a normalized confidence score between 0 and 1.
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

        # Normalize each signal to 0-1
        technique_score = min(technique_count / 30, 1.0)
        software_score = min(software_count / 15, 1.0)
        alias_score = min(alias_count / 10, 1.0)

        # Weighted composite
        confidence_score = (
            technique_score * 0.5 +
            software_score * 0.3 +
            alias_score * 0.2
        )

        if confidence_score >= 0.7:
            risk_level = "HIGH"
        elif confidence_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "confidence_score": round(confidence_score, 4),
            "is_anomaly": False,
            "risk_level": risk_level,
            "technique_count": technique_count,
            "software_count": software_count,
            "alias_count": alias_count,
            "note": "Score derived from MITRE ATT&CK coverage — technique breadth, tooling, and documentation depth."
        }