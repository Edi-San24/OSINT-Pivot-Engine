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