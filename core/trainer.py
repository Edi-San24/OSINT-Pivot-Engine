# core/trainer.py
# ML model training and MLflow experiment tracking.
# Trains Isolation Forest and Gradient Boosting models
# on engineered features from pivot results.

import os
import joblib
import numpy as np
import pandas as pd
import mlflow
import mlflow.sklearn
from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from core.features import build_feature_matrix, FEATURE_COLUMNS

# Model output directory
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

def load_training_data() -> tuple:
    """
    Loads real labeled training data from CSV.
    Falls back to synthetic data if CSV not found.
    """
    if os.path.exists("data/training_data.csv"):
        print("[*] Loading real training data from CSV...")
        df = pd.read_csv("data/training_data.csv")
        df = df.fillna(0)
        X = df[FEATURE_COLUMNS]
        y = df["label"].values
        print(f"[+] Loaded {len(df)} samples. Malicious: {sum(y)} | Benign: {len(y) - sum(y)}")
        return X, y
    else:
        print("[!] No real training data found. Falling back to synthetic data.")
        return generate_training_data()

def generate_training_data() -> tuple:
    """
    Generates synthetic training data based on
    known malicious and benign infrastructure patterns.
    Returns features DataFrame and labels array.
    """
    benign_samples = []
    malicious_samples = []

    # Benign infrastructure patterns
    for _ in range(200):
        benign_samples.append({
            "malicious_votes": np.random.randint(0, 12),
            "harmless_votes": np.random.randint(10, 70),
            "malicious_ratio": np.random.uniform(0.0, 0.35),
            "shodan_blocked": np.random.choice([0, 1], p=[0.5, 0.5]),
            "dns_record_count": np.random.randint(0, 15),
            "total_open_ports": np.random.randint(0, 10),
            "high_risk_country": np.random.choice([0, 1], p=[0.6, 0.4]),
        })

    # Malicious infrastructure patterns
    for _ in range(200):
        malicious_samples.append({
            "malicious_votes": np.random.randint(0, 25),
            "harmless_votes": np.random.randint(0, 60),
            "malicious_ratio": np.random.uniform(0.0, 1.0),
            "shodan_blocked": np.random.choice([0, 1], p=[0.4, 0.6]),
            "dns_record_count": np.random.randint(0, 15),
            "total_open_ports": np.random.randint(0, 10),
            "high_risk_country": np.random.choice([0, 1], p=[0.35, 0.65]),
        })

    benign_df = pd.DataFrame(benign_samples)
    malicious_df = pd.DataFrame(malicious_samples)

    X = pd.concat([benign_df, malicious_df], ignore_index=True)
    y = np.array([0] * 200 + [1] * 200)

    return X, y

def train_models():
    """
    Trains Isolation Forest and Gradient Boosting models.
    Logs all experiments and registers models with MLflow.
    """
    print("[*] Loading training data...")
    X, y = load_training_data()

    X = X.fillna(0)
    X = X[FEATURE_COLUMNS]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    mlflow.set_experiment("osint-pivot-engine")

    with mlflow.start_run(run_name="isolation_forest"):
        print("[*] Training Isolation Forest...")

        iso_forest = IsolationForest(
            contamination=0.2,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(X_train)

        mlflow.log_param("contamination", 0.2)
        mlflow.log_param("n_estimators", 100)
        mlflow.sklearn.log_model(iso_forest, name="isolation_forest")

        joblib.dump(iso_forest, f"{MODEL_DIR}/isolation_forest.joblib")
        print("[+] Isolation Forest trained and saved.")

    with mlflow.start_run(run_name="gradient_boosting"):
        print("[*] Training Gradient Boosting...")

        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=3,
            random_state=42
        )
        gb_model.fit(X_train, y_train)

        y_pred = gb_model.predict(X_test)
        y_prob = gb_model.predict_proba(X_test)[:, 1]
        roc_auc = roc_auc_score(y_test, y_prob)

        mlflow.log_param("n_estimators", 100)
        mlflow.log_param("learning_rate", 0.1)
        mlflow.log_param("max_depth", 3)
        mlflow.log_metric("roc_auc", roc_auc)
        mlflow.sklearn.log_model(gb_model, name="gradient_boosting")

        joblib.dump(gb_model, f"{MODEL_DIR}/gradient_boosting.joblib")
        print(f"[+] Gradient Boosting trained. ROC-AUC: {roc_auc:.4f}")
        print(classification_report(y_test, y_pred))

    print("[+] All models trained and logged to MLflow.")

if __name__ == "__main__":
    train_models()