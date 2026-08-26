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
from config import MODEL_DIR, DATA_DIR

# Model output directory — shared with core/scorer.py via config so training
# always writes where scoring reads, regardless of the working directory.
os.makedirs(MODEL_DIR, exist_ok=True)
TRAINING_DATA_PATH = os.path.join(DATA_DIR, "training_data.csv")
DOMAIN_TRAINING_DATA_PATH = os.path.join(DATA_DIR, "training_data_domains.csv")

def load_training_data(path: str = None) -> tuple:
    """
    Loads real labeled training data from CSV.
    Falls back to synthetic data if CSV not found.

    Columns absent from the file are filled with zeros rather than raising, so a
    dataset collected before a feature existed still loads.
    """
    path = path or TRAINING_DATA_PATH
    if os.path.exists(path):
        print(f"[*] Loading real training data from {os.path.basename(path)}...")
        df = pd.read_csv(path)
        df = df.fillna(0)
        for column in FEATURE_COLUMNS:
            if column not in df:
                df[column] = 0
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

def train_models(dataset: str = "ip"):
    """
    Trains Isolation Forest and Gradient Boosting models.
    Logs all experiments and registers models with MLflow.

    dataset="domain" trains on the domain set and writes to its own model files.
    Domain and IP rows are not interchangeable: Shodan and Censys are IP
    services the domain pivot never calls, so their features are zero on every
    domain row. Training on one and serving the other loses a third of the
    learned signal, which is what the live engine was doing.
    """
    domain_mode = dataset == "domain"
    path = DOMAIN_TRAINING_DATA_PATH if domain_mode else TRAINING_DATA_PATH
    suffix = "_domain" if domain_mode else ""

    print(f"[*] Loading {dataset} training data...")
    X, y = load_training_data(path)

    X = X.fillna(0)
    X = X[FEATURE_COLUMNS]

    # Constant columns carry no signal and invite the model to split on noise.
    # On the domain set that drops shodan_blocked, total_open_ports and
    # high_risk_country, all zero across every row by construction.
    dead = [c for c in X.columns if X[c].nunique() <= 1]
    if dead:
        print(f"[!] Dropping {len(dead)} zero-variance feature(s): {dead}")
        X = X.drop(columns=dead)
    trained_columns = list(X.columns)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    mlflow.set_experiment("osint-pivot-engine")

    with mlflow.start_run(run_name=f"isolation_forest{suffix}"):
        print("[*] Training Isolation Forest...")

        iso_forest = IsolationForest(
            contamination=0.2,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(X_train)

        mlflow.log_param("contamination", 0.2)
        mlflow.log_param("n_estimators", 100)
        mlflow.sklearn.log_model(iso_forest, name=f"isolation_forest{suffix}")

        joblib.dump(iso_forest, f"{MODEL_DIR}/isolation_forest{suffix}.joblib")
        print("[+] Isolation Forest trained and saved.")

    with mlflow.start_run(run_name=f"gradient_boosting{suffix}"):
        print("[*] Training Gradient Boosting...")

        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=3,
            random_state=42
        )

        # Compute class weights to compensate for imbalanced dataset
        from sklearn.utils.class_weight import compute_sample_weight
        sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
        gb_model.fit(X_train, y_train, sample_weight=sample_weights)

        y_pred = gb_model.predict(X_test)
        y_prob = gb_model.predict_proba(X_test)[:, 1]
        roc_auc = roc_auc_score(y_test, y_prob)

        mlflow.log_param("n_estimators", 100)
        mlflow.log_param("learning_rate", 0.1)
        mlflow.log_param("max_depth", 3)
        mlflow.log_metric("roc_auc", roc_auc)
        mlflow.sklearn.log_model(gb_model, name=f"gradient_boosting{suffix}")

        joblib.dump(gb_model, f"{MODEL_DIR}/gradient_boosting{suffix}.joblib")
        print(f"[+] Gradient Boosting trained. ROC-AUC: {roc_auc:.4f}")
        print(classification_report(y_test, y_pred))

    # The column list travels with the models. Scoring must build its matrix in
    # the same order and without the dropped columns, and a silent mismatch
    # would be scored rather than raised.
    joblib.dump(trained_columns, f"{MODEL_DIR}/feature_columns{suffix}.joblib")
    print(f"[+] Trained on {len(trained_columns)} features: {trained_columns}")
    print("[+] All models trained and logged to MLflow.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train the scoring models.")
    parser.add_argument("--dataset", choices=("ip", "domain"), default="ip")
    train_models(parser.parse_args().dataset)