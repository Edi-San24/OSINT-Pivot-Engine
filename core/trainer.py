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
    # No synthetic fallback. It existed to keep the trainer runnable before any
    # data was collected, and it silently produced a model fitted to invented
    # numbers that looked exactly like a real one on disk.
    raise FileNotFoundError(
        f"No training data at {path}. Collect some with "
        "scripts/collect_training_data.py, or pass --data."
    )

def train_models(
    dataset: str = "domain",
    exclude: list | None = None,
    tag: str = "",
    data_path: str | None = None,
):
    """
    Trains Isolation Forest and Gradient Boosting models.
    Logs all experiments and registers models with MLflow.

    Domains are the only type with a model. Addresses, URLs and hashes are
    scored from feed evidence by ConfidenceScorer, so nothing loads a model
    trained on them.

    exclude drops named features before fitting, for comparing variants on one
    dataset. tag keeps each variant in its own model files — placed before
    "_domain" so the result still matches the ignore rule that keeps domain
    models local.
    """
    domain_mode = dataset == "domain"
    path = data_path or (DOMAIN_TRAINING_DATA_PATH if domain_mode else TRAINING_DATA_PATH)
    suffix = f"_{tag}" if tag else ""
    suffix = f"{suffix}_domain" if domain_mode else suffix

    print(f"[*] Loading {dataset} training data...")
    X, y = load_training_data(path)

    X = X.fillna(0)
    X = X[FEATURE_COLUMNS]

    if exclude:
        unknown = [c for c in exclude if c not in X.columns]
        if unknown:
            raise ValueError(f"Cannot exclude unknown feature(s): {unknown}")
        X = X.drop(columns=list(exclude))
        print(f"[!] Excluded {len(exclude)} feature(s): {list(exclude)}")

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

        # Printed because the split is the finding, not the score. An ROC-AUC of
        # 1.0000 next to one feature at 0.90 importance is a leak, not a result.
        print("[*] Feature importances:")
        ranked = sorted(
            zip(trained_columns, gb_model.feature_importances_),
            key=lambda pair: pair[1], reverse=True,
        )
        for name, importance in ranked:
            print(f"      {name:20} {importance:.4f}")

    # The column list travels with the models. Scoring must build its matrix in
    # the same order and without the dropped columns, and a silent mismatch
    # would be scored rather than raised.
    joblib.dump(trained_columns, f"{MODEL_DIR}/feature_columns{suffix}.joblib")
    print(f"[+] Trained on {len(trained_columns)} features: {trained_columns}")
    print("[+] All models trained and logged to MLflow.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train the scoring models.")
    # Only domains have a model. Addresses, URLs and hashes are scored from feed
    # evidence by ConfidenceScorer, so training an IP model produces something
    # nothing loads.
    parser.add_argument("--dataset", choices=("domain",), default="domain")
    parser.add_argument(
        "--exclude", default="",
        help="Comma-separated features to drop before fitting.",
    )
    parser.add_argument("--tag", default="", help="Names the variant's model files.")
    parser.add_argument("--data", help="Dataset CSV to train on.")
    args = parser.parse_args()

    train_models(
        args.dataset,
        exclude=[c.strip() for c in args.exclude.split(",") if c.strip()],
        tag=args.tag,
        data_path=args.data,
    )