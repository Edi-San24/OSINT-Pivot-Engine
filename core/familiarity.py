# core/familiarity.py
# The familiarity model: marks domains whose features are unlike the classifier's
# training data. Kept apart from core/trainer.py so it imports without MLflow.

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

# Share of training domains treated as unlike the rest. Small on purpose: the
# note is for the rare input the classifier has little basis for, and flagging
# a fifth of everything would make it noise.
FAMILIARITY_CONTAMINATION = 0.02
FAMILIARITY_TREES = 200


def fit_familiarity(X: pd.DataFrame) -> Pipeline:
    """
    An isolation forest over the features the classifier sees, marking the few
    inputs least like its training data. Imputed as the classifier is, so an
    unpublished registration date is not itself unusual.
    """
    return Pipeline([
        ("impute_absent", SimpleImputer(missing_values=-1, strategy="median")),
        ("forest", IsolationForest(contamination=FAMILIARITY_CONTAMINATION,
                                   n_estimators=FAMILIARITY_TREES, random_state=42)),
    ]).fit(X)
