import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split

from config import (
    RANDOM_STATE,
    TEST_SIZE,
    IF_MODEL_PATH,
    RF_MODEL_PATH,
)
from preprocess import make_model_pipeline


def can_stratify(y: pd.Series) -> bool:
    counts = y.value_counts()
    return len(counts) > 1 and counts.min() >= 2


def train_random_forest(processed: pd.DataFrame):
    x = processed.copy()
    y = processed["label"]
    stratify = y if can_stratify(y) else None

    if len(processed) < 2 or y.nunique() < 2:
        train_df = test_df = x
        y_train = y_test = y
    else:
        train_df, test_df, y_train, y_test = train_test_split(
            x,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=stratify,
        )

    rf = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )
    pipeline = make_model_pipeline(rf)
    pipeline.fit(train_df, y_train)

    RF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, RF_MODEL_PATH)
    return pipeline, test_df, y_test


def add_random_forest_outputs(processed: pd.DataFrame, rf_pipeline) -> pd.DataFrame:
    result = processed.copy()
    result["prediction"] = rf_pipeline.predict(result)

    probabilities = rf_pipeline.predict_proba(result)
    result["rf_probability"] = probabilities.max(axis=1)
    return result


def train_isolation_forest(processed: pd.DataFrame):
    isolation_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=RANDOM_STATE,
    )
    model = make_model_pipeline(isolation_forest)
    model.fit(processed)

    IF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, IF_MODEL_PATH)
    return model


def add_isolation_forest_outputs(processed: pd.DataFrame, if_model) -> pd.DataFrame:
    result = processed.copy()
    result["if_score"] = if_model.decision_function(result)
    result["anomaly_flag"] = if_model.predict(result)
    return result
