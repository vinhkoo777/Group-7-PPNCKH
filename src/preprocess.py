import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from config import CATEGORICAL_FEATURES, NUMERICAL_FEATURES, PROCESSED_ALERTS_PATH
from label_mapping import keyword_attack_score, map_label, normalize_text


CRITICAL_ASSET_TERMS = ["server", "wazuh", "dc", "database", "db", "web"]


def build_processed_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    processed = pd.DataFrame()
    processed["alert_id"] = df["id"].astype(str)
    processed["timestamp"] = df["timestamp"].astype(str)
    processed["rule_level"] = pd.to_numeric(df["rule.level"], errors="coerce").fillna(0)
    processed["rule_firedtimes"] = pd.to_numeric(df["rule.firedtimes"], errors="coerce").fillna(0)
    processed["rule_description"] = df["rule.description"].astype(str)
    processed["agent_name"] = df["agent.name"].astype(str)
    processed["agent_id"] = df["agent.id"].astype(str)
    processed["manager_name"] = df["manager.name"].astype(str)
    processed["decoder_name"] = df["decoder.name"].astype(str)
    processed["location"] = df["location"].astype(str)
    processed["full_log"] = df["full_log"].astype(str)
    processed["src_ip"] = df["data.srcip"].astype(str)
    processed["dst_ip"] = df["data.dstip"].astype(str)
    processed["src_port"] = pd.to_numeric(df["data.srcport"], errors="coerce").fillna(0)
    processed["dst_port"] = pd.to_numeric(df["data.dstport"], errors="coerce").fillna(0)
    processed["protocol"] = df["data.protocol"].astype(str)
    processed["url"] = df["data.url"].astype(str)
    processed["src_user"] = df["data.srcuser"].astype(str)
    processed["command"] = df["data.command"].astype(str)
    processed["system_name"] = df["data.system_name"].astype(str)

    text = processed.apply(
        lambda row: normalize_text(
            row["full_log"],
            row["rule_description"],
            row["decoder_name"],
            row["location"],
            row["url"],
            row["src_user"],
            row["command"],
            row["system_name"],
        ),
        axis=1,
    )
    processed["combined_text"] = text
    processed["full_log_length"] = processed["full_log"].str.len().fillna(0)
    processed["keyword_attack_score"] = text.apply(keyword_attack_score)
    processed["src_ip_frequency"] = processed.groupby("src_ip")["src_ip"].transform("count")
    processed["asset_criticality"] = processed["agent_name"].apply(calculate_asset_criticality)
    processed["event_type"] = np.where(
        processed["decoder_name"].str.lower().ne("unknown"),
        processed["decoder_name"],
        processed["location"],
    )
    processed["label"] = text.apply(map_label)

    return processed


def calculate_asset_criticality(agent_name: str) -> float:
    lowered = str(agent_name).lower()
    if any(term in lowered for term in CRITICAL_ASSET_TERMS):
        return 1.0
    return 0.5


def make_feature_preprocessor() -> ColumnTransformer:
    try:
        encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        encoder = OneHotEncoder(handle_unknown="ignore", sparse=False)

    return ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERICAL_FEATURES),
            ("cat", encoder, CATEGORICAL_FEATURES),
        ],
        remainder="drop",
    )


def make_model_pipeline(model) -> Pipeline:
    return Pipeline(
        steps=[
            ("preprocess", make_feature_preprocessor()),
            ("model", model),
        ]
    )


def save_processed_alerts(df: pd.DataFrame, path=PROCESSED_ALERTS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
