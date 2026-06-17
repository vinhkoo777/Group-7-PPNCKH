import pandas as pd


SEVERITY_BY_ROUTE = {
    "high_priority": "high",
    "anomaly_review": "medium",
    "low_priority": "low",
}


def route_single_alert(row: pd.Series) -> str:
    if row["priority_score"] >= 0.80:
        return "high_priority"
    if row["rf_probability"] < 0.60 and row["norm_novelty_if"] >= 0.70:
        return "anomaly_review"
    if 0.50 <= row["priority_score"] < 0.80:
        return "anomaly_review"
    return "low_priority"


def add_routes(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    result["route"] = result.apply(route_single_alert, axis=1)
    result["severity"] = result["route"].map(SEVERITY_BY_ROUTE)
    result["feedback_state"] = "pending"
    return result
