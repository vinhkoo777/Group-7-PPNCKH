import pandas as pd

from config import FEEDBACK_PATH


FEEDBACK_TYPES = [
    "confirm_malicious",
    "downgrade_false_positive",
    "escalate_suspicious",
    "needs_investigation",
]


def ensure_feedback_file(alerts: pd.DataFrame, path=FEEDBACK_PATH) -> None:
    if path.exists():
        existing = pd.read_csv(path, dtype={"alert_id": str}, low_memory=False)
        if "alert_id" in existing.columns and set(existing["alert_id"].astype(str)) == set(
            alerts["alert_id"].astype(str)
        ):
            return

    path.parent.mkdir(parents=True, exist_ok=True)
    feedback = alerts[["alert_id", "route", "label"]].copy()
    feedback["feedback_type"] = "needs_investigation"
    feedback["analyst_comment"] = ""
    feedback.to_csv(path, index=False)


def generate_tuning_suggestions(alerts: pd.DataFrame) -> list[str]:
    suggestions = []
    high_priority = alerts[alerts["route"] == "high_priority"]
    high_fp = high_priority[high_priority["label"] == "Benign"]
    high_fp_rate = len(high_fp) / len(high_priority) if len(high_priority) else 0

    missed_suspicious = alerts[
        (alerts["route"] == "low_priority") & (alerts["label"] != "Benign")
    ]
    missed_rate = len(missed_suspicious) / len(alerts) if len(alerts) else 0

    if high_fp_rate > 0.30:
        suggestions.append(
            "High priority false positive rate is above 0.30; suggest increasing "
            "the high threshold from 0.80 to 0.85."
        )
    if missed_rate > 0.10:
        suggestions.append(
            "Missed suspicious alerts in low_priority are elevated; suggest lowering "
            "the anomaly threshold from 0.50 to 0.45."
        )
    if not suggestions:
        suggestions.append("No threshold tuning suggestion triggered by current rules.")

    return suggestions
