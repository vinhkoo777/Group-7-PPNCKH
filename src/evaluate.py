import os

from config import PROJECT_ROOT

MPL_CACHE_DIR = PROJECT_ROOT / ".matplotlib_cache"
MPL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
for lock_file in MPL_CACHE_DIR.glob("*.matplotlib-lock"):
    try:
        lock_file.unlink()
    except OSError:
        pass

os.environ.setdefault("MPLCONFIGDIR", str(MPL_CACHE_DIR))

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from config import FIGURES_DIR, METRICS_REPORT_PATH
from feedback_tuning import generate_tuning_suggestions


def evaluate_and_report(alerts: pd.DataFrame, rf_pipeline, test_df: pd.DataFrame, y_test: pd.Series) -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    y_pred = rf_pipeline.predict(test_df)
    labels = sorted(pd.Series(y_test).astype(str).unique().tolist())
    matrix = confusion_matrix(y_test, y_pred, labels=labels)

    total_alerts = len(alerts)
    high_priority_count = int((alerts["route"] == "high_priority").sum())
    anomaly_review_count = int((alerts["route"] == "anomaly_review").sum())
    low_priority_count = int((alerts["route"] == "low_priority").sum())
    alert_volume_reduction = 1 - (
        (high_priority_count + anomaly_review_count) / total_alerts
    ) if total_alerts else 0

    high_priority = alerts[alerts["route"] == "high_priority"]
    high_non_benign = high_priority[high_priority["label"] != "Benign"]
    high_priority_precision = len(high_non_benign) / len(high_priority) if len(high_priority) else 0
    false_positive_count = int(
        ((alerts["route"] == "high_priority") & (alerts["label"] == "Benign")).sum()
    )

    write_metrics_report(
        y_test,
        y_pred,
        labels,
        matrix,
        total_alerts,
        high_priority_count,
        anomaly_review_count,
        low_priority_count,
        alert_volume_reduction,
        high_priority_precision,
        false_positive_count,
        generate_tuning_suggestions(alerts),
    )

    plot_attack_distribution(alerts)
    plot_priority_score_distribution(alerts)
    plot_route_distribution(alerts)
    plot_confusion_matrix(matrix, labels)


def write_metrics_report(
    y_test,
    y_pred,
    labels,
    matrix,
    total_alerts,
    high_priority_count,
    anomaly_review_count,
    low_priority_count,
    alert_volume_reduction,
    high_priority_precision,
    false_positive_count,
    tuning_suggestions,
) -> None:
    report = classification_report(y_test, y_pred, zero_division=0)
    lines = [
        "Adaptive AI-Assisted Alert Prioritization Metrics Report",
        "=" * 62,
        "",
        "1. Random Forest classification report",
        report,
        "",
        "2. Confusion matrix",
        f"Labels: {labels}",
        np.array2string(matrix),
        "",
        "3. SOC-oriented metrics",
        f"total_alerts: {total_alerts}",
        f"high_priority_count: {high_priority_count}",
        f"anomaly_review_count: {anomaly_review_count}",
        f"low_priority_count: {low_priority_count}",
        f"alert_volume_reduction: {alert_volume_reduction:.4f}",
        "",
        "4. High priority precision",
        f"high_priority_precision: {high_priority_precision:.4f}",
        "",
        "5. False positive count",
        f"false_positive_count: {false_positive_count}",
        "",
        "6. Analyst override simulation and feedback tuning",
        *tuning_suggestions,
    ]
    METRICS_REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


def plot_attack_distribution(alerts: pd.DataFrame) -> None:
    counts = alerts["label"].value_counts()
    plt.figure(figsize=(8, 5))
    counts.plot(kind="bar", color="#4c78a8")
    plt.title("Attack Distribution")
    plt.xlabel("Label")
    plt.ylabel("Alert Count")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "attack_distribution.png")
    plt.close()


def plot_priority_score_distribution(alerts: pd.DataFrame) -> None:
    plt.figure(figsize=(8, 5))
    plt.hist(alerts["priority_score"], bins=20, color="#f58518", edgecolor="black")
    plt.title("Priority Score Distribution")
    plt.xlabel("PriorityScore")
    plt.ylabel("Alert Count")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "priority_score_distribution.png")
    plt.close()


def plot_route_distribution(alerts: pd.DataFrame) -> None:
    counts = alerts["route"].value_counts()
    plt.figure(figsize=(8, 5))
    counts.plot(kind="bar", color="#54a24b")
    plt.title("Route Distribution")
    plt.xlabel("Route")
    plt.ylabel("Alert Count")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "route_distribution.png")
    plt.close()


def plot_confusion_matrix(matrix, labels) -> None:
    plt.figure(figsize=(7, 6))
    plt.imshow(matrix, interpolation="nearest", cmap="Blues")
    plt.title("Confusion Matrix")
    plt.colorbar()
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels, rotation=45, ha="right")
    plt.yticks(tick_marks, labels)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")

    threshold = matrix.max() / 2 if matrix.size and matrix.max() else 0
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            color = "white" if matrix[i, j] > threshold else "black"
            plt.text(j, i, str(matrix[i, j]), ha="center", va="center", color=color)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "confusion_matrix.png")
    plt.close()
