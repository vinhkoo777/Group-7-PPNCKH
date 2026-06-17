import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
OUTPUT_DATA_DIR = DATA_DIR / "output"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"

RAW_ALERTS_PATH = Path(os.environ.get("RAW_ALERTS_PATH", RAW_DATA_DIR / "alerts_export.json"))
MLCVE_DATA_DIR = Path(os.environ.get("MLCVE_DATA_DIR", RAW_DATA_DIR / "MachineLearningCVE"))
HYBRID_MLCVE_ENABLED = os.environ.get("HYBRID_MLCVE_ENABLED", "0").lower() in {
    "1",
    "true",
    "yes",
}
MLCVE_MAX_ROWS = int(os.environ.get("MLCVE_MAX_ROWS", "120000"))
PROCESSED_ALERTS_PATH = PROCESSED_DATA_DIR / "alerts_processed.csv"
PRIORITIZED_CSV_PATH = OUTPUT_DATA_DIR / "ai_prioritized_alerts.csv"
PRIORITIZED_JSONL_PATH = OUTPUT_DATA_DIR / "ai_prioritized_alerts.jsonl"
FEEDBACK_PATH = OUTPUT_DATA_DIR / "feedback.csv"
RF_MODEL_PATH = MODELS_DIR / "rf_model.pkl"
IF_MODEL_PATH = MODELS_DIR / "if_model.pkl"
METRICS_REPORT_PATH = REPORTS_DIR / "metrics_report.txt"

RANDOM_STATE = 42
TEST_SIZE = 0.2

STRING_DEFAULT = "unknown"
NUMERIC_DEFAULT = 0

STRING_COLUMNS = [
    "timestamp",
    "rule.description",
    "agent.name",
    "agent.id",
    "manager.name",
    "decoder.name",
    "location",
    "full_log",
    "data.srcip",
    "data.dstip",
    "data.protocol",
    "data.url",
    "data.srcuser",
    "data.command",
    "data.system_name",
    "id",
]

NUMERIC_COLUMNS = [
    "rule.level",
    "rule.firedtimes",
    "data.srcport",
    "data.dstport",
]

CATEGORICAL_FEATURES = [
    "agent_name",
    "decoder_name",
    "location",
    "event_type",
]

NUMERICAL_FEATURES = [
    "rule_level",
    "rule_firedtimes",
    "full_log_length",
    "keyword_attack_score",
    "src_ip_frequency",
    "asset_criticality",
]

OUTPUT_COLUMNS = [
    "alert_id",
    "timestamp",
    "agent_name",
    "src_ip",
    "rule_level",
    "rule_description",
    "decoder_name",
    "location",
    "label",
    "prediction",
    "rf_probability",
    "if_score",
    "norm_novelty_if",
    "anomaly_flag",
    "priority_score",
    "route",
    "severity",
    "feedback_state",
]


def ensure_directories() -> None:
    for directory in [
        RAW_DATA_DIR,
        PROCESSED_DATA_DIR,
        OUTPUT_DATA_DIR,
        MODELS_DIR,
        FIGURES_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
