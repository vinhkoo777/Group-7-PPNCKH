import json

import pandas as pd

from config import NUMERIC_COLUMNS, NUMERIC_DEFAULT, RAW_ALERTS_PATH, STRING_COLUMNS, STRING_DEFAULT


DATASET_MISSING_MESSAGE = (
    "Dataset not found. Please provide your exported Wazuh alerts JSONL file "
    "at data/raw/alerts_export.json."
)


def load_wazuh_alerts(path=RAW_ALERTS_PATH) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(DATASET_MISSING_MESSAGE)

    records = []
    skipped_lines = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip().strip("\x00")
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                skipped_lines.append((line_number, str(exc)))

    if not records:
        raise ValueError("Dataset is empty. Please provide at least one Wazuh alert record.")
    if skipped_lines:
        preview = ", ".join(f"line {line}: {error}" for line, error in skipped_lines[:3])
        print(f"Skipped {len(skipped_lines)} malformed JSONL line(s): {preview}")

    df = pd.json_normalize(records)
    return ensure_expected_columns(df)


def ensure_expected_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    for column in STRING_COLUMNS:
        if column not in df.columns:
            df[column] = STRING_DEFAULT
        df[column] = df[column].fillna(STRING_DEFAULT).astype(str)

    for column in NUMERIC_COLUMNS:
        if column not in df.columns:
            df[column] = NUMERIC_DEFAULT
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(NUMERIC_DEFAULT)

    return df
