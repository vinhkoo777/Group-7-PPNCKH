from pathlib import Path

import pandas as pd

from config import MLCVE_MAX_ROWS, NUMERIC_COLUMNS, STRING_COLUMNS


CHUNKSIZE = 50000

KEY_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "Label",
]

RULE_LEVEL_BY_CATEGORY = {
    "Benign": 3,
    "BruteForce": 10,
    "WebAttack": 11,
    "PortScan": 10,
    "DDoS": 12,
    "DoS": 11,
    "Bot": 10,
    "Infiltration": 12,
    "Heartbleed": 13,
    "SuspiciousProcess": 9,
}


def load_machine_learning_cve_alerts(data_dir: Path, max_rows: int = MLCVE_MAX_ROWS) -> pd.DataFrame:
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No MachineLearningCVE CSV files found in {data_dir}")

    if max_rows <= 0:
        sampled = load_all_rows(files)
    else:
        sampled = sample_balanced_rows(files, max_rows)
    if sampled.empty:
        raise ValueError(f"No MachineLearningCVE records could be loaded from {data_dir}")

    return convert_flows_to_wazuh_like_alerts(sampled)


def load_all_rows(files: list[Path]) -> pd.DataFrame:
    parts = []
    for file_path in files:
        for chunk in pd.read_csv(file_path, chunksize=CHUNKSIZE, low_memory=False):
            chunk.columns = chunk.columns.str.strip()
            chunk = chunk[[column for column in KEY_COLUMNS if column in chunk.columns]].copy()
            if "Label" not in chunk.columns:
                continue

            chunk["Label"] = chunk["Label"].astype(str).str.strip()
            chunk["source_file"] = file_path.name
            parts.append(chunk)

    if not parts:
        return pd.DataFrame()
    return pd.concat(parts, ignore_index=True)


def sample_balanced_rows(files: list[Path], max_rows: int) -> pd.DataFrame:
    per_label_cap = max(max_rows // 16, 1)
    samples_by_label: dict[str, list[pd.DataFrame]] = {}
    counts_by_label: dict[str, int] = {}

    for file_path in files:
        for chunk_index, chunk in enumerate(pd.read_csv(file_path, chunksize=CHUNKSIZE, low_memory=False)):
            chunk.columns = chunk.columns.str.strip()
            chunk = chunk[[column for column in KEY_COLUMNS if column in chunk.columns]].copy()
            if "Label" not in chunk.columns:
                continue

            chunk["Label"] = chunk["Label"].astype(str).str.strip()
            chunk["source_file"] = file_path.name
            for label, group in chunk.groupby("Label", dropna=False):
                current = counts_by_label.get(label, 0)
                remaining = per_label_cap - current
                if remaining <= 0:
                    continue

                take = min(len(group), remaining)
                if take < len(group):
                    group = group.sample(n=take, random_state=42 + chunk_index)

                samples_by_label.setdefault(label, []).append(group)
                counts_by_label[label] = current + len(group)

    parts = [part for label_parts in samples_by_label.values() for part in label_parts]
    if not parts:
        return pd.DataFrame()

    sampled = pd.concat(parts, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=42).reset_index(drop=True)
    return sampled.reset_index(drop=True)


def convert_flows_to_wazuh_like_alerts(flows: pd.DataFrame) -> pd.DataFrame:
    converted = pd.DataFrame(index=flows.index)
    canonical_labels = flows["Label"].apply(canonicalize_label)
    rule_levels = canonical_labels.map(RULE_LEVEL_BY_CATEGORY).fillna(9).astype(int)

    converted["timestamp"] = "unknown"
    converted["rule.description"] = canonical_labels.apply(
        lambda label: f"MachineLearningCVE network flow classified as {label}"
    )
    converted["rule.level"] = rule_levels
    converted["rule.firedtimes"] = 1
    converted["agent.name"] = "MachineLearningCVE"
    converted["agent.id"] = "mlcve"
    converted["manager.name"] = "hybrid-dataset"
    converted["decoder.name"] = "mlcve-flow"
    converted["location"] = flows["source_file"].astype(str)
    converted["full_log"] = flows.apply(build_full_log, axis=1)
    converted["data.srcip"] = canonical_labels.apply(lambda label: f"mlcve-{label.lower()}")
    converted["data.dstip"] = "unknown"
    converted["data.protocol"] = "flow"
    converted["data.url"] = "unknown"
    converted["data.srcuser"] = "unknown"
    converted["data.command"] = "unknown"
    converted["data.system_name"] = "MachineLearningCVE"
    converted["id"] = [f"mlcve-{i}" for i in range(len(flows))]
    converted["data.srcport"] = 0
    converted["data.dstport"] = pd.to_numeric(
        flows.get("Destination Port", 0),
        errors="coerce",
    ).fillna(0)

    for column in STRING_COLUMNS:
        if column not in converted.columns:
            converted[column] = "unknown"
        converted[column] = converted[column].fillna("unknown").astype(str)

    for column in NUMERIC_COLUMNS:
        if column not in converted.columns:
            converted[column] = 0
        converted[column] = pd.to_numeric(converted[column], errors="coerce").fillna(0)

    return converted


def canonicalize_label(label: str) -> str:
    normalized = str(label).strip().lower()
    if normalized == "benign":
        return "Benign"
    if "web attack" in normalized or "sql injection" in normalized or "xss" in normalized:
        return "WebAttack"
    if "patator" in normalized or "brute force" in normalized:
        return "BruteForce"
    if "portscan" in normalized or "port scan" in normalized:
        return "PortScan"
    if "ddos" in normalized:
        return "DDoS"
    if normalized.startswith("dos") or "slowloris" in normalized or "hulk" in normalized:
        return "DoS"
    if "bot" in normalized:
        return "Bot"
    if "infiltration" in normalized:
        return "Infiltration"
    if "heartbleed" in normalized:
        return "Heartbleed"
    return "SuspiciousProcess"


def build_full_log(row: pd.Series) -> str:
    label = canonicalize_label(row.get("Label", "unknown"))
    metrics = [
        f"dst_port={row.get('Destination Port', 'unknown')}",
        f"flow_duration={row.get('Flow Duration', 'unknown')}",
        f"fwd_packets={row.get('Total Fwd Packets', 'unknown')}",
        f"bwd_packets={row.get('Total Backward Packets', 'unknown')}",
        f"flow_bytes_s={row.get('Flow Bytes/s', 'unknown')}",
        f"flow_packets_s={row.get('Flow Packets/s', 'unknown')}",
        f"syn_flags={row.get('SYN Flag Count', 'unknown')}",
        f"ack_flags={row.get('ACK Flag Count', 'unknown')}",
        f"source_file={row.get('source_file', 'unknown')}",
    ]
    return f"MachineLearningCVE label={label} " + " ".join(metrics)
