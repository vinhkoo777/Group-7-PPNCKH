# Adaptive AI-Assisted Alert Prioritization for Wazuh Alerts

This project is a research prototype for an offline/batch framework that prioritizes exported Wazuh SIEM alerts using machine learning and rule-based security context.

It does not implement real-time Wazuh re-ingestion, custom Wazuh rules, or Wazuh dashboard integration. The intended input is a JSON lines export from Wazuh, commonly from `/var/ossec/logs/alerts/alerts.json`.

## Project Scope

The pipeline loads exported Wazuh alerts, flattens nested JSON fields, creates features, maps alert text into research labels, trains a Random Forest classifier, trains an Isolation Forest anomaly model, calculates `PriorityScore`, routes alerts into analyst queues, and generates outputs for a research report.

## Dataset Placement

Place the exported Wazuh JSONL file here:

```text
data/raw/alerts_export.json
```

If the file is missing, `python src/main.py` stops with:

```text
Dataset not found. Please provide your exported Wazuh alerts JSONL file at data/raw/alerts_export.json.
```

## Installation

```bash
pip install -r requirements.txt
```

## Run the Pipeline

```bash
python src/main.py
```

## Expected Outputs

```text
data/processed/alerts_processed.csv
models/rf_model.pkl
models/if_model.pkl
data/output/ai_prioritized_alerts.csv
data/output/ai_prioritized_alerts.jsonl
data/output/feedback.csv
reports/metrics_report.txt
reports/figures/attack_distribution.png
reports/figures/priority_score_distribution.png
reports/figures/route_distribution.png
reports/figures/confusion_matrix.png
```

## PriorityScore

The prototype calculates:

```text
PriorityScore =
0.35 * RF_Probability
+ 0.25 * NormNoveltyIF
+ 0.20 * NormRuleLevel
+ 0.10 * RecurrenceSignal
+ 0.10 * AssetCriticality
```

Where:

- `RF_Probability` is the maximum Random Forest class probability.
- `NormNoveltyIF` is min-max normalized negative Isolation Forest score, where higher means more anomalous.
- `NormRuleLevel` is `min(rule_level / 15, 1)`.
- `RecurrenceSignal` is `min(rule_firedtimes / 10, 1)`.
- `AssetCriticality` is `1.0` for agent names containing `server`, `wazuh`, `dc`, `database`, `db`, or `web`; otherwise `0.5`.

## Alert Routing

Alerts are routed as:

```text
priority_score >= 0.80
=> high_priority

rf_probability < 0.60 and norm_novelty_if >= 0.70
=> anomaly_review

0.50 <= priority_score < 0.80
=> anomaly_review

otherwise
=> low_priority
```

Severity is mapped as:

- `high_priority` -> `high`
- `anomaly_review` -> `medium`
- `low_priority` -> `low`

## Evaluation

The report includes:

- Random Forest classification report.
- Confusion matrix.
- Total alerts and queue counts.
- Alert volume reduction.
- High priority precision.
- False positive count.
- Simple analyst feedback and threshold tuning suggestions.

## Limitations

- Labels are generated from rule-based keyword mapping, not verified analyst ground truth.
- The prototype is intended for offline research evaluation only.
- Isolation Forest uses engineered features and should not be treated as definitive evidence of compromise.
- Thresholds are fixed defaults and should be tuned with real analyst feedback.

## Future Work

- Add manually validated analyst labels.
- Expand feature engineering with MITRE ATT&CK technique mappings.
- Compare more supervised and unsupervised models.
- Add temporal aggregation for multi-stage attack campaigns.
- Evaluate threshold tuning across multiple exported Wazuh datasets.
