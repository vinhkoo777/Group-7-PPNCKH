# Research Results Using All 8 MachineLearningCVE/CIC-IDS2017 Datasets

## Experimental Setup

The framework was trained and evaluated using the Wazuh exported alert dataset together with all 8 CSV files from `data/raw/MachineLearningCVE`.

- Wazuh dataset: `data/raw/alert_export3.json`
- Wazuh alert records: `358,299`
- MachineLearningCVE/CIC-IDS2017 files used: `8`
- MachineLearningCVE/CIC-IDS2017 records added: `2,830,743`
- Total processed alerts: `3,189,042`

Execution command:

```powershell
$env:RAW_ALERTS_PATH='data/raw/alert_export3.json'
$env:HYBRID_MLCVE_ENABLED='1'
$env:MLCVE_MAX_ROWS='0'
python src\main.py
```

`MLCVE_MAX_ROWS=0` means that the loader uses all available rows instead of balanced sampling.

## Source Distribution

| Source | Records |
|---|---:|
| Wazuh `alert_export3.json` | 358,299 |
| Full 8 MachineLearningCVE/CIC-IDS2017 CSV files | 2,830,743 |
| Total | 3,189,042 |

## Model Classification Performance

The Random Forest classifier produced very high weighted performance:

- Accuracy: approximately `1.00`
- Weighted precision: approximately `1.00`
- Weighted recall: approximately `1.00`
- Weighted F1-score: approximately `1.00`
- Macro F1-score: `0.90`

Per-class performance was strong for large classes such as `Benign`, `PortScan`, `DoS`, `DDoS`, `WebAttack`, `BruteForce`, and `Bot`. Smaller classes such as `Recon` and `SuspiciousProcess` remained weaker because they have very small support compared with the dominant CIC2017 classes.

## Label Distribution

| Label | Count |
|---|---:|
| Benign | 2,293,376 |
| PortScan | 286,467 |
| DoS | 252,661 |
| DDoS | 225,745 |
| WebAttack | 114,500 |
| BruteForce | 14,078 |
| Bot | 1,966 |
| SuspiciousProcess | 164 |
| Recon | 38 |
| Infiltration | 36 |
| Heartbleed | 11 |

The full CIC2017 experiment is highly imbalanced. `Benign` dominates the dataset, while rare attack classes such as `Heartbleed`, `Infiltration`, `Recon`, and `SuspiciousProcess` have very low support.

## Dynamic Alert Routing Results

| Route | Count |
|---|---:|
| low_priority | 1,713,241 |
| anomaly_review | 1,398,336 |
| high_priority | 77,465 |

SOC-oriented metrics:

- Total alerts: `3,189,042`
- High priority count: `77,465`
- Anomaly review count: `1,398,336`
- Low priority count: `1,713,241`
- Alert volume reduction: `0.5372`
- High priority precision: `0.2223`
- False positive count in high priority: `60,248`

Compared with the sampled hybrid run, using the full 8 CIC2017 datasets greatly increased alert volume reduction because many alerts were routed to `low_priority`. However, high-priority precision decreased because many `Benign` records were assigned high PriorityScore.

## Route Distribution by Label

| Label | anomaly_review | high_priority | low_priority |
|---|---:|---:|---:|
| Benign | 519,889 | 60,248 | 1,713,239 |
| Bot | 1,966 | 0 | 0 |
| BruteForce | 14,078 | 0 | 0 |
| DDoS | 225,745 | 0 | 0 |
| DoS | 252,661 | 0 | 0 |
| Heartbleed | 11 | 0 | 0 |
| Infiltration | 36 | 0 | 0 |
| PortScan | 286,467 | 0 | 0 |
| Recon | 28 | 10 | 0 |
| SuspiciousProcess | 138 | 26 | 0 |
| WebAttack | 97,317 | 17,181 | 2 |

The high-priority queue is mostly composed of `Benign` and `WebAttack`. This shows that the current threshold and score weights need tuning when the full CIC2017 distribution is used.

## PriorityScore and Anomaly Evidence

PriorityScore statistics:

- Mean: `0.5397`
- Standard deviation: `0.1004`
- Minimum: `0.4500`
- 25th percentile: `0.4650`
- Median: `0.4919`
- 75th percentile: `0.6178`
- Maximum: `0.9031`

Random Forest probability statistics:

- Mean: `0.9986`
- Median: `1.0000`
- Minimum: `0.3200`

Normalized Isolation Forest novelty statistics:

- Mean: `0.2247`
- Median: `0.1678`
- Maximum: `1.0000`

Isolation Forest anomaly flags:

| Anomaly Flag | Count |
|---|---:|
| 1, normal | 3,029,602 |
| -1, anomaly | 159,440 |

Isolation Forest identified `159,440` anomalous records. This anomaly signal remains useful for routing uncertain or rare events to `anomaly_review`, but the final queue distribution depends strongly on the PriorityScore thresholds.

## Research Interpretation

Using all 8 MachineLearningCVE/CIC-IDS2017 datasets changes the research conclusion in an important way. The framework scales to more than 3.18 million hybrid alerts and still produces the required outputs, models, reports, and plots. It also demonstrates that the system can reduce analyst-facing volume by routing `53.72%` of alerts to `low_priority`.

However, this experiment also exposes a limitation of the current scoring configuration. High-priority precision is only `22.23%`, mainly because `60,248` benign records were routed to `high_priority`. This means the current PriorityScore formula and threshold are too permissive for the full CIC2017 class distribution.

Therefore, the main finding is:

> The framework is scalable and effective for large-batch alert processing, but full CIC2017 usage requires threshold/weight calibration to preserve high-priority precision.

## Threshold Tuning Suggestion

The evaluation module triggered this suggestion:

> High priority false positive rate is above 0.30; suggest increasing the high threshold from 0.80 to 0.85.

For the next experiment, the recommended adjustment is to raise the high-priority threshold and compare:

- Current rule: `priority_score >= 0.80`
- Suggested rule: `priority_score >= 0.85`

The research report should discuss this as evidence that human-in-the-loop feedback and threshold adaptation are necessary when moving from a sampled lab dataset to a full, highly imbalanced benchmark dataset.

## Limitations

- MachineLearningCVE/CIC-IDS2017 flow records are converted into pseudo-Wazuh alerts, so they do not perfectly represent native Wazuh alert semantics.
- Labels are derived from CIC2017 labels and rule-based mapping, not from SOC analyst validation.
- The dataset is highly imbalanced, causing macro metrics and high-priority routing quality to be sensitive to minority classes.
- The current feedback mechanism suggests threshold changes but does not automatically retrain or update thresholds during runtime.
- The system remains an offline/batch research prototype.
