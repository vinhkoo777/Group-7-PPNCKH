# Beyond Classification: An AI-Assisted Alert Prioritization Framework for Wazuh SIEM Using Composite Risk Scoring

Đây là một prototype nghiên cứu cho một framework offline/batch nhằm chấm điểm ưu tiên (prioritize) các cảnh báo Wazuh SIEM đã được export, dựa trên kết hợp giữa machine learning và ngữ cảnh bảo mật theo rule-based.

Framework **không** triển khai real-time re-ingestion vào Wazuh, **không** tạo custom Wazuh rules, và **không** tích hợp Wazuh Dashboard. Dữ liệu đầu vào mong đợi là một file JSON lines (JSON) được export từ Wazuh, thường lấy từ `/var/ossec/logs/alerts/alerts.json`.

## Phạm vi dự án (Project Scope)

Pipeline thực hiện các bước sau:
- Nạp dữ liệu Wazuh alerts export
- Flatten các trường JSON lồng nhau (nested JSON fields)
- Tạo đặc trưng (feature engineering)
- Gán nhãn nghiên cứu (research labels) dựa trên ánh xạ từ nội dung alert
- Huấn luyện mô hình phân loại Random Forest
- Huấn luyện mô hình phát hiện bất thường Isolation Forest
- Tính toán `PriorityScore`
- Định tuyến alert (routing) vào các queue xử lý cho analyst
- Sinh các output phục vụ báo cáo nghiên cứu

## Vị trí đặt dữ liệu (Dataset Placement)

Đặt file Wazuh alerts export dạng JSONL tại đường dẫn sau:
```text
data/raw/alerts_export.json
```

Nếu không tìm thấy file, `python src/main.py` sẽ dừng lại và hiển thị:
```text
Dataset not found. Please provide your exported Wazuh alerts JSONL file at data/raw/alerts_export.json.
```

## Cài đặt (Installation)

```bash
pip install -r requirements.txt
```

## Chạy Pipeline (Run the Pipeline)

```bash
python src/main.py
```

## Output mong đợi (Expected Outputs)

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

## PriorityScore (Composite Risk Scoring)

Prototype tính điểm ưu tiên cho từng alert theo công thức:

```text
PriorityScore =
0.35 * RF_Probability
+ 0.25 * NormNoveltyIF
+ 0.20 * NormRuleLevel
+ 0.10 * RecurrenceSignal
+ 0.10 * AssetCriticality
```

Trong đó:
- `RF_Probability`: xác suất lớn nhất theo nhãn dự đoán của mô hình Random Forest (supervised confidence).
- `NormNoveltyIF`: điểm Isolation Forest âm được chuẩn hóa min-max, giá trị càng cao thể hiện mức độ bất thường càng lớn.
- `NormRuleLevel`: `min(rule_level / 15, 1)`.
- `RecurrenceSignal`: `min(rule_firedtimes / 10, 1)` — phản ánh tần suất lặp lại của alert.
- `AssetCriticality`: bằng `1.0` nếu tên agent chứa các từ khóa `server`, `wazuh`, `dc`, `database`, `db`, hoặc `web`; ngược lại bằng `0.5`.

## Định tuyến cảnh báo (Dynamic Alert Routing)

Alert được định tuyến theo logic:

```text
priority_score >= 0.80
=> high_priority

rf_probability < 0.60 và norm_novelty_if >= 0.70
=> anomaly_review

0.50 <= priority_score < 0.80
=> anomaly_review

còn lại
=> low_priority
```

Mức độ nghiêm trọng (severity) được ánh xạ tương ứng:
- `high_priority` → `high`
- `anomaly_review` → `medium`
- `low_priority` → `low`

## Đánh giá (Evaluation)

Báo cáo (metrics_report.txt) bao gồm:
- Classification report của Random Forest
- Confusion matrix
- Tổng số alert và số lượng alert theo từng queue
- Alert Volume Reduction
- High Priority Precision
- False Positive Count
- Mô phỏng analyst feedback và đề xuất hiệu chỉnh ngưỡng (threshold tuning suggestions)

## Hạn chế (Limitations)

- Nhãn được gán bằng rule-based keyword mapping, chưa phải ground truth đã được analyst xác thực.
- Prototype chỉ phục vụ mục đích đánh giá nghiên cứu offline, chưa dùng cho môi trường SOC production.
- Isolation Forest sử dụng các đặc trưng đã được engineering, không nên xem là bằng chứng xác định (definitive evidence) về việc bị xâm nhập.
- Các ngưỡng (thresholds) hiện tại là giá trị mặc định cố định, cần được hiệu chỉnh thêm dựa trên feedback thật từ analyst.

## Hướng phát triển (Future Work)

- Bổ sung nhãn được analyst xác thực thủ công (manually validated labels).
- Mở rộng feature engineering với ánh xạ kỹ thuật theo MITRE ATT&CK.
- So sánh thêm nhiều mô hình supervised và unsupervised khác.
- Bổ sung temporal aggregation cho các chiến dịch tấn công nhiều giai đoạn (multi-stage attack campaigns).
- Đánh giá khả năng hiệu chỉnh ngưỡng (threshold tuning) trên nhiều tập dữ liệu Wazuh export khác nhau.
