import pandas as pd

from config import (
    HYBRID_MLCVE_ENABLED,
    MLCVE_DATA_DIR,
    OUTPUT_COLUMNS,
    PRIORITIZED_CSV_PATH,
    PRIORITIZED_JSONL_PATH,
    ensure_directories,
)
from evaluate import evaluate_and_report
from feedback_tuning import ensure_feedback_file
from load_machine_learning_cve import load_machine_learning_cve_alerts
from load_data import DATASET_MISSING_MESSAGE, load_wazuh_alerts
from preprocess import build_processed_dataframe, save_processed_alerts
from priority_score import add_priority_score
from route_alerts import add_routes
from train_models import (
    add_isolation_forest_outputs,
    add_random_forest_outputs,
    train_isolation_forest,
    train_random_forest,
)


def main() -> int:
    ensure_directories()

    try:
        raw_alerts = load_wazuh_alerts()
    except FileNotFoundError:
        print(DATASET_MISSING_MESSAGE)
        return 1
    except ValueError as exc:
        print(exc)
        return 1

    if HYBRID_MLCVE_ENABLED:
        try:
            mlcve_alerts = load_machine_learning_cve_alerts(MLCVE_DATA_DIR)
        except (FileNotFoundError, ValueError) as exc:
            print(exc)
            return 1

        raw_alerts = pd.concat([raw_alerts, mlcve_alerts], ignore_index=True)
        print(f"Hybrid MachineLearningCVE records added: {len(mlcve_alerts)}")

    processed = build_processed_dataframe(raw_alerts)
    save_processed_alerts(processed)

    rf_pipeline, test_df, y_test = train_random_forest(processed)
    prioritized = add_random_forest_outputs(processed, rf_pipeline)

    if_model = train_isolation_forest(prioritized)
    prioritized = add_isolation_forest_outputs(prioritized, if_model)
    prioritized = add_priority_score(prioritized)
    prioritized = add_routes(prioritized)

    output = prioritized[OUTPUT_COLUMNS].copy()
    PRIORITIZED_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(PRIORITIZED_CSV_PATH, index=False)
    output.to_json(PRIORITIZED_JSONL_PATH, orient="records", lines=True)

    ensure_feedback_file(output)
    evaluate_and_report(prioritized, rf_pipeline, test_df, y_test)

    print("Pipeline completed successfully.")
    print(f"Processed alerts: {len(output)}")
    print(f"CSV output: {PRIORITIZED_CSV_PATH}")
    print(f"JSONL output: {PRIORITIZED_JSONL_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
