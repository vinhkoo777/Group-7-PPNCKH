import pandas as pd


def min_max_normalize(series: pd.Series) -> pd.Series:
    minimum = series.min()
    maximum = series.max()
    if pd.isna(minimum) or pd.isna(maximum) or maximum == minimum:
        return pd.Series(0.0, index=series.index)
    return (series - minimum) / (maximum - minimum)


def add_priority_score(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    result["norm_rule_level"] = (result["rule_level"] / 15).clip(upper=1)
    result["recurrence_signal"] = (result["rule_firedtimes"] / 10).clip(upper=1)

    novelty_raw = -result["if_score"]
    result["norm_novelty_if"] = min_max_normalize(novelty_raw)

    result["priority_score"] = (
        0.35 * result["rf_probability"]
        + 0.25 * result["norm_novelty_if"]
        + 0.20 * result["norm_rule_level"]
        + 0.10 * result["recurrence_signal"]
        + 0.10 * result["asset_criticality"]
    )
    result["priority_score"] = result["priority_score"].clip(lower=0, upper=1)
    return result
