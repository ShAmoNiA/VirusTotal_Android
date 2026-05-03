from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


NUMERIC_FEATURES = [
    "size_bytes",
    "positives",
    "total_engines",
    "detection_ratio",
    "times_submitted",
    "unique_sources",
    "community_reputation",
    "malicious_votes",
    "harmless_votes",
    "itw_url_count",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run extra Python analysis over VirusTotal outputs.")
    parser.add_argument("--outputs", type=Path, default=Path("outputs"), help="Project outputs directory.")
    return parser.parse_args()


def add_python_features(samples: pd.DataFrame) -> pd.DataFrame:
    features = samples.copy()
    features["size_mb"] = features["size_bytes"] / (1024 * 1024)
    features["has_itw_urls"] = features["itw_url_count"] > 0
    features["is_repeatedly_submitted"] = features["times_submitted"] > features["times_submitted"].median()
    features["tag_count"] = features["tags"].fillna("").apply(lambda value: len([tag for tag in value.split("|") if tag]))
    features["submission_name_count"] = features["submission_names"].fillna("").apply(
        lambda value: len([name for name in value.split("|") if name])
    )
    features["consensus_band"] = pd.cut(
        features["detection_ratio"],
        bins=[0.0, 0.25, 0.35, 0.50, 1.0],
        labels=["low-medium", "medium", "medium-high", "high"],
        include_lowest=True,
    )
    return features


def plot_size_vs_detection(features: pd.DataFrame, charts_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.8))
    colors = np.where(features["has_itw_urls"], "#c44900", "#376996")
    ax.scatter(features["size_mb"], features["detection_ratio"], c=colors, alpha=0.72, edgecolor="white", linewidth=0.4)
    ax.set_xscale("log")
    ax.set_title("File Size vs Detection Ratio")
    ax.set_xlabel("File size in MB, log scale")
    ax.set_ylabel("Detection ratio")
    ax.grid(True, alpha=0.25)
    fig.tight_layout()
    fig.savefig(charts_dir / "size_vs_detection_ratio.png", dpi=160)
    plt.close(fig)


def plot_submissions_vs_detection(features: pd.DataFrame, charts_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.8))
    x_values = features["times_submitted"].fillna(0).clip(lower=1)
    ax.scatter(x_values, features["detection_ratio"], color="#2f6f5e", alpha=0.72, edgecolor="white", linewidth=0.4)
    ax.set_xscale("log")
    ax.set_title("Submissions vs Detection Ratio")
    ax.set_xlabel("Times submitted, log scale")
    ax.set_ylabel("Detection ratio")
    ax.grid(True, alpha=0.25)
    fig.tight_layout()
    fig.savefig(charts_dir / "submissions_vs_detection_ratio.png", dpi=160)
    plt.close(fig)


def plot_correlation_heatmap(features: pd.DataFrame, charts_dir: Path) -> pd.DataFrame:
    corr = features[NUMERIC_FEATURES].corr(numeric_only=True).round(3)
    fig, ax = plt.subplots(figsize=(8.5, 7))
    image = ax.imshow(corr.values, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(corr.columns)))
    ax.set_yticks(range(len(corr.index)))
    ax.set_xticklabels(corr.columns, rotation=45, ha="right")
    ax.set_yticklabels(corr.index)
    ax.set_title("Correlation Matrix of Numeric Features")
    fig.colorbar(image, ax=ax, shrink=0.78)
    for row in range(len(corr.index)):
        for col in range(len(corr.columns)):
            ax.text(col, row, f"{corr.iloc[row, col]:.2f}", ha="center", va="center", fontsize=7)
    fig.tight_layout()
    fig.savefig(charts_dir / "numeric_feature_correlations.png", dpi=160)
    plt.close(fig)
    return corr


def summarize_by_band(features: pd.DataFrame) -> pd.DataFrame:
    return (
        features.groupby("consensus_band", observed=False)
        .agg(
            samples=("sha256", "count"),
            avg_detection_ratio=("detection_ratio", "mean"),
            avg_size_mb=("size_mb", "mean"),
            avg_times_submitted=("times_submitted", "mean"),
            samples_with_itw_urls=("has_itw_urls", "sum"),
            avg_tag_count=("tag_count", "mean"),
        )
        .reset_index()
        .round(3)
    )


def build_engine_agreement(scans: pd.DataFrame, outputs_dir: Path) -> pd.DataFrame:
    top_engines = (
        scans.groupby("engine")["detected"]
        .sum()
        .sort_values(ascending=False)
        .head(15)
        .index
    )
    matrix = (
        scans[scans["engine"].isin(top_engines)]
        .pivot_table(index="sha256", columns="engine", values="detected", aggfunc="max", fill_value=False)
        .astype(int)
    )
    matrix["top_engine_agreement"] = matrix.sum(axis=1)
    matrix.to_csv(outputs_dir / "top_engine_agreement_matrix.csv")
    return matrix


def markdown_table(frame: pd.DataFrame) -> str:
    headers = list(frame.columns)
    rows = []
    rows.append("| " + " | ".join(headers) + " |")
    rows.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for _, record in frame.iterrows():
        values = [str(record[column]) for column in headers]
        rows.append("| " + " | ".join(values) + " |")
    return "\n".join(rows)


def write_python_summary(features: pd.DataFrame, band_summary: pd.DataFrame, corr: pd.DataFrame, output_path: Path) -> None:
    strongest_corr = (
        corr["detection_ratio"]
        .drop(labels=["detection_ratio"])
        .abs()
        .sort_values(ascending=False)
    )
    top_feature = strongest_corr.index[0]
    top_value = corr.loc[top_feature, "detection_ratio"]
    high_rows = features.sort_values("detection_ratio", ascending=False).head(3)

    lines = [
        "# Python-Generated Extended Analysis",
        "",
        "This section was generated from the normalized CSV files using pandas, numpy, and matplotlib.",
        "",
        "## Feature Engineering",
        "",
        "- `size_mb`: file size converted from bytes to MB.",
        "- `has_itw_urls`: whether VirusTotal reports in-the-wild URL evidence.",
        "- `is_repeatedly_submitted`: whether submissions are above the dataset median.",
        "- `tag_count`: number of VirusTotal tags per sample.",
        "- `consensus_band`: binned detection ratio used for exploratory analysis.",
        "",
        "## Consensus Band Summary",
        "",
        markdown_table(band_summary),
        "",
        "## Correlation Note",
        "",
        f"The numeric feature with the strongest absolute correlation to `detection_ratio` is `{top_feature}` "
        f"with correlation {top_value:.3f}. This is exploratory and should not be interpreted as causation.",
        "",
        "## Three Highest-Consensus Samples",
        "",
    ]
    for _, row in high_rows.iterrows():
        lines.append(
            f"- `{row['sha256']}`: detection ratio {row['detection_ratio']:.3f}, "
            f"{int(row['positives'])}/{int(row['total_engines'])} engines, tags `{row['tags']}`."
        )
    lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    outputs_dir = args.outputs
    charts_dir = outputs_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    samples = pd.read_csv(outputs_dir / "samples_summary.csv")
    scans = pd.read_csv(outputs_dir / "engine_scans_long.csv")

    features = add_python_features(samples)
    features.to_csv(outputs_dir / "python_feature_table.csv", index=False)

    band_summary = summarize_by_band(features)
    band_summary.to_csv(outputs_dir / "consensus_band_summary.csv", index=False)

    plot_size_vs_detection(features, charts_dir)
    plot_submissions_vs_detection(features, charts_dir)
    corr = plot_correlation_heatmap(features, charts_dir)
    corr.to_csv(outputs_dir / "numeric_feature_correlations.csv")
    build_engine_agreement(scans, outputs_dir)

    write_python_summary(features, band_summary, corr, outputs_dir / "python_extended_summary.md")
    print("Advanced Python analysis completed.")


if __name__ == "__main__":
    main()
