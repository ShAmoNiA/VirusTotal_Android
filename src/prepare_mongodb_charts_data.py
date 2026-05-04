"""Prepare chart-ready datasets for MongoDB Charts / Atlas Charts.

MongoDB Charts can visualize the raw collections directly, but small aggregated
collections make the dashboard easier to build and faster to render. This
script creates those summaries from the normalized Python outputs.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create chart-ready VirusTotal summary tables.")
    parser.add_argument("--outputs", type=Path, default=Path("outputs"), help="Project outputs directory.")
    return parser.parse_args()


def split_tags(samples: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, sample in samples.iterrows():
        tags = str(sample.get("tags", "")).split("|")
        for tag in tags:
            if tag:
                rows.append(
                    {
                        "sha256": sample["sha256"],
                        "tag": tag,
                        "detection_ratio": sample["detection_ratio"],
                        "risk_category": sample["risk_category"],
                        "size_bytes": sample["size_bytes"],
                    }
                )
    return pd.DataFrame(rows)


def build_chart_tables(outputs_dir: Path) -> dict[str, pd.DataFrame]:
    samples = pd.read_csv(outputs_dir / "samples_summary.csv")
    scans = pd.read_csv(outputs_dir / "engine_scans_long.csv")
    terms = pd.read_csv(outputs_dir / "top_detection_terms.csv")
    tags_long = split_tags(samples)

    risk_distribution = (
        samples.groupby("risk_category")
        .agg(
            samples=("sha256", "count"),
            avg_detection_ratio=("detection_ratio", "mean"),
            avg_size_mb=("size_bytes", lambda values: values.mean() / (1024 * 1024)),
        )
        .reset_index()
        .sort_values("samples", ascending=False)
        .round(4)
    )

    top_engines = (
        scans.groupby("engine")
        .agg(
            samples_seen=("sha256", "count"),
            detections=("detected", "sum"),
        )
        .reset_index()
    )
    top_engines["detection_rate"] = top_engines["detections"] / top_engines["samples_seen"]
    top_engines = top_engines.sort_values(["detections", "detection_rate"], ascending=False).head(20).round(4)

    tag_consensus = (
        tags_long.groupby("tag")
        .agg(
            samples=("sha256", "count"),
            avg_detection_ratio=("detection_ratio", "mean"),
            avg_size_mb=("size_bytes", lambda values: values.mean() / (1024 * 1024)),
        )
        .reset_index()
    )
    tag_consensus = tag_consensus[tag_consensus["samples"] >= 2]
    tag_consensus = tag_consensus.sort_values(["avg_detection_ratio", "samples"], ascending=False).round(4)

    detection_scatter = samples[
        [
            "sha256",
            "size_bytes",
            "positives",
            "total_engines",
            "detection_ratio",
            "risk_category",
            "times_submitted",
            "itw_url_count",
            "tags",
        ]
    ].copy()
    detection_scatter["size_mb"] = detection_scatter["size_bytes"] / (1024 * 1024)
    detection_scatter["has_itw_urls"] = detection_scatter["itw_url_count"] > 0
    detection_scatter = detection_scatter.round({"detection_ratio": 4, "size_mb": 4})

    terms = terms.rename(columns={"term": "detection_term"})
    terms = terms.sort_values("count", ascending=False).head(20)

    return {
        "chart_risk_distribution": risk_distribution,
        "chart_top_engines": top_engines,
        "chart_tag_consensus": tag_consensus,
        "chart_detection_scatter": detection_scatter,
        "chart_detection_terms": terms,
    }


def main() -> None:
    args = parse_args()
    chart_dir = args.outputs / "mongodb_charts"
    chart_dir.mkdir(parents=True, exist_ok=True)

    tables = build_chart_tables(args.outputs)
    for name, table in tables.items():
        table.to_csv(chart_dir / f"{name}.csv", index=False)
        table.to_json(chart_dir / f"{name}.json", orient="records", indent=2)

    print(f"Prepared {len(tables)} chart-ready datasets in {chart_dir.resolve()}.")


if __name__ == "__main__":
    main()
