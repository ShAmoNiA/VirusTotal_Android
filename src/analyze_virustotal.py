from __future__ import annotations

import argparse
import csv
import json
import math
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


STOP_TERMS = {
    "android",
    "androidos",
    "andr",
    "trojan",
    "variant",
    "generic",
    "heur",
    "virus",
    "score",
    "gen",
    "agent",
    "malware",
    "malicious",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze VTAndroid VirusTotal reports.")
    parser.add_argument(
        "--zip",
        type=Path,
        default=Path("..") / "Python for Data Science" / "VTAndroid.zip",
        help="Path to VTAndroid.zip.",
    )
    parser.add_argument(
        "--outputs",
        type=Path,
        default=Path("outputs"),
        help="Directory where CSV, JSON, and chart outputs will be written.",
    )
    return parser.parse_args()


def risk_category(detection_ratio: float) -> str:
    if detection_ratio >= 0.50:
        return "high-confidence malicious"
    if detection_ratio >= 0.10:
        return "suspicious"
    return "low consensus"


def family_terms(result: str | None) -> list[str]:
    if not result:
        return []
    terms = []
    for token in re.split(r"[^A-Za-z0-9]+", result.lower()):
        if len(token) >= 4 and token not in STOP_TERMS:
            terms.append(token)
    return terms


def load_reports(zip_path: Path) -> tuple[pd.DataFrame, pd.DataFrame, Counter[str], Counter[str]]:
    sample_rows: list[dict[str, Any]] = []
    scan_rows: list[dict[str, Any]] = []
    tag_counter: Counter[str] = Counter()
    term_counter: Counter[str] = Counter()

    with zipfile.ZipFile(zip_path) as archive:
        json_names = sorted(name for name in archive.namelist() if name.endswith(".json"))
        for name in json_names:
            report = json.loads(archive.read(name).decode("utf-8"))
            positives = int(report.get("positives") or 0)
            total = int(report.get("total") or len(report.get("scans", {})) or 0)
            detection_ratio = positives / total if total else math.nan
            tags = report.get("tags") or []
            itw_urls = report.get("ITW_urls") or []

            for tag in tags:
                tag_counter[tag] += 1

            sample_rows.append(
                {
                    "sha256": report.get("sha256"),
                    "sha1": report.get("sha1"),
                    "md5": report.get("md5"),
                    "vhash": report.get("vhash"),
                    "file_type": report.get("type"),
                    "size_bytes": report.get("size"),
                    "first_seen": report.get("first_seen"),
                    "last_seen": report.get("last_seen"),
                    "scan_date": report.get("scan_date"),
                    "positives": positives,
                    "total_engines": total,
                    "detection_ratio": detection_ratio,
                    "risk_category": risk_category(detection_ratio),
                    "times_submitted": report.get("times_submitted"),
                    "unique_sources": report.get("unique_sources"),
                    "community_reputation": report.get("community_reputation"),
                    "malicious_votes": report.get("malicious_votes"),
                    "harmless_votes": report.get("harmless_votes"),
                    "itw_url_count": len(itw_urls),
                    "tags": "|".join(tags),
                    "submission_names": "|".join(report.get("submission_names") or []),
                    "source_file": name,
                }
            )

            for engine, scan in (report.get("scans") or {}).items():
                detected = bool(scan.get("detected"))
                result = scan.get("result")
                if detected:
                    term_counter.update(family_terms(result))
                scan_rows.append(
                    {
                        "sha256": report.get("sha256"),
                        "engine": engine,
                        "detected": detected,
                        "result": result,
                        "engine_version": scan.get("version"),
                        "engine_update": scan.get("update"),
                        "scan_date": report.get("scan_date"),
                    }
                )

    return pd.DataFrame(sample_rows), pd.DataFrame(scan_rows), tag_counter, term_counter


def save_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot_detection_hist(samples: pd.DataFrame, charts_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.hist(samples["detection_ratio"], bins=12, color="#376996", edgecolor="white")
    ax.axvline(samples["detection_ratio"].median(), color="#c44900", linewidth=2, label="Median")
    ax.set_title("Distribution of Detection Ratios")
    ax.set_xlabel("Positive engines / total engines")
    ax.set_ylabel("Number of samples")
    ax.legend()
    fig.tight_layout()
    fig.savefig(charts_dir / "detection_ratio_distribution.png", dpi=160)
    plt.close(fig)


def plot_risk_categories(samples: pd.DataFrame, charts_dir: Path) -> None:
    counts = samples["risk_category"].value_counts().sort_index()
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.bar(counts.index, counts.values, color=["#7f7caf", "#4f7cac", "#d08c60"][: len(counts)])
    ax.set_title("Risk Categories by Antivirus Consensus")
    ax.set_xlabel("Category")
    ax.set_ylabel("Samples")
    ax.tick_params(axis="x", rotation=12)
    for idx, value in enumerate(counts.values):
        ax.text(idx, value + 1, str(value), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(charts_dir / "risk_categories.png", dpi=160)
    plt.close(fig)


def plot_top_engines(scans: pd.DataFrame, charts_dir: Path) -> pd.DataFrame:
    top = (
        scans.groupby("engine")["detected"]
        .agg(["sum", "count"])
        .rename(columns={"sum": "detections", "count": "samples_seen"})
        .reset_index()
    )
    top["detection_rate"] = top["detections"] / top["samples_seen"]
    top = top.sort_values(["detections", "detection_rate"], ascending=False).head(12)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(top["engine"], top["detections"], color="#2f6f5e")
    ax.invert_yaxis()
    ax.set_title("Antivirus Engines with Most Positive Detections")
    ax.set_xlabel("Detected samples")
    ax.set_ylabel("Engine")
    for y, value in enumerate(top["detections"]):
        ax.text(value + 1, y, str(int(value)), va="center")
    fig.tight_layout()
    fig.savefig(charts_dir / "top_detection_engines.png", dpi=160)
    plt.close(fig)
    return top


def plot_top_tags(tag_counter: Counter[str], charts_dir: Path) -> pd.DataFrame:
    top_tags = pd.DataFrame(tag_counter.most_common(12), columns=["tag", "count"])
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.barh(top_tags["tag"], top_tags["count"], color="#8a5a44")
    ax.invert_yaxis()
    ax.set_title("Most Common VirusTotal Tags")
    ax.set_xlabel("Samples")
    ax.set_ylabel("Tag")
    fig.tight_layout()
    fig.savefig(charts_dir / "top_tags.png", dpi=160)
    plt.close(fig)
    return top_tags


def build_metrics(
    samples: pd.DataFrame,
    scans: pd.DataFrame,
    top_engines: pd.DataFrame,
    top_tags: pd.DataFrame,
    term_counter: Counter[str],
) -> dict[str, Any]:
    top_terms = pd.DataFrame(term_counter.most_common(15), columns=["term", "count"])
    metrics = {
        "sample_count": int(len(samples)),
        "engine_scan_rows": int(len(scans)),
        "engine_count": int(scans["engine"].nunique()),
        "positives_min": int(samples["positives"].min()),
        "positives_median": float(samples["positives"].median()),
        "positives_max": int(samples["positives"].max()),
        "detection_ratio_mean": float(samples["detection_ratio"].mean()),
        "detection_ratio_median": float(samples["detection_ratio"].median()),
        "risk_categories": samples["risk_category"].value_counts().to_dict(),
        "size_min_bytes": int(samples["size_bytes"].min()),
        "size_median_bytes": float(samples["size_bytes"].median()),
        "size_max_bytes": int(samples["size_bytes"].max()),
        "samples_with_itw_urls": int((samples["itw_url_count"] > 0).sum()),
        "max_itw_urls": int(samples["itw_url_count"].max()),
        "times_submitted_median": float(samples["times_submitted"].median()),
        "times_submitted_max": int(samples["times_submitted"].max()),
        "top_engines": top_engines.to_dict(orient="records"),
        "top_tags": top_tags.to_dict(orient="records"),
        "top_detection_terms": top_terms.to_dict(orient="records"),
    }
    return metrics


def write_markdown_summary(metrics: dict[str, Any], output_path: Path) -> None:
    top_engine = metrics["top_engines"][0]
    top_terms = ", ".join(item["term"] for item in metrics["top_detection_terms"][:6])
    lines = [
        "# Generated Analysis Summary",
        "",
        f"- Samples analyzed: {metrics['sample_count']}",
        f"- Normalized engine scan records: {metrics['engine_scan_rows']}",
        f"- Antivirus engines observed: {metrics['engine_count']}",
        f"- Detection positives range: {metrics['positives_min']} to {metrics['positives_max']}",
        f"- Median detection ratio: {metrics['detection_ratio_median']:.3f}",
        f"- Dominant risk category: {max(metrics['risk_categories'], key=metrics['risk_categories'].get)}",
        f"- Top detecting engine: {top_engine['engine']} ({int(top_engine['detections'])} detections)",
        f"- Samples with in-the-wild URLs: {metrics['samples_with_itw_urls']}",
        f"- Frequent detection-name terms: {top_terms}",
        "",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    outputs_dir = args.outputs
    charts_dir = outputs_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    samples, scans, tag_counter, term_counter = load_reports(args.zip)
    samples.to_csv(outputs_dir / "samples_summary.csv", index=False)
    scans.to_csv(outputs_dir / "engine_scans_long.csv", index=False)

    plot_detection_hist(samples, charts_dir)
    plot_risk_categories(samples, charts_dir)
    top_engines = plot_top_engines(scans, charts_dir)
    top_tags = plot_top_tags(tag_counter, charts_dir)

    top_terms = pd.DataFrame(term_counter.most_common(30), columns=["term", "count"])
    top_engines.to_csv(outputs_dir / "top_detection_engines.csv", index=False)
    top_tags.to_csv(outputs_dir / "top_tags.csv", index=False)
    top_terms.to_csv(outputs_dir / "top_detection_terms.csv", index=False)

    metrics = build_metrics(samples, scans, top_engines, top_tags, term_counter)
    (outputs_dir / "project_metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_markdown_summary(metrics, outputs_dir / "generated_summary.md")

    print(f"Analyzed {metrics['sample_count']} reports.")
    print(f"Wrote outputs to {outputs_dir.resolve()}")


if __name__ == "__main__":
    main()
