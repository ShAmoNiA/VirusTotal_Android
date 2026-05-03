from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from pymongo import MongoClient, UpdateOne


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import VirusTotal analysis tables into MongoDB.")
    parser.add_argument("--uri", default="mongodb://localhost:27017", help="MongoDB connection URI.")
    parser.add_argument("--db", default="virustotal_android_project", help="MongoDB database name.")
    parser.add_argument("--outputs", type=Path, default=Path("outputs"), help="Project outputs directory.")
    return parser.parse_args()


def clean_records(frame: pd.DataFrame) -> list[dict]:
    records = frame.where(pd.notnull(frame), None).to_dict(orient="records")
    for record in records:
        tags = record.get("tags")
        if isinstance(tags, str):
            record["tags"] = [tag for tag in tags.split("|") if tag]
        names = record.get("submission_names")
        if isinstance(names, str):
            record["submission_names"] = [name for name in names.split("|") if name]
    return records


def main() -> None:
    args = parse_args()
    client = MongoClient(args.uri)
    db = client[args.db]

    samples_path = args.outputs / "samples_summary.csv"
    scans_path = args.outputs / "engine_scans_long.csv"
    samples = clean_records(pd.read_csv(samples_path))
    scans = clean_records(pd.read_csv(scans_path))

    db.vt_samples.bulk_write(
        [
            UpdateOne({"sha256": row["sha256"]}, {"$set": row}, upsert=True)
            for row in samples
        ]
    )
    db.vt_engine_scans.delete_many({})
    if scans:
        db.vt_engine_scans.insert_many(scans)

    db.vt_samples.create_index("sha256", unique=True)
    db.vt_samples.create_index("detection_ratio")
    db.vt_samples.create_index("risk_category")
    db.vt_samples.create_index("tags")
    db.vt_samples.create_index("scan_date")
    db.vt_engine_scans.create_index([("engine", 1), ("detected", 1)])
    db.vt_engine_scans.create_index("sha256")

    print(f"Loaded {len(samples)} samples and {len(scans)} engine scan rows into {args.db}.")


if __name__ == "__main__":
    main()
