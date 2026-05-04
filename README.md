# Final Project: VirusTotal Android Malware Risk Profiling

This project answers the course final-project requirement from the introductory slides: use the VirusTotal dataset to define and complete an end-to-end data engineering and data analysis project using Python and MongoDB concepts.

## Project Question

How can we transform nested VirusTotal Android APK reports into an analysis-ready dataset, measure antivirus consensus, and identify the strongest malware/risk patterns in the sample?

## Contents

- `src/analyze_virustotal.py`: reads `VTAndroid.zip`, normalizes the JSON reports, builds CSV tables, and generates charts.
- `src/advanced_python_analysis.py`: adds Python feature engineering, correlations, consensus-band summaries, extra charts, and report-ready Markdown.
- `src/prepare_mongodb_charts_data.py`: creates chart-ready datasets for MongoDB Charts / Atlas Charts.
- `src/import_to_mongodb.py`: optional loader that imports the normalized tables into MongoDB.
- `mongodb/queries.js`: MongoDB queries for risk distribution, top engines, tags, and high-consensus samples.
- `mongodb/charts_pipelines.js`: MongoDB aggregation pipelines that materialize dashboard collections.
- `mongodb/mongodb_charts_dashboard.md`: step-by-step MongoDB Charts dashboard guide.
- `docs/final_report.md`: final written report with methodology, results, limitations, and conclusions.
- `docs/presentation_outline.md`: short slide-by-slide structure for presenting the project.
- `outputs/`: generated CSV summaries, metrics, and chart images.

## How to Run

From this folder:

```powershell
python -m pip install -r requirements.txt
python .\src\analyze_virustotal.py
python .\src\advanced_python_analysis.py
python .\src\prepare_mongodb_charts_data.py
```

The script expects the original dataset at:

```text
..\Python for Data Science\VTAndroid.zip
```

It generates:

- `outputs/samples_summary.csv`
- `outputs/engine_scans_long.csv`
- `outputs/top_detection_engines.csv`
- `outputs/top_tags.csv`
- `outputs/top_detection_terms.csv`
- `outputs/project_metrics.json`
- `outputs/python_feature_table.csv`
- `outputs/consensus_band_summary.csv`
- `outputs/numeric_feature_correlations.csv`
- `outputs/python_extended_summary.md`
- `outputs/mongodb_charts/*.csv`
- `outputs/mongodb_charts/*.json`
- `outputs/dashboard.html`
- `outputs/charts/*.png`

To view the local dashboard:

```powershell
cd .\outputs
python -m http.server 8000 --bind 127.0.0.1
```

Then open:

```text
http://127.0.0.1:8000/dashboard.html
```

## Optional MongoDB Import

Start MongoDB locally, then run:

```powershell
python -m pip install pymongo
python .\src\import_to_mongodb.py --uri "mongodb://localhost:27017"
```

Then execute or copy the examples in:

```text
mongodb/queries.js
```

For MongoDB visualization, follow:

```text
mongodb/mongodb_charts_dashboard.md
```

The dashboard collections can be created either by importing the Python-generated files in `outputs/mongodb_charts/` or by running the aggregation pipelines in:

```text
mongodb/charts_pipelines.js
```

## Main Results

- 157 VirusTotal Android APK reports were analyzed.
- The nested engine results were normalized into 9,564 antivirus scan records.
- 66 antivirus engines appear in the dataset.
- The median detection ratio is 0.323.
- 156 samples are in the suspicious consensus category and 1 sample is high-confidence malicious.
- The most frequent detection terms are adware, artemis, riskware, mobby, notifyer, and ewind.
- The extended Python analysis adds engineered features such as file size in MB, tag counts, in-the-wild URL flags, repeated-submission flags, consensus bands, and numeric correlations.

## Important Limitation

The dataset does not include an independent benign/malicious ground-truth label. The project therefore uses antivirus consensus as an operational risk score, not as an absolute malware label.
