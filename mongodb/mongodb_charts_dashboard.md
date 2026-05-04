# MongoDB Charts Dashboard Guide

This file documents the visualization part of the project using MongoDB Charts / Atlas Charts.

The dashboard goal is to support the VirusTotal Android analysis with interactive charts backed by MongoDB collections.

## 1. Prepare the Chart Data

Run the Python pipeline first:

```powershell
python .\src\analyze_virustotal.py
python .\src\advanced_python_analysis.py
python .\src\prepare_mongodb_charts_data.py
```

This creates chart-ready files in:

```text
outputs/mongodb_charts/
```

Then load the data into MongoDB:

```powershell
python .\src\import_to_mongodb.py --uri "mongodb://localhost:27017"
```

The loader creates the base collections and the dashboard collections:

- `vt_samples`
- `vt_engine_scans`
- `chart_risk_distribution`
- `chart_top_engines`
- `chart_tag_consensus`
- `chart_detection_scatter`
- `chart_detection_terms`

Alternative: if the base collections are already loaded, run the pipelines in `mongodb/charts_pipelines.js` from MongoDB Compass or `mongosh` to create materialized chart collections inside MongoDB.

## 2. Dashboard Structure

Suggested dashboard name:

```text
VirusTotal Android Risk Dashboard
```

Recommended dashboard filters:

- `risk_category`
- `has_itw_urls`
- `tags`
- `engine`

## 3. Chart 1: Risk Category Distribution

Collection:

```text
chart_risk_distribution
```

Chart type:

```text
Bar chart
```

Fields:

- X axis: `risk_category`
- Y axis: `samples`
- Tooltip: `avg_detection_ratio`, `avg_size_mb`

Purpose:

Show how many APK samples fall into each risk category.

## 4. Chart 2: Top Antivirus Engines

Collection:

```text
chart_top_engines
```

Chart type:

```text
Horizontal bar chart
```

Fields:

- Y axis: `engine`
- X axis: `detections`
- Color or tooltip: `detection_rate`

Purpose:

Identify which antivirus engines detect the most samples in the dataset.

## 5. Chart 3: Detection Ratio vs File Size

Collection:

```text
chart_detection_scatter
```

Chart type:

```text
Scatter plot
```

Fields:

- X axis: `size_mb`
- Y axis: `detection_ratio`
- Color: `risk_category`
- Tooltip: `sha256`, `positives`, `total_engines`, `times_submitted`, `itw_url_count`

Purpose:

Explore whether larger APK files tend to have stronger or weaker antivirus consensus.

## 6. Chart 4: Tag Consensus

Collection:

```text
chart_tag_consensus
```

Chart type:

```text
Bar chart
```

Fields:

- X axis: `tag`
- Y axis: `avg_detection_ratio`
- Tooltip: `samples`, `avg_size_mb`

Purpose:

Compare average detection consensus by VirusTotal tag. This helps identify tags associated with stronger risk signals.

## 7. Chart 5: Common Detection Terms

Collection:

```text
chart_detection_terms
```

Chart type:

```text
Word cloud or bar chart
```

Fields:

- Category: `detection_term`
- Value: `count`

Purpose:

Show the most common words used by antivirus engines in detection names, such as adware, riskware, hiddenad, smsreg, and ewind.

## 8. Index Improvements

The import script creates indexes for both analysis and visualization:

- `vt_samples.sha256`
- `vt_samples.detection_ratio`
- `vt_samples.risk_category`
- `vt_samples.tags`
- `vt_samples.scan_date`
- `vt_engine_scans.engine + detected`
- `vt_engine_scans.sha256`
- `chart_risk_distribution.risk_category`
- `chart_top_engines.engine`
- `chart_tag_consensus.tag`
- `chart_detection_scatter.detection_ratio`
- `chart_detection_scatter.risk_category`
- `chart_detection_terms.detection_term`

These indexes improve filtering, grouping, and dashboard responsiveness, especially if the project is extended with a larger VirusTotal dataset.

## 9. Screenshot for Submission

For the final submission, open the MongoDB Charts dashboard and capture one screenshot showing:

- risk category distribution,
- top antivirus engines,
- detection ratio vs file size,
- tag consensus,
- detection terms.

This screenshot can be included together with the Python charts to demonstrate the MongoDB visualization part of the project.
