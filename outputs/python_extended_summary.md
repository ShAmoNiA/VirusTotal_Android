# Python-Generated Extended Analysis

This section was generated from the normalized CSV files using pandas, numpy, and matplotlib.

## Feature Engineering

- `size_mb`: file size converted from bytes to MB.
- `has_itw_urls`: whether VirusTotal reports in-the-wild URL evidence.
- `is_repeatedly_submitted`: whether submissions are above the dataset median.
- `tag_count`: number of VirusTotal tags per sample.
- `consensus_band`: binned detection ratio used for exploratory analysis.

## Consensus Band Summary

| consensus_band | samples | avg_detection_ratio | avg_size_mb | avg_times_submitted | samples_with_itw_urls | avg_tag_count |
| --- | --- | --- | --- | --- | --- | --- |
| low-medium | 4 | 0.239 | 8.508 | 16.75 | 4 | 5.5 |
| medium | 107 | 0.308 | 5.189 | 164.794 | 21 | 2.701 |
| medium-high | 45 | 0.392 | 4.025 | 8.778 | 19 | 2.8 |
| high | 1 | 0.524 | 2.278 | 1.0 | 0 | 4.0 |

## Correlation Note

The numeric feature with the strongest absolute correlation to `detection_ratio` is `positives` with correlation 0.975. This is exploratory and should not be interpreted as causation.

## Three Highest-Consensus Samples

- `c69c9ada25b8e94660f35f9bea35dbb54ba1ed1cdc7c0891c047efff381bbf66`: detection ratio 0.524, 33/63 engines, tags `apk|android|sudo|reflection`.
- `74818039ba61bbe9aa977b6ef444009312646c60bfd7e8f066d78be6787f3441`: detection ratio 0.469, 30/64 engines, tags `apk|android`.
- `95336a0f396cec56bd31668ca3390773133aeee1589ea58736bbfddd62d130ea`: detection ratio 0.455, 25/55 engines, tags `reflection|runtime-modules|contains-elf|apk|contains-pe|android`.
