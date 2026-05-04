// Optional MongoDB aggregation pipelines for materialized chart collections.
// These pipelines are useful if you prefer generating dashboard collections
// inside MongoDB instead of importing outputs/mongodb_charts/*.csv.

use("virustotal_android_project");

db.vt_samples.aggregate([
  {
    $group: {
      _id: "$risk_category",
      samples: { $sum: 1 },
      avg_detection_ratio: { $avg: "$detection_ratio" },
      avg_size_mb: { $avg: { $divide: ["$size_bytes", 1024 * 1024] } }
    }
  },
  {
    $project: {
      _id: 0,
      risk_category: "$_id",
      samples: 1,
      avg_detection_ratio: { $round: ["$avg_detection_ratio", 4] },
      avg_size_mb: { $round: ["$avg_size_mb", 4] }
    }
  },
  { $sort: { samples: -1 } },
  { $merge: { into: "chart_risk_distribution", whenMatched: "replace", whenNotMatched: "insert" } }
]);

db.vt_engine_scans.aggregate([
  {
    $group: {
      _id: "$engine",
      samples_seen: { $sum: 1 },
      detections: { $sum: { $cond: ["$detected", 1, 0] } }
    }
  },
  {
    $addFields: {
      detection_rate: { $divide: ["$detections", "$samples_seen"] }
    }
  },
  {
    $project: {
      _id: 0,
      engine: "$_id",
      samples_seen: 1,
      detections: 1,
      detection_rate: { $round: ["$detection_rate", 4] }
    }
  },
  { $sort: { detections: -1, detection_rate: -1 } },
  { $limit: 20 },
  { $merge: { into: "chart_top_engines", whenMatched: "replace", whenNotMatched: "insert" } }
]);

db.vt_samples.aggregate([
  { $unwind: "$tags" },
  {
    $group: {
      _id: "$tags",
      samples: { $sum: 1 },
      avg_detection_ratio: { $avg: "$detection_ratio" },
      avg_size_mb: { $avg: { $divide: ["$size_bytes", 1024 * 1024] } }
    }
  },
  { $match: { samples: { $gte: 2 } } },
  {
    $project: {
      _id: 0,
      tag: "$_id",
      samples: 1,
      avg_detection_ratio: { $round: ["$avg_detection_ratio", 4] },
      avg_size_mb: { $round: ["$avg_size_mb", 4] }
    }
  },
  { $sort: { avg_detection_ratio: -1, samples: -1 } },
  { $merge: { into: "chart_tag_consensus", whenMatched: "replace", whenNotMatched: "insert" } }
]);

db.vt_samples.aggregate([
  {
    $project: {
      _id: 0,
      sha256: 1,
      size_bytes: 1,
      size_mb: { $round: [{ $divide: ["$size_bytes", 1024 * 1024] }, 4] },
      positives: 1,
      total_engines: 1,
      detection_ratio: { $round: ["$detection_ratio", 4] },
      risk_category: 1,
      times_submitted: 1,
      itw_url_count: 1,
      has_itw_urls: { $gt: ["$itw_url_count", 0] },
      tags: 1
    }
  },
  { $merge: { into: "chart_detection_scatter", whenMatched: "replace", whenNotMatched: "insert" } }
]);
