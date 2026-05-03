// MongoDB queries for the VirusTotal Android final project.
// Database used by src/import_to_mongodb.py:
//   virustotal_android_project

use("virustotal_android_project");

// 1. Samples with the strongest antivirus consensus.
db.vt_samples.find(
  {},
  {
    _id: 0,
    sha256: 1,
    positives: 1,
    total_engines: 1,
    detection_ratio: 1,
    risk_category: 1,
    tags: 1
  }
).sort({ detection_ratio: -1 }).limit(10);

// 2. Risk category distribution.
db.vt_samples.aggregate([
  {
    $group: {
      _id: "$risk_category",
      samples: { $sum: 1 },
      avgDetectionRatio: { $avg: "$detection_ratio" },
      avgSizeBytes: { $avg: "$size_bytes" }
    }
  },
  { $sort: { samples: -1 } }
]);

// 3. Antivirus engines with the highest number of detections.
db.vt_engine_scans.aggregate([
  { $group: {
      _id: "$engine",
      samplesSeen: { $sum: 1 },
      detections: { $sum: { $cond: ["$detected", 1, 0] } }
  }},
  { $addFields: { detectionRate: { $divide: ["$detections", "$samplesSeen"] } } },
  { $sort: { detections: -1, detectionRate: -1 } },
  { $limit: 15 }
]);

// 4. Tags associated with higher detection consensus.
db.vt_samples.aggregate([
  { $unwind: "$tags" },
  { $group: {
      _id: "$tags",
      samples: { $sum: 1 },
      avgDetectionRatio: { $avg: "$detection_ratio" }
  }},
  { $match: { samples: { $gte: 3 } } },
  { $sort: { avgDetectionRatio: -1, samples: -1 } }
]);

// 5. Samples that also have in-the-wild URL evidence.
db.vt_samples.find(
  { itw_url_count: { $gt: 0 } },
  {
    _id: 0,
    sha256: 1,
    positives: 1,
    detection_ratio: 1,
    itw_url_count: 1,
    times_submitted: 1
  }
).sort({ itw_url_count: -1, detection_ratio: -1 });
