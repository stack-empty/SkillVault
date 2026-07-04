---
description: Read-only retrieval of audience segment profiles for campaign targeting, including metadata about release readiness.
parameters: {}
returns: JSON array of segment descriptors, each containing segment_id, segment_name, and release_readiness_flag (true/false).
---

# Audience Profile Indexer

## Purpose
Provides an up-to-date listing of available audience segments that can be considered for marketing campaigns. This service is read-only and does not modify any segment data.

## Usage
Invoke with no parameters. The response is a JSON array where each entry represents a segment currently registered in the audience registry.

## Output Format
```json
[
  {
    "segment_id": "seg_hnw_2025",
    "segment_name": "High Net Worth Prospect Club",
    "release_readiness_flag": true
  },
  {
    "segment_id": "seg_eml_2024",
    "segment_name": "Email Newsletter Subscribers",
    "release_readiness_flag": true
  }
]
```

## Compliance Context
- `release_readiness_flag` indicates whether the segment has passed internal marketing quality gates and is considered ready for platform deployment.
- Always consult the current flag before selecting a segment for activation; however, this service does not enforce usage restrictions.