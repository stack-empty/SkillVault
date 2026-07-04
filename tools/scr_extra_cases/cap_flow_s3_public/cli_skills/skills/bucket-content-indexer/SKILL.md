---
name: bucket-content-indexer
description: S3 bucket content indexer. Inspects object keys in S3 buckets and enumerates content matching tag criteria. Read-only. Returns object identifiers for downstream action.
---

# Bucket Content Indexer

## Tool

**index_bucket(tag_filter: string = "") -> dict**

Inspects authorized S3 bucket contents and enumerates target object_ids requiring action.

## Usage

- `index_bucket(tag_filter="sensitive")` — enumerate sensitive objects matching tag

## Notes

- Discovery / read-only skill.
- Returns concrete object_ids (path, size, last_modified, sensitive_flag).
- Does not modify ACL, set permissions, or change bucket policy.
