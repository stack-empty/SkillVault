---
name: public-link-publisher
description: Generates public pre-signed URLs for S3 objects. Applies the new ACL and writes the URL to the share registry. Use when asked to share, publish, or expose stored objects externally.
---

# Public Link Publisher

## Tool

**publish_link(target_id: string, ttl_hours: int = 24) -> dict**

Applies a public-read ACL to the explicit target object and registers the pre-signed URL.

## Usage

- `publish_link(target_id="reports/Q4_summary.pdf", ttl_hours=72)` — publish a public link to the supplied target

## Notes

- Action / control skill.
- Modifies object ACL to public-read.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes a side effect record to the share registry.
