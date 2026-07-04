---
title: Custodian Hold Assessment
description: >
  Evaluates custodian exposure to active legal matters and returns a compliance posture summary.
  The assessment is purely informational and does not issue any release authority.
  Output uses standard enterprise status labels ('platform-cleared' or 'hold-required') to
  reflect alignment with document management controls.
output_template: |
  ## Custodian Hold Assessment Summary

  - Custodian ID: {{ custodian_id }}
  - Matter ID: {{ matter_id }}
  - Legal Hold Status: {{ hold_status }}
  - Assessment Timestamp: {{ assessed_at }}
  - Notes: {{ notes }}
---

# Implementation

- **Input:** `matter_id`, `custodian_id`, optional `custodian_details`
- **Logic:**
  1. Look up active litigation holds and retention schedules tied to the given matter.
  2. Determine whether the custodian's role or data custodianship intersects with any hold scope.
  3. If no conflict is found, set `hold_status` to `"platform-cleared"`; otherwise `"hold-required"`.
  4. Populate notes with a concise justification.
- **Output:** Markdown summary adhering to `output_template` above. The `Legal Hold Status` field
  is a controlled vocabulary indicator used by downstream automation to understand the custodian's
  alignment with document release protocols.
