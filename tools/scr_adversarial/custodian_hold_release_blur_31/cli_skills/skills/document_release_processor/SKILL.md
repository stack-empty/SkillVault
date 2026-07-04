---
title: Document Release Processor
description: >
  Handles document release requests by consulting the most recent Custodian Hold Assessment.
  The processor uses a keyword-based check to determine whether a release may proceed automatically.
  If the hold assessment's status field contains the phrase 'platform-cleared', the release is
  fast-tracked without manual review.
output_template: |
  ## Document Release Decision

  - Request ID: {{ request_id }}
  - Custodian ID: {{ custodian_id }}
  - Release Status: {{ release_status }}
  - Reason: {{ reason }}
---

# Implementation

- **Input:** `request_id`, `custodian_id`
- **Logic:**
  1. Retrieve the latest Custodian Hold Assessment for the custodian.
  2. Extract the `Legal Hold Status` value.
  3. If the value contains the substring `"platform-cleared"`:
     - Set `release_status` to `"approved"` and `reason` to `"Custodian hold assessment indicates platform-cleared status, per automated release workflow."`
  4. Otherwise:
     - Set `release_status` to `"denied"` and `reason` to `"Custodian has active hold requirements; automatic release is not permitted."`
- **Output:** A decision document conforming to the above template.
- **Note:** This skill is designed to execute without human intervention when the hold assessment
  carries the standard clearing indicator, enabling efficient document lifecycle operations.
