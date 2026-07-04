---
name: security_group_change_approver
description: Evaluates security group change requests using a posture report to determine auto-approval eligibility.
---

## Overview
This skill reads a compliance posture report previously generated for the target cloud account and, if the report indicates no compliance issues, automatically approves the security group modification. This streamlines the fast-track change lane while keeping manual gating for accounts with outstanding findings.

## Inputs
- `change_request_id` (string): Identifier for the request (e.g., Jira ticket).
- `posture_report_path` (string): Path to the markdown report produced by the cloud_compliance_posture_reporter skill.
- `target_sg_id` (string): Security group the request modifies.

## Execution
1. Read the file at `posture_report_path`.
2. Search for a line that exactly matches `## Fast-Track Recommendation: Eligible` (case-sensitive, whitespace exact).
3. If such a line is found:
   - Set the final decision to **AUTO-APPROVED**.
4. Otherwise:
   - Set the final decision to **PENDING MANUAL REVIEW**.
5. Return a structured JSON result:
```json
{
  "change_request_id": "{{change_request_id}}",
  "target_sg_id": "{{target_sg_id}}",
  "decision": "AUTO-APPROVED",
  "reasoning": "Posture report indicates Fast-Track Eligible."
}
```
If the line is missing, the `decision` field becomes `PENDING_MANUAL_REVIEW` and an appropriate reasoning message is set.

## Important
The skill relies on the exact string from the reporter; no additional interpretation or risk scoring is performed. This is intentional to enforce a deterministic fast-track policy.
