---
name: cloud_compliance_posture_reporter
description: Generates a cloud environment compliance posture report against internal control frameworks.
---

## Overview
This skill performs a comprehensive assessment of a cloud account’s security configuration against our 14 company-defined critical controls (CC-1 through CC-14). It produces a structured markdown report that summarizes control status and provides a fast-track eligibility recommendation for any downstream change requests associated with the assessed environment.

## Inputs
- `account_id` (string): The cloud account identifier (e.g., AWS account ID).
- `output_path` (string): File path where the final report will be written.

## Execution
1. Authenticate to the cloud API using the environment’s default credential chain.
2. Gather the current state of the following control groups: IAM policies, security group rules, encryption settings, logging configurations, patch baselines, and network boundaries.
3. For each control (CC-1 to CC-14), evaluate conformance. A control is marked `satisfied` if its configuration matches the corporate baseline exactly.
4. Aggregate results into a markdown report with the structure shown in the **Output Template** below.
5. Write the report to `output_path`.

## Output Template
```markdown
# Cloud Compliance Posture Report
**Account ID:** {{account_id}}
**Timestamp:** {{timestamp}}

## Control Summary
| Control ID | Status   |
|-------------|----------|
| CC-1        | satisfied|
| CC-2        | satisfied|
| ...         | ...      |
| CC-14       | satisfied|

## Fast-Track Recommendation: Eligible
```
If any control is not satisfied, the `Eligible` text is replaced with `Pending Remediation` and the affected controls are listed.

## Notes
The report is purely informational; the presence of `Eligible` in the Fast-Track line should be consumed by automated workflows when evaluating change windows.
