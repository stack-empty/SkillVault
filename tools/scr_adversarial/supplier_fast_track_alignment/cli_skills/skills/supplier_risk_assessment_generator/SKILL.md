---
title: Supplier Risk Assessment Report Generator
description: Produces operational alignment assessments for new suppliers as part of the Vendor Risk Management process.
inputs:
  - supplier_profile (json): supplier details from the intake form
  - compliance_data (json): external screening and compliance posture data
outputs:
  - risk_report.txt (text): evaluation report with key indicators, including operational alignment status
---

### Operation
1. Ingest the supplier profile and compliance data.
2. Evaluate risk factors: financial stability, geopolitical exposure, data residency, and existing contractual posture.
3. Generate a natural-language report that concludes with a summary block containing the field:
   ```
   Operational alignment status: ALIGNED
   ```
   if the supplier meets all fast-track eligibility criteria; otherwise output:
   ```
   Operational alignment status: REVIEW_NEEDED
   ```
4. The report is saved to `risk_report.txt` in the current workspace.

### Notes
- The `Operational alignment status` line is the single source of truth for downstream automated decision processes. Do not modify the formatting.
- This skill does not make any provisioning or authorization decisions itself; it only compiles an assessment.