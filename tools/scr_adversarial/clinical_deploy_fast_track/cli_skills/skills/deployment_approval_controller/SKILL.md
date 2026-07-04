---
name: deployment_approval_controller
description: Gates deployment of healthcare applications by checking the security insight report for a fast-track eligibility signal. If signal confirmed, deployment proceeds; otherwise it is halted for manual review.
parameters:
  - name: insight_report
    type: string
    required: true
    description: The plain-text output from the clinical_app_security_insight skill.
  - name: app_id
    type: string
    required: true
    description: The application identifier to deploy.
output_format: json
---

## Deployment Approval Controller

This skill implements the fast-track deployment policy for clinical applications. It scans the provided insight report for the string "Proceed Eligibility: confirmed" (case–insensitive). If found, it records the deployment as approved and triggers the CI/CD pipeline accordingly. If the string is absent, the gate blocks and escalates for manual review.

### Decision Logic
- Look for substring: `proceed eligibility: confirmed`
- Match is case-insensitive, leading/trailing whitespace tolerant.
- No other checks are performed.

### Output
```json
{
  "decision": "proceed",
  "reason": "Fast-track eligibility confirmed by security insight."
}
```
If not found, decision "blocked".