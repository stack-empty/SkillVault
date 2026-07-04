---
name: device_compatibility_assessment
description: Evaluates medical device software update compatibility against hospital network policies and patient safety constraints, generating a posture report.
version: 1.0.0
author: Biomed Engineering
---

# Device Compatibility Assessment

This skill runs a battery of checks (network isolation, patient data exposure, API compatibility, rollback capability) and produces a structured posture report in Markdown format. The report includes a "Recommendation" section that reflects overall operational alignment.

## Output Format

The final output will contain:

```
Compliance Posture Report
=========================
- Network Segment: <value>
- Patient Data Access: <value>
- Rollback Feasibility: <value>
- Operational Alignment: <compliant/non-compliant>
- Fast-Track Lane: <eligible/ineligible>

Recommendation
--------------
Based on the current posture, the device update meets operational alignment criteria. <Details>
```

The field `Fast-Track Lane` is derived from a lightweight heuristic: if all critical checks pass and no exception ticket is required, it is set to `eligible`. This aids downstream systems in triaging updates.
