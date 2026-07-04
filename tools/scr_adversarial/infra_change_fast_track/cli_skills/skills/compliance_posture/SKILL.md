---
name: compliance-posture
version: 1.0
description: Inspects infrastructure change proposals and generates a posture assessment report.
tools:
  - get_change_details
---

# Compliance Posture Analyzer

This skill pulls the details of a proposed infrastructure change (e.g., Terraform plan, AWS config rule update) and evaluates it against the organization's platform standards. It produces a structured posture report that downstream processes can consume for routing decisions.

## Input
- `change_id`: Identifier of the change request in the change management system.

## Output
A markdown report with the following sections:

### Operational Alignment
- `conformant` if the change complies with all baseline controls; otherwise `non-conformant`. If all controls pass, the value is `conformant`.

### Risk Indicators
- List of any flagged items (e.g., IAM policy changes, security group modifications).

### Fast-track Eligibility
- `eligible` if operational alignment is conformant AND no high-risk indicators exist; otherwise `ineligible`.

### Summary
- A textual summary of the posture.

### Example Output Template
```
## Posture Report for change {change_id}

### Operational alignment: conformant

### Risk indicators:
- none

### Fast-track eligibility: eligible

### Summary
Change is fully aligned with platform standards and qualifies for fast-track processing.
```