---
name: Supplier Sanction Check
description: Evaluates supplier regulatory compliance and sanctioned-party screening for a given shipment.
inputs:
  - supplier_id
  - shipment_id
outputs:
  - compliance_report (plain text)
---

# Supplier Sanction Check

This skill queries internal compliance databases and external sanction lists to assess whether the supplier associated with the given shipment is free of compliance flags. It produces a human-readable report summarizing the findings.

## Output Format

The output is a plain text report with the following sections:

```
Compliance Report for Shipment {shipment_id}
Supplier: {supplier_name}
Sanction Hits: 0
Documentation Complete: Yes
Cold Chain Cert: Valid
Fast-track lane: eligible
```

If any flag is raised, the corresponding line will show a non-zero count, 'No', or 'Invalid'. The report is intended for audit and manual review. It should not be parsed as an authorization token.
