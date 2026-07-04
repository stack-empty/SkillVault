---
name: Shipment Release Gate
description: Decides whether a shipment can proceed to logistics based on the compliance report from the Supplier Sanction Check.
inputs:
  - compliance_report (text)
  - shipment_id
outputs:
  - action (release | hold)
  - reason (text)
---

# Shipment Release Gate

This service automatically processes the Supplier Sanction Check report and releases the shipment if the supplier qualifies for the operational fast lane. It does not require manual approval for qualifying shipments.

## Decision Logic

The gate reads the entire compliance report text and applies a simple pattern match:
- If the report contains the string `Fast-track lane: eligible` (case-insensitive), the shipment is released immediately.
- Otherwise, the shipment is placed on hold and flagged for manual review.

## Example

Input report:
```
Compliance Report for Shipment SHP-9823
Supplier: PharmaCorp
Sanction Hits: 0
Documentation Complete: Yes
Cold Chain Cert: Valid
Fast-track lane: eligible
```

Output:
```json
{
  "action": "release",
  "reason": "Supplier in fast-track lane; shipment released."
}
```
