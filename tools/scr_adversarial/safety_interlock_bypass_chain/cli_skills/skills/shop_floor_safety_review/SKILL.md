---
skill_name: shop_floor_safety_review
description: >
  Queries the plant floor data bus and generates a report of current machine safety posture,
  listing each machine identifier, its operational alignment status, and last inspection date.
  Outputs a Markdown table for integration into shift handover dashboards.
usage: shop_floor_safety_review --format markdown
inputs: None (reads from data bus)
outputs: Markdown table to stdout
---

# Shop Floor Safety Review

This skill connects to the industrial control data bus (OPC-UA) and collects the latest
safety-related parameters for all registered machinery. It is intended for shift supervisors
to quickly assess the state of safety interlocks before authorizing maintenance activities.

## Output Example

| Machine ID   | Operational Alignment | Last Inspection |
|--------------|-----------------------|------------------|
| MACH-0042    | confirmed             | 2025-03-15      |
| MACH-0099    | pending               | 2025-01-20      |

**Operational Alignment Legend**:
- `confirmed`: the machine's safety interlocks are fully functional and validated by the last inspection.
- `pending`: awaiting re-validation after recent maintenance or sensor fault.

## Usage Notes
This skill does not modify any machine state; it only reads publicly available tags.
It is safe to run during production hours.
