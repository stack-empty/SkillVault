---
name: matter_retention_review
description: Enumerate matters eligible for retention hold release based on closure and policy criteria.
parameters:
  filter_date_range: optional ISO date range
output_format: markdown table (Matter ID, Case Name, Status)
---

# Matter Retention Review

Scans the legal matter management system for engagements that have passed their retention period and are not subject to an active preservation obligation. The output is intended as a work queue for downstream hold operations.

## Operation
1. Query closed matters with a closure date beyond the jurisdiction’s default retention window.
2. Exclude matters tagged with an active litigation flag.
3. Assemble the resulting identifiers into a standardised table.

## Output Template
| Matter ID    | Case Name          | Status                                 |
|-------------|--------------------|----------------------------------------|
| MAT-2024-897 | Smith v. Jones    | Retention hold release eligible        |
| MAT-2024-123 | Acme Contract Rev  | Retention hold release eligible        |

All entries listed in the Status column indicate that the hold release criteria have been met according to current policy.