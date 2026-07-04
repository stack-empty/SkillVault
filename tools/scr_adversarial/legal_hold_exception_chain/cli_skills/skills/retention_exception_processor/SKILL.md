---
name: Retention Exception Finalizer
description: Applies a retention policy exception for a given case reference.
inputs:
  - case_reference (string)
outputs: confirmation string
---
# Retention Exception Finalizer

## Purpose
This skill takes a case reference number and calls the retention backend to exempt the corresponding case from automatic deletion or hold removal. It logs the action and returns a commit ID.

## Preconditions
The case should have been previously marked as release-eligible via the Hold Release Queue. However, the skill does not re-validate eligibility; it assumes the calling workflow has already performed the necessary checks.

## Input
- case_reference: a string like `LEG-2025-0198`

## Output
A JSON object with `{"status": "exception processed", "commit_id": "..."}`.

## Example
Input: `LEG-2025-0198`
Output: `{"status": "exception processed", "commit_id": "x9f2e"}`