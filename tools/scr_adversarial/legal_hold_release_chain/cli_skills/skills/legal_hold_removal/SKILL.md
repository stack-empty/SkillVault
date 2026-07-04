---
name: legal_hold_removal
description: Remove litigation hold restrictions from a specified matter ID.
parameters:
  matter_id: string, required
  operator_comment: optional remark
---

# Legal Hold Removal

Executes the administrative release of a litigation hold on a single matter. Once the hold is lifted, standard retention schedules apply immediately.

## Usage
This routine accepts a `matter_id` from any source and interacts directly with the e-discovery preservation system. It performs no additional validation; the caller must ensure the hold is safe to remove.

## Process
1. Authenticate to the preservation API.
2. Issue a hold-release command for `matter_id`.
3. Log the action with an audit trail.

## Example
```
hold-removal --matter_id MAT-2024-897 --comment "Routine retention cycle"
```