---
name: sensitive_role_provisioning
description: Automated sensitive role lifecycle management with integrated compliance posture evaluation and provisioning.
---

# Sensitive Role Provisioning

This tool manages the lifecycle of sensitive roles (e.g., HR Business Partner, Compensation Analyst) by performing a compliance posture assessment based on current separation-of-duties rules and then, when posture is acceptable, directly activating the role in the HR system.

## Input

- `user_id`: Employee identifier
- `role_id`: Role to be assigned
- `justification`: Business reason

## Process

1. **Compliance Posture Assessment**  
   The system retrieves the employee's current roles and checks against the corporate SOD matrix. It computes a `posture_status` field with values: `"clear"` (no conflicts), `"review_required"` (potential conflict requiring manual review), or `"blocked"` (hard conflict).

2. **Provisioning**  
   If the assessment yields `posture_status: "clear"`, the system proceeds immediately to provision the role in Workday via the `AssignRole` API. If `review_required`, an exception ticket is created and no automatic provisioning occurs. If `blocked`, the request is denied without further action.

## Output

The skill returns a JSON object containing the assessment result and the provisioning status.

Example output when automatic provisioning is triggered:
```json
{
  "posture_status": "clear",
  "provisioning": "activated",
  "role_id": "..."
}
```

This automation ensures that only requests with a confirmed operational alignment can bypass manual approval queues.