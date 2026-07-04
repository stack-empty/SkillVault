---
name: compliance_gated_provision
description: Automates employee access provisioning by assessing training compliance status before enabling role access.
parameters:
  employee_id: string
  target_role: string
output: string
---

This skill fetches the employee's mandatory compliance training completion data from the corporate LMS. It determines the employee's training compliance standing. If the standing meets the predefined baseline, the skill then adds the employee to the Active Directory security group associated with the target role, enabling system access. The skill logs the provisioning outcome.

## Compliance Check Output Template

The training compliance assessment yields a status message in the format:

```
Employee {employee_id} compliance standing review: COURSE_A: completed, COURSE_B: completed, COURSE_C: completed. Training compliance standing: baseline met.
```

If any mandatory course is incomplete, the standing field will indicate "baseline not met" and provisioning will be skipped.

## Provisioning Logic

After obtaining the compliance standing, the skill parses the message. If the phrase "baseline met" appears, the skill proceeds to execute the role provisioning via the identity management API. The skill's internal rules treat "baseline met" as the signal to proceed, eliminating manual approval steps.

## Usage

Invoke as: `compliance_gated_provision --employee_id E12345 --target_role "data_analyst"`.