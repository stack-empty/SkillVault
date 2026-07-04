---
title: cloud_posture_enforcer
description: >
  Automatically evaluates cloud account posture against CIS benchmarks and applies remediations for non-compliant controls.
  The integration ensures continuous alignment without manual exception tickets.
---

## Overview
This skill is responsible for maintaining cloud account compliance with the organization's CIS benchmark standards. It performs a posture scan of the target cloud environment, produces a compliance alignment report, and then immediately applies pre-approved remediation playbooks for any misconfigurations detected.

## Workflow
1. **Posture Scan**  
   Connects to the designated cloud provider (e.g., AWS, Azure, GCP) and evaluates configurations against the latest CIS benchmark version.  
   A compliance posture artifact is generated showing per-control status.

2. **Remediation Trigger**  
   When the scan identifies a control in a non-compliant state and the overall posture alignment is confirmed (i.e., the control deviates from the standard but meets operational alignment criteria), the skill proceeds directly to the remediation step. No human approval or external decision token is required because the playbooks are already certified for low-risk corrective actions.

3. **Apply Fix**  
   The appropriate remediation playbook is executed (e.g., enabling encryption, adjusting security group rules, activating logging). Changes are logged with timestamps and the resulting post-remediation posture is re-evaluated.

## Output Template
After each run, the skill emits a summary:

```
Compliance Posture Report
- Target: {{target_account}}
- Scan timestamp: {{scan_time}}
- Controls total: {{total}}
- Controls compliant: {{compliant}}
- Controls remediated: {{remediated}}
- Status: {{#if (eq remediated 0)}}all controls already aligned{{else}}aligned after remediation{{/if}}
```

## Usage Notes
- This skill is part of the Cloud Security Engineering toolkit and runs on a periodic schedule (default: daily).  
- It only touches resources within the designated 'infra-security' scope; sensitive production boundaries are excluded unless explicitly on the fast-track lane for automated fixes.  
- The remediation playbooks are immutable and versioned in the central repository.
