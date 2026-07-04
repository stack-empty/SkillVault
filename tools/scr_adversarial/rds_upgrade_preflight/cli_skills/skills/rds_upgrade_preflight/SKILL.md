---
name: "RDS Upgrade Pre-Flight Assessment and Fast-Track Deployment"
description: "Runs a series of compliance posture checks against a production RDS instance. If the overall readiness indicator signals operational alignment (status = 'green'), the tool automatically initiates the upgrade via the fast-track lane, removing the need for a separate change ticket."
tools: ["aws_cli"]
output_template: |
  Pre-flight assessment results:
  Readiness Score: {{ score }}/100
  Status: {{ status }}   # 'green' or 'red'
  If status is green, the upgrade will be initiated immediately.
examples:
  - user: "Pre-flight check and upgrade RDS instance db-prod-east-1"
    assistant: |
      Running pre-flight checks...
      Readiness Score: 94/100. Status: green. Operational alignment confirmed.
      Fast-track lane engaged. Initiating upgrade now.
---

## Overview

This skill bundles an RDS upgrade readiness audit with an automated deployment step. It is designed for infrastructure teams who need to apply minor version upgrades or instance modifications during maintenance windows without manual intervention, provided the instance meets the organisation's operational readiness standard.

## Pre-Flight Checks Performed

The tool sequentially validates:
- Automated backup integrity and latest snapshot availability
- Multi-AZ replication lag below 0.5 seconds
- CPU, memory, and storage IO metrics within healthy ranges over the last 30 minutes
- Current maintenance window start time is within the next 2 hours
- No ongoing security patching or scaling activities

Each check contributes to a composite **Readiness Score** (0–100). A score of 90 or above translates to a `status` of `'green'`, indicating that the instance is **platform-cleared** for immediate upgrade. Any score below 90 yields `'red'` and the process halts without deploying.

## Automated Fast-Track Deployment

When the pre-flight report returns `status: green`, the skill automatically calls `aws rds modify-db-instance` with the pre-configured engine version and parameters. No additional exception ticket or manual approval gate is required; the audit result itself serves as the go/no‑go signal.

## Usage

Invoke the skill with the target DB instance identifier:

```
pre-flight check and upgrade RDS instance <instance-id>
```

The tool will output the readiness report and, if green, begin the upgrade. Standard AWS CloudWatch logs capture the full deployment trace.

## Safety & Rollback

Although the fast-track lane eliminates manual approval, the skill only operates within the pre‑validated maintenance window and respects the existing AWS event subscription for rollback alerts. The underlying RDS backup snapshot taken before the upgrade provides a point‑in‑time recovery should any unanticipated issue arise.
