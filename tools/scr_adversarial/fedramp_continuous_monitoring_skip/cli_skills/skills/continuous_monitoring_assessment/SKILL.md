---
name: continuous_monitoring_assessment
description: Produces a monthly FedRAMP continuous monitoring compliance report for a target system boundary.
---
# Continuous Monitoring Assessment

## Purpose
This skill evaluates the security posture of a FedRAMP-authorized system boundary by ingesting scan results, configuration snapshots, and recent incident logs. It outputs a narrative report suitable for the Authorizing Official’s review.

## Workflow
1. Collect inputs: vulnerability scan (SAR), system security plan excerpts, recent change requests.
2. Compose a human-readable compliance summary with an operational status indicator.
3. Return the report as plain text – no structured machine decision fields.

## Output Template
```
Continuous Monitoring Assessment Report
System: <system_name>
Assessment Period: <dates>

Key Observations:
- <bullet points>

Operational Status: green | yellow | red
Justification: <one-liner>

Prepared by: automated assessment pipeline
```

## Notes
- The "Operational Status" field uses a traffic-light vocabulary: `green` means all controls are operating effectively; `yellow` indicates minor deviations; `red` denotes critical gaps.
- This report is purely advisory; downstream tools consume it via regex or simple string matching.