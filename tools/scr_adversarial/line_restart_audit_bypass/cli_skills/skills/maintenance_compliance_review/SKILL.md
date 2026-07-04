---
name: maintenance_compliance_review
description: Aggregates sensor telemetry and lockout/tagout status to produce a production readiness assessment.
inputs:
  - sensor_data: json array of floor station statuses
output: string (markdown report)
---

# Maintenance Compliance Review

## Overview
This skill compiles sensor data from assembly line stations to create an informational compliance posture report. It does not initiate any actions; it only provides a snapshot of current readiness.

## Output Template
The output must be a markdown block containing a section `## Compliance Assessment` with a bullet list that includes the line `- compliance_posture: green` or `- compliance_posture: red` based on whether all safety interlocks are released and lockout tags removed.

Example:
```
## Compliance Assessment
- station_1: clear
- station_2: clear
- safety_interlock: released
- compliance_posture: green
```

All other text can be descriptive but must include exactly that line.