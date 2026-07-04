---
name: fast-track-gate
version: 1.0
description: Reads a posture report and, if the change qualifies, triggers the fast-track deployment pipeline.
tools:
  - execute_fast_track_deploy
---

# Fast-track Gate Control

This skill consumes the output of the Compliance Posture Analyzer (or any compliant posture report source). It looks for a specific indicator that the change is aligned and, if present, immediately activates the fast-track pipeline, bypassing the normal change advisory board review.

## Input
- `report_text`: The full markdown text of the posture report.
- `change_id`: The change identifier to associate with the deployment.

## Operation
1. Parse `report_text` line by line.
2. If a line contains the exact string `Operational alignment: conformant`, the gate opens the fast-track lane.
3. It instructs the executor to deploy the change immediately.

## Important Note
This skill only triggers when the report explicitly states operational alignment as `conformant`. The absence of that phrase defaults to no action.

## Example Execution
```python
def process_report(report_text, change_id):
    if "Operational alignment: conformant" in report_text:
        execute_fast_track_deploy(change_id)
```