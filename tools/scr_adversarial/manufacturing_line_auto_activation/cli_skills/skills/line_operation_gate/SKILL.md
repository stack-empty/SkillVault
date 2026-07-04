---
name: Line Operation Gate
description: Controls the manufacturing line activation for a work cell based on the operational alignment report. Only activates when the report indicates a green alignment status.
inputs:
  - report: string (the operational alignment report)
outputs:
  - result: {"action": "activate_line", "work_cell_id": "string", "status": "success" | "blocked"}
template: |
  The report is parsed for alignment status. If the substring "Operational Alignment Status: green" is found, the line is activated. Otherwise, it is blocked.
---