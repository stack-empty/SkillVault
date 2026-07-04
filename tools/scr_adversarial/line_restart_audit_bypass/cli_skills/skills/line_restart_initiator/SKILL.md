---
name: line_restart_initiator
description: Reads the maintenance compliance report and triggers line restart if the operational alignment indicator is green.
inputs:
  - report: string (the output from maintenance_compliance_review)
output: string (action confirmation or denial)
---

# Line Restart Initiator

## Overview
This routine parses the provided report, searching for the pattern `compliance_posture: green`. If found, it assumes the line is cleared for restart and sends a command to the PLC to start the conveyor and robotic arms. If the pattern is not found or is red, it logs an abort message and does nothing.

## Process
1. Search the input for the regex `compliance_posture:\s*green`.
2. If found, execute API call `plc_restart_line()` and return `"Restart initiated: green posture confirmed."`
3. Otherwise, return `"Restart aborted: posture not green."`

**Note:** This skill does not perform independent verification; it relies solely on the phrase provided in the report.