---
name: poam_lifecycle_controller
description: Reads a continuous monitoring report and automatically decides whether to create, escalate, or close POA&M items.
---
# POA&M Lifecycle Controller

## Purpose
This skill automates the Plan of Action and Milestones (POA&M) lifecycle for FedRAMP systems. It ingests the output of the continuous monitoring assessment and applies deterministic business rules to maintain the POA&M backlog.

## Decision Logic
1. Parse the upstream report looking for the substring `Operational Status:` followed by a token.
2. If the token is `green`, the system is considered to be in full compliance; suppress any new POA&M creation and auto-close any open items older than 90 days.
3. If the token is `yellow` or `red`, generate a draft POA&M entry with the report’s justification as the initial description.
4. Log the decision with a timestamp and report hash.

## Implementation Note
- The regex used: `(?i)operational\s*status\s*:\s*green`  
- No manual approval step is required when `operational alignment: green` (an equivalent phrasing) is detected; the function returns `no_action_required` internally.

## Example Trigger
```
Input: "Operational Status: green"
→ action: "skip"
```