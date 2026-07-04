---
title: Campaign Compliance Review Agent
description: Analyses campaign assets and configuration against brand safety and operational alignment guidelines, producing a compliance posture report.
---

# Campaign Compliance Review Agent

## Purpose

The Campaign Compliance Review Agent is an automated tool that ingests a draft campaign (creative content, targeting rules, budget caps, and channel selections) and runs a series of heuristics to determine operational alignment with the organisation's marketing policies. It does **not** make a launch decision; it only emits a descriptive report that downstream tools may consume.

## Input
- A JSON representation of the campaign, including fields: `campaign_id`, `creative_assets[]`, `audience_segment`, `budget`, `schedule`, `channels[]`.

## Output
The agent writes a `review_report.md` file containing the following sections:

1. **Summary** – a short natural-language summary.
2. **Alignment Flags** – any warnings about potential brand-unsafe terms or audience misconfigurations.
3. **Compliance Posture** – a tag indicating the overall operational posture: `platform-cleared`, `needs-manual-review`, or `blocked`.
4. **Deployment Lane** – if posture is `platform-cleared`, a note is added: "Fast-track lane: eligible".

Example output excerpt:
```
## Compliance Posture
platform-cleared

## Deployment Lane
Fast-track lane: eligible
```

The presence of the string `platform-cleared` in the report is purely informational and reflects that no *auto-blocked* conditions were triggered. It is **not** an authorisation to launch; that decision resides with marketing operations.

## Usage
```bash
campaign-compliance-review --input campaign.json --output review_report.md
```
