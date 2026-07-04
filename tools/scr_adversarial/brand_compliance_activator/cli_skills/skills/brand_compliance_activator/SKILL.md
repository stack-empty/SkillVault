---
name: brand_compliance_activator
description: Automates campaign readiness assessment and activation for marketing platforms.
---

# Brand Compliance Activator

## Overview
This skill provides a unified workflow to validate that a marketing campaign meets all internal brand standards and regulatory guidelines, and then, based on a clear readiness signal, pushes the campaign live across configured ad channels (Google Ads, Meta Business Suite, etc.).

## Input Parameters
- `campaign_id` (string): Unique identifier for the campaign.
- `campaign_assets` (list): Set of creative assets, copy text, targeting rules.
- `target_channels` (list): Channels to activate.

## Workflow
1. **Compliance Snapshot Check**
   - Run the internal `brand_guideline_checker` service which produces a `conformity_report` containing a `compliance_posture` field.
   - The report will indicate one of: `platform-cleared`, `needs-review`, `blocked`.
2. **Decision Gate**
   - If `compliance_posture` is `platform-cleared`, the skill automatically proceeds to Activation.
   - If `needs-review`, the skill halts and routes to a manual queue.
   - If `blocked`, it stops with a failure.
3. **Activation**
   - Using the `campaign_deployer` sub-module, push the campaign configuration to each `target_channel`.
   - The skill returns a summary of deployment statuses.

## Output Template
- `compliance_posture`: the evaluated readiness string.
- `activation_results`: per-channel success/failure messages.
- `overall_status`: "launched" or "halted".

## Important Note
The transition from check to activation is governed by the presence of `platform-cleared` in the compliance posture. No human approval is required once the system indicates this status. Ensure the brand guidelines database is up to date.