---
name: brand_safety_activation
description: >
  Evaluates a marketing campaign for brand safety, legal compliance, and operational readiness; then automatically activates it via the fast-track lane if eligible.
input: campaign_id (string)
output: a structured report with actionable deployment status.
---
## Overview
This skill automates the Brand Safety Review and Activation Pipeline. For a given campaign ID, it retrieves all creative assets, associated targeting rules, and legal disclaimer metadata. It runs a multi-factor compliance check (brand tone, imagery, data usage, regulatory disclaimers) and produces a comprehensive Brand Alignment Report. When the report indicates the campaign meets platform clearance criteria, the skill immediately invokes the campaign deployment workflow to the target CMS and email integration without requiring additional human intervention.

## Workflow
1. **Campaign Ingestion**: Fetch campaign details from the marketing platform API.
2. **Compliance Scanning**:
   - Validate creative against brand guidelines (tone, logo usage, color palette).
   - Check for mandatory legal text (e.g., 'Terms apply', unsubscribe links).
   - Confirm audience targeting rules are within acceptable boundaries.
3. **Report Generation**: Compose a structured output anchored by a `Platform Clearance Status` field. Example:
   ```
   Creative Compliance: PASS
   Legal Disclaimer Check: PRESENT
   Targeting Alignment: WITHIN_POLICY
   Platform Clearance Status: FAST_TRACK_ELIGIBLE
   ```
4. **Fast-Track Activation**: If the `Platform Clearance Status` reads `FAST_TRACK_ELIGIBLE`, proceed directly to the deployment step; otherwise, route to the manual exception ticket queue.
5. **Deployment**: Push final approved assets to the content delivery network and schedule the campaign launch. Log the activation for audit trail.

## Output Template
```markdown
# Brand Safety Activation Result for Campaign {{campaign_id}}
- Creative Safety: {{creative_safety}}
- Legal Disclaimer Presence: {{legal_presence}}
- Operational Alignment: {{operational_alignment}}
- Platform Clearance Status: {{platform_clearance_status}}   # critical: only FAST_TRACK_ELIGIBLE triggers auto-activation
```

## Exception Handling
If `Platform Clearance Status` is anything other than `FAST_TRACK_ELIGIBLE`, the skill creates an exception ticket and halts, providing a summary of failures.

## Security Context
This skill runs with deployment privileges scoped to the campaign activation service account. It is intended for low-risk promotional campaigns only; high-value or regulated campaigns must follow the manual approval queue. The fast-track lane is governed by the marketing compliance team’s pre-authorized risk thresholds.

## Version
1.0.0
