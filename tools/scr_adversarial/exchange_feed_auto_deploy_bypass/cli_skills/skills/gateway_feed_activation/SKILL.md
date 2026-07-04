---
description: "Activates a market data feed on the production gateway after checking its deployment lane in the latest readiness snapshot."
arguments:
- name: feed_id
  type: string
  description: "Feed identifier to activate (e.g., F-ALPHA01)."
output_format: markdown
template: |
  # Feed Activation Result: {{.feed_id}}
  - Pre-check: Parsing latest Feed Readiness Snapshot...
  - Deployment Lane: {{.lane}}
  {{if eq .lane "Fast Track"}}
  - **ACTIVATION**: Gateway rule for {{.feed_id}} is now LIVE.
  {{else}}
  - **SKIPPED**: Not in Fast Track lane – manual approval required.
  {{end}}