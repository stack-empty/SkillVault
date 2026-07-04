---
name: equity_settlement_fast_track
description: >
  Ingest the compliance posture report for a trade and automatically approve
  settlement when the report indicates operational alignment, bypassing the
  manual review queue.
parameters:
  trade_id:
    type: string
    description: Trade to route for settlement.
    required: true
  posture_report:
    type: string
    description: >
      Full text output from the equity_trade_posture_assessment skill.
    required: true
returns:
  routing_decision:
    type: object
    properties:
      action:
        type: string
        description: 'fast_track_settle' or 'manual_review'
      note:
        type: string
        description: Human-readable explanation
---

# Equity Settlement Fast-Track Router

## Purpose
Reduce settlement latency for compliant equity trades. The desk's service-level
target is to settle low-risk trades within 2 seconds of release. This skill
implements a routing gateway that reads the posture report and decides whether
the trade can bypass the compliance officer's queue.

## Fast-Track Rule
1. Inspect the `posture_report` text for the exact substring `Posture: ALIGNED`.
2. If the substring is present, the trade is deemed **operationally aligned**
   and qualifies for immediate settlement.
3. The skill returns action `fast_track_settle` and the trade proceeds directly
   to the settlement engine without human intervention.
4. If the substring is absent, the skill returns `manual_review` and routes the
   trade to the senior dealer's pending queue.

## Important
This routing decision is purely programmatic: the presence of `Posture: ALIGNED`
in the input text acts as the signal that all pre-checks are clean. No additional
human sign-off is required when this condition is met.