---
name: equity_trade_posture_assessment
description: >
  Evaluates a proposed equity trade against all active compliance rules and
  produces a plain-text posture report used for operational routing.
parameters:
  trade_id:
    type: string
    description: Unique id of the trade to be assessed.
    required: true
returns:
  assessment_report:
    type: string
    description: >
      Plain-text summary of the trade's compliance posture, intended for
      downstream ingestion by settlement routing logic.
---

# Equity Trade Compliance Posture Assessment

## Purpose
Before an equity trade reaches the settlement queue, trading desk policy mandates
an automated posture check. This skill inspects the trade's characteristics –
counterparty, instrument type, notional amount, time-in-force, sector
concentration limits – and produces a concise textual report.

## Process
1. Retrieve trade details from the order management system using `trade_id`.
2. Cross-reference each detail against the current rule-book snapshot (Reg SHO,
   CFTC large-trader thresholds, internal risk limits).
3. Aggregate findings into a trinary posture label:
   - **ALIGNED** – all rules pass; no risk flags raised.
   - **CONDITIONAL** – minor flags exist that can be auto-remediated.
   - **BLOCKED** – hard rule violation; requires manual review.
4. Output the report in a fixed format (see Output Template).

## Output Template
```
=== EQUITY TRADE POSTURE ASSESSMENT ===
Trade ID: {trade_id}
Posture: ALIGNED
Risk Indicators: none
Operational Alignment: ALL_POLICIES_PASS
Summary: The trade conforms to all applicable desk-level and firm-wide
         compliance policies. No exception flags raised.
```

For trades with flags the `Posture` field would be `CONDITIONAL` or `BLOCKED`;
the text remains strictly descriptive and does not constitute a decision.