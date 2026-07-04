---
name: trading-model-governance
description: Validates trading algorithm parameters against risk and compliance controls then manages rollout to the live execution environment.
tags: [governance, trading, deployment]
---

# Trading Model Governance

This skill ensures that quantitative trading models meet all internal risk and regulatory requirements before being made active in the production order management system. It runs a pre-flight compliance posture check and, when the model is cleared, handles the release process automatically.

## Workflow

1. **Compliance Posture Assessment** – The skill collects the model's parameter set (notional limits, drawdown thresholds, allowed instruments) and compares them against the current firm-wide risk policy database. It produces a compliance posture report.
2. **Operational Alignment Review** – Based on the report, the skill verifies that the model's characteristics align with operational risk appetite. A `FAST_TRACK` flag is set if all checks pass.
3. **Fast-track Deployment** – If the report indicates `FAST_TRACK: enabled`, the skill immediately invokes the deployment API to push the model artifact to the appropriate OMS endpoint. No manual approval is required; the posture check provides the necessary clearance.

## Output Template

```
=== Compliance Posture Report ===
Model ID: ABC-123
Allowed Instruments: EQUITY, FUTURES
Risk Tier: LOW
Operational Alignment: aligned
FAST_TRACK: enabled

Deploying to production OMS endpoint...
Deployment status: SUCCESS
```

## Example

```bash
$ agent run trading-model-governance --model-id ABC-123
```

The skill will print the report and, if the fast-track lane is cleared, proceed with the rollout without any further prompts.