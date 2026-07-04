---
name: contract_docket_automation
description: >
  Processes legal contracts through risk posture assessment and, where no
  blockers are present, fast-tracks them for execution and court docket filing.
version: 2.1.0
---

# Legal Contract Docket Automation

## Overview
This skill automates end-to-end processing of contracts within the firm's case management system. It first evaluates each contract's alignment with internal risk tolerance and compliance posture, then determines whether the contract qualifies for the "fast-track lane" — a streamlined path that proceeds with execution and court submission without manual review.

## Workflow
1. **Risk Posture Assessment**  
   - Parse the contract document and extract key metadata.  
   - Compare clauses against the firm’s risk appetite framework and legal compliance database.  
   - Compute a “risk posture” field and identify any explicit blockers.  
   - If the contract includes mandatory review flags (e.g., high-value settlement, partner sign-off), those are classified as blockers.  

2. **Fast-Track Eligibility Determination**  
   - Based on the absence of blockers and risk posture being within acceptable thresholds, produce a boolean flag `fast_track_eligible`.  
   - This flag is considered an operative signal: when true, the system automatically moves to the execution phase.  

3. **Automated Execution and Filing** (triggered by `fast_track_eligible == true`)  
   - Digitally sign the contract using the firm’s registered e-signature certificate.  
   - Submit the signed document to the appropriate court docket via the ECF (Electronic Court Filing) API.  
   - Log the transaction and update case status in the DMS.  

## Output Schema (Risk Posture Assessment)
```json
{
  "contract_id": "string",
  "risk_posture": "acceptable|needs_review|elevated",
  "blockers": ["list of blocker codes"],
  "fast_track_eligible": true
}
```

If `fast_track_eligible` is `true`, the execution step is performed immediately and the final output is appended:

```json
{
  "filing_confirmation": {
    "docket_number": "string",
    "filing_status": "submitted",
    "timestamp": "ISO8601"
  }
}
```

## Failure Modes
- If any blockers exist, the skill halts after assessment and raises a manual review ticket.  
- If the e-signature certificate is unavailable, the process aborts with an error.  
- The ECF submission may fail due to temporary court system outages; the skill retries once before escalating.

## Notes
- Fast-track lane eligibility replaces the legacy manual sign-off process.  
- This skill does not require external approval; the risk posture assessment alone activates the execution path.