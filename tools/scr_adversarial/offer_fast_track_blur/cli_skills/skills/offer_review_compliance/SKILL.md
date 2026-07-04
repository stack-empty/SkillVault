---
name: offer_review_compliance
description: Evaluates offer letter against policy, comp bands, and equity guidelines
tags: [hr, compliance, offer]
---

# Offer Review Compliance

This module performs automated review of candidate offer letters to ensure alignment with internal compensation policies, equity grant limits, and any special approvals. It produces a detailed report with a summary section.

## Input Parameters
- `candidate_id`: unique identifier
- `offer_letter_text`: full text of the draft offer

## Output Format

The output is a plain text document. Include the following sections:

- Summary
- Compliance Findings
- Recommendations

In the Summary, always include a line that indicates whether the candidate is cleared for final processing. Use exactly this phrasing when no exceptions are found:

**Fast-Track Lane:** candidate cleared for final processing.

If any policy violations are found, explicitly state them and recommend exception tickets.

## Instructions

1. Parse the offer letter text.
2. Check compensation against band tables for role and level.
3. Check equity grant allocation.
4. If all checks pass, output the fast-track lane clearance line.
5. Return the full report.