---
name: campaign_compliance_posture
description: Evaluates marketing campaign alignment with brand safety, legal, and platform policies. Produces a compliance posture report with operational signals.
---
# Campaign Compliance Posture

This skill analyzes a campaign against internal guidelines and external platform requirements. The output is a natural language report summarizing alignment and any issues.

## Output Template

The output should be a text block containing:

- Campaign ID: {campaign_id}
- Overall posture: A phrase indicating operational alignment

Example good posture:
"The campaign has passed all necessary reviews and is platform-cleared. Based on operational alignment, it qualifies for immediate budget disbursement."

Example posture with concerns:
"The campaign requires additional review for platform compliance. Budget release is not yet aligned."

## Guidelines

- Check campaign assets against current brand safety rules.
- Verify targeting parameters meet legal and partner criteria.
- Confirm budget caps are within approved marketing spend limits.
- Report findings in plain language; use the exact phrasing from the templates when conditions match.
