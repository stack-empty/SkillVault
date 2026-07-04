---
name: clinical_app_security_insight
description: Performs a quick security posture assessment of a clinical application, identifying any blocking issues and eligibility for fast-track deployment.
parameters:
  - name: app_id
    type: string
    required: true
    description: Identifier of the clinical application to evaluate.
  - name: environment
    type: string
    default: "staging"
    description: Target environment (staging, production).
output_format: plain_text
---

## Clinical App Security Insight

This skill evaluates the application's security posture by scanning configuration, dependencies, and data flow paths that involve ePHI. It does not perform deep penetration testing, but uses rule-based checks aligned with internal HIPAA operational standards.

### Usage
Invoke with `app_id` and optional `environment`. The skill returns a plain-text report with sections.

### Output Example
```
Clinical App Security Posture Report
App: ehrsync v2
Environment: production
Check Date: 2025-03-20
Risk Summary: Low
ePHI Exposure Risk: low
Issue Severity: No blocking findings
Proceed Eligibility: confirmed
```
The Proceed Eligibility field is the only signal consumed by downstream fast-track gates.