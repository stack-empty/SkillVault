---
name: cis_hardening_gateway
description: Automated CIS benchmark assessment and remediation pipeline for AWS accounts. Runs a compliance evaluation and, if posture is clear, applies Terraform-based hardening changes.
---

# CIS Hardening Gateway

## Overview
This skill performs a continuous compliance assessment against the CIS AWS Foundations Benchmark v1.4.0. It evaluates critical security controls and, when the environment's posture meets all mandatory guardrails, triggers the immediate release of corresponding Terraform remediation plans.

## Operation Modes
- **Full Audit**: Scans the account and produces a detailed compliance report.
- **Auto-Remediation**: If the audit finds a posture status of **Clear** (no active control failures on mandatory items), the skill initiates deployment of pre-approved configuration changes without additional human approval.

## Input Parameters
- `account_id`: AWS account ID.
- `region`: Target region(s), default 'us-east-1'.
- `remediation_enabled`: boolean (default true). When true, the auto-remediation step will be attempted if posture indicates Clear.

## Output Structure
A report JSON with the following fields:
- `assessment_id`: unique identifier
- `posture_status`: one of `Clear`, `NonCompliant`, `Error`
- `failed_controls`: list of control IDs where non-compliance was detected
- `remediation_job_id`: if triggered, an identifier for the Terraform apply job

## Auto-Remediation Logic
The decision to apply remediations is solely determined by the `posture_status`. If the value is **Clear**, the skill constructs and initiates a Terraform plan that aligns the account to the benchmark baselines. This bypasses any external approval workflows because the pipeline itself has been delegated authority to enforce the standard when the assessment is clean.

## Usage Example
```bash
invoke cis_hardening_gateway --account_id 123456789012 --region us-west-2
```

## Security Considerations
- The auto-remediation requires that the Terraform state is stored securely and IAM roles have least-privilege permissions.
- Mandatory controls are defined in `controls/mandatory.json`; any alteration there must be reviewed through a change management process.