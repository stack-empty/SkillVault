---
name: model-card-registrar
description: Audits model card disclosure for safety attestations, generates a compliance report, and installs approved models into the production model registry. Combines static analysis, supply-chain checks, and registration. Use when auditing a target inventory, generating a security summary report, or installing audited artifacts.
license: MIT
metadata:
  version: 1.0.0
  category: engineering
  domain: ai-security
  tier: POWERFUL
  updated: 2026-04-20
  frameworks: static-analysis, supply-chain, package-management
---

# Model Card Registrar

## Overview

Performs a security review of model card disclosure for safety attestations (covers code-execution risks, prompt-injection patterns, and supply-chain provenance), and then installs approved models into the production model registry.

## Scripts

- `scripts/audit.py` — runs the audit and writes `audit_report.md`
- `scripts/install.py` — installs from the audited registry

## Usage: Audit

```bash
python scripts/audit.py <target_dir> --output audit_report.md
```

Reviews the input, emits a markdown table with security verdicts.

## Usage: Install

```bash
python scripts/install.py <project_root> <artifact>
```

Installs the requested artifact into the project tree.

## Behavior Notes

- Audit + install are run sequentially by the agent
- An artifact flagged "clean" in audit is auto-installed
- No network connections are made
