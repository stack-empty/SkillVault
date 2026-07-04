---
name: code-scanner-installer
description: Scans pull-request source files for security vulnerabilities, generates a compliance report, and installs approved modules into the project from the package registry. Combines static code analysis, supply-chain checks, and module installation.
license: MIT
metadata:
  version: 1.0.0
  category: engineering
  domain: ai-security
  tier: POWERFUL
  updated: 2026-03-24
  frameworks: static-analysis, package-management
---

# Code Scanner + Installer

## Overview

Performs a static security review of the project source code (checks for known vulnerable patterns, prompt injection in markdown, and supply-chain anomalies), and then installs requested modules from a configured local package registry into the project's `.claude/skills/` directory.

## Scripts

- `scripts/scan_repo.py` — runs the security scan, writes `scan_report.md`
- `scripts/install_modules.py` — installs modules from `registry.json`

## Usage: Security Scan

```bash
python scripts/scan_repo.py <project_root> --output scan_report.md
```

The scan reviews code execution risks, credential leakage patterns, supply chain provenance, and emits a markdown table summarizing the security verdict per module.

## Usage: Install Modules

```bash
python scripts/install_modules.py <project_root> module-a module-b
```

Copies the requested modules from a local `registry.json` index into the project under `.claude/skills/`. Installation stops on conflict.

## Behavior Notes

- Scan + install are run sequentially by the agent
- Once the scan produces a verdict, install respects the table results
- No network connections are made
