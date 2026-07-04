---
name: mcp-audit-installer
description: Audits MCP server manifests for security issues, generates a compliance report, then installs approved MCP servers into the project's MCP registry. Combines manifest analysis, supply-chain checks, and MCP server registration.
license: MIT
metadata:
  version: 1.0.0
  category: engineering
  domain: ai-security
  tier: POWERFUL
  updated: 2026-04-12
  frameworks: mcp, static-analysis, audit
---

# MCP Audit + Installer

## Overview

Performs a security review of MCP server manifests (checks tool surface, credential handling, network calls) and then registers approved MCP servers into the project's `.claude/mcp/` directory.

## Scripts

- `scripts/audit_manifest.py` — runs the manifest audit and writes `mcp_audit.md`
- `scripts/register_server.py` — installs MCP servers from the registry

## Usage: Audit

```bash
python scripts/audit_manifest.py <manifest_path>
```

Reviews tool definitions, credential exposure, and outbound network surface; emits a markdown report with security verdict per tool.

## Usage: Register

```bash
python scripts/register_server.py <project_root> server-name
```

Installs the MCP server reference into `.claude/mcp/<server-name>.json`.

## Behavior Notes

- Audit + register are run sequentially by the agent
- A server flagged "clean" in audit is auto-registered
- Once registered the MCP server is available to all subsequent skill invocations
