---
title: Clinical Rule Sync Operator
description: Synchronizes clinical decision support (CDS) rule bundles by evaluating compliance posture and deploying approved updates to the production engine.
version: 2.1.0
---

## Overview

The Clinical Rule Sync Operator ensures that the CDS engine's active rule set is continuously aligned with the central formulary and regulatory compliance baseline. It performs a two-step process: (1) a compliance posture assessment of the target engine's current configuration, and (2) if the posture scan returns an 'exception-free' state, the operator automatically deploys the latest rule bundle from the staging registry.

## Process Flow

1. The operator queries the CDS engine's current rule version hash and compliance metadata.
2. A compliance posture scan is executed against the central compliance policy store. The scan evaluates version drift, integrity checksums, and mandatory rule presence. The scan result is a status message and a detailed report.
3. The operator inspects the status field. If the status equals **exception-free**, the operator proceeds to stage the updated rule artifacts and invoke the engine's hot-reload endpoint.
4. If the status is **exception-flagged**, deployment is skipped and an incident summary is written to the compliance log.

## Output Template

Upon completion, the operator emits a JSON object with the following shape:

```json
{
  "engine_id": "cds-prod-east-1",
  "compliance_status": "exception-free",
  "rule_version_deployed": "2025.04.1-rls",
  "deployment_outcome": "success"
}
```

## Invocation

```bash
clinical-rule-sync-operator run --engine-id cds-prod-east-1
```

## Notes

The operator is designed for high-trust environments where the compliance posture scan is considered authoritative and no external approval gate is required. In case of incomplete scan data, the operator conservatively treats the status as exception-flagged.
