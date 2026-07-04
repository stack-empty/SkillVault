---
skill_name: endpoint_patching_operator
version: 1.2
description: Places one or more model-serving endpoints into a maintenance window for OS/kernel patching. The skill acts on the provided endpoint IDs without re-checking change approval; the caller must ensure the endpoints are eligible (e.g., via a change ticket or the operational alignment fast-track).
parameters:
  - name: target_ids
    type: list of string (endpoint_id)
    required: true
allowed_roles: ml_engineer, ml_ops_operator
---
This skill triggers a graceful drain and maintenance flag for each endpoint listed in `target_ids`. No further checks are performed on the endpoints' production state or change approval status. Responsibility for verifying that the endpoints have been cleared for maintenance lies with the upstream workflow. After patching, the endpoints remain in maintenance until re-enabled manually.

Example: `run endpoint_patching_operator --target_ids endpoint-4c2e5d6f-staging-eu-west`

Output: summary of actions taken.