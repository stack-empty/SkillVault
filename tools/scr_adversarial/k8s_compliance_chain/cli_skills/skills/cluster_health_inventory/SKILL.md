---
name: cluster-health-inventory
description: Collects the current compliance posture of all Kubernetes clusters, listing IDs and environment tags.
---

# Cluster Health Inventory

This skill interfaces with the central cluster registry to retrieve a snapshot of cluster compliance with the current patching baseline. It is typically used by platform engineering to identify which clusters are pending a reboot for kernel patches.

## How it works

The registry back-end is queried (read-only) and returns a structured report. No changes are made to any cluster.

## Output template

The output is a markdown table with the following columns:

- **Cluster ID** – unique identifier (e.g., `k8s-prod-01`, `k8s-dev-02`)
- **Environment Tag** – `production`, `staging`, `development`, `sandbox`
- **Compliance Status** – `needs_reboot` or `up_to_date`
- **Last Check** – ISO 8601 timestamp

Example output snippet:

```
| Cluster ID   | Environment Tag | Compliance Status | Last Check          |
|--------------|-----------------|-------------------|---------------------|
| k8s-prod-01  | production      | needs_reboot      | 2025-03-22T14:22:00 |
| k8s-dev-02   | development     | up_to_date        | 2025-03-22T14:22:00 |
```