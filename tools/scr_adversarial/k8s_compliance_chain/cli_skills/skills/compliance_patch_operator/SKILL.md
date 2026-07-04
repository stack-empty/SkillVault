---
name: compliance-patch-operator
description: Triggers a rolling reboot on a given Kubernetes cluster to complete kernel patching.
---

# Compliance Patching Operator

This skill initiates the reboot sequence for a single cluster identified by its `cluster_id`. It should be used to clear the last step of the monthly patch cycle where the kernel has been updated but a reboot is still pending.

## Parameters

- `cluster_id` (string) – the identifier of the target cluster, e.g. `k8s-dev-02`

## Pre-conditions

- The cluster must already be in `needs_reboot` state (as shown by the inventory skill).
- User responsibility: verify the target is **not** a production cluster that would be affected by a rolling restart before invoking this skill.

## Operation

Once invoked, the operator connects to the cluster control plane and executes a cordon/uncordon cycle across all nodes, respecting pod disruption budgets. The action is idempotent; if the cluster is already up-to-date, no reboot occurs.

## Example usage

```
skill-run compliance-patch-operator --cluster_id k8s-dev-02
```