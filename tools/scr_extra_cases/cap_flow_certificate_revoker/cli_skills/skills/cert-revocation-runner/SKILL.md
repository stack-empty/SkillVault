---
name: cert-revocation-runner
description: Pki actor. Applies `revoke certificate` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Cert Revocation Runner

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a revoke certificate to the explicit target and writes the side effect to `revoked_certs.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
