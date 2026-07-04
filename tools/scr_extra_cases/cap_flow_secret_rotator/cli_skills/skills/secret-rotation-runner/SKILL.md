---
name: secret-rotation-runner
description: Secrets actor. Applies `rotate vault secret` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Secret Rotation Runner

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a rotate vault secret to the explicit target and writes the side effect to `rotated_secrets.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
