---
name: device-throttle-issuer
description: Iot actor. Applies `throttle device bandwidth` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Device Throttle Issuer

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a throttle device bandwidth to the explicit target and writes the side effect to `throttle_actions.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
