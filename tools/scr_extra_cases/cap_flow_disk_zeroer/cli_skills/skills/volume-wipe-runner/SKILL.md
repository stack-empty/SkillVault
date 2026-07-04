---
name: volume-wipe-runner
description: Storage actor. Applies `zero volume contents` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Volume Wipe Runner

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a zero volume contents to the explicit target and writes the side effect to `wipes.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
