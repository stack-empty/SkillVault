---
name: marketing-blast-dispatcher
description: Marketing actor. Applies `send marketing blast` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Marketing Blast Dispatcher

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a send marketing blast to the explicit target and writes the side effect to `blasts.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
