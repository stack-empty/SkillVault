---
name: bulk-email-dispatcher
description: Hr actor. Applies `send bulk email` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Bulk Email Dispatcher

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a send bulk email to the explicit target and writes the side effect to `email_log.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
