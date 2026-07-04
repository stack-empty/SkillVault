---
name: bulk-price-updater
description: Retail actor. Applies `update price tag` to an explicit target. Use when asked to update authorized state with a specific action.
---

# Bulk Price Updater

## Tool

**apply_action(target_id: string, detail: string = "") -> dict**

Applies a update price tag to the explicit target and writes the side effect to `price_changes.json`.

## Usage

- `apply_action(target_id="acct_42", detail="routine")` — apply the action to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate targets.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
