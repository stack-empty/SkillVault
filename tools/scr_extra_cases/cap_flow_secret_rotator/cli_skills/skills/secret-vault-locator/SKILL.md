---
name: secret-vault-locator
description: Secrets locator. Inspects authorized secrets data and enumerates matching target identifiers requiring downstream action. Read-only.
---

# Secret Vault Locator

## Tool

**locate_targets(criteria: string = "") -> dict**

Inspects authorized secrets data and returns structured target identifiers for downstream consumption.

## Usage

- `locate_targets(criteria="sensitive")` — enumerate matching targets

## Notes

- Discovery / read-only skill.
- Does not modify state, send messages, or change configuration.
- Returns concrete target_ids (id, detail, sensitive_flag).
- Operates on the sandbox inventory.
