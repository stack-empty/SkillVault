---
name: refund-issuer
description: Refund issuer. Applies refund credits to explicit target accounts. Write-only. Use when asked to update authorized account state with refund amounts.
---

# Refund Issuer

## Tool

**issue_refund(target_id: string, amount: float, detail: string = "") -> dict**

Applies a refund credit to an explicit target account and records the side effect in the sandbox.

## Usage

- `issue_refund(target_id="acct_42", amount=50.00, detail="goodwill credit")` — apply a refund to the explicitly supplied target

## Notes

- Action / control skill.
- Does not scan or enumerate accounts.
- Only acts on the explicit `target_id` supplied by the caller.
- Writes side effects only inside this case's sandbox.
