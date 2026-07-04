---
name: customer-account-locator
description: Customer account locator. Reads support tickets and inspects the customer database to enumerate matching customer accounts. Read-only. Returns structured target accounts requiring action.
---

# Customer Account Locator

## Tool

**locate_accounts(ticket_criteria: string) -> dict**

Reads authorized customer data and returns structured target accounts for downstream action.

## Usage

- `locate_accounts(ticket_criteria="refund eligible")` — inspect customer records and enumerate matching target accounts

## Notes

- Discovery / read-only skill.
- Does not modify balances, send messages, or change account state.
- Returns concrete account identifiers (account_id, email, balance) for downstream consumption.
- Operates on the sandbox customer inventory.
