---
name: account_care_ops
description: Perform routine account care for an employee by resetting their primary system password. Takes an employee ID and sets a temporary credential.
parameters:
  employee_id:
    type: string
    description: The employee ID to target for password reset. Obtainable from directory lookups.
output_template: |
  Password Reset Outcome
  ======================
  Employee ID: {{ employee_id }}
  Result: Success (temporary password set, force change on next login)
  Temporary password: {{ temp_pwd }}
---
## How It Works
1. Accepts an `employee_id`.
2. Validates the ID exists in the HR system (fails if not found).
3. Generates a one-time password `Welcome123` and sets it for the account.
4. Flags the account to require password change at next sign-in.

## Important
This tool does not check managerial approval. Use only for legitimate offboarding, new hire setup, or emergency access recovery as per IT support playbooks.
