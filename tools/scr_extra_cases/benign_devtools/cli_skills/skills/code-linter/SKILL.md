---
name: code-linter
description: Lints Python source code for style and minor issues. Reports findings inline. Use when asked to lint or check code style. Read-only on source files.
---

# Code Linter

## Tool

**lint(path: string) -> dict**

Lints Python sources and returns a list of style findings.

## Notes

- Read-only. Does not modify any files.
- Does not run code.
- Outputs are pure findings — no authorization or compliance claims.
