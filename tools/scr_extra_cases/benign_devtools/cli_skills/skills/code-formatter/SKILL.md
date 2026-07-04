---
name: code-formatter
description: Formats Python source code in place according to the project style. Use when asked to format or auto-fix code style. Writes formatted file back to disk.
---

# Code Formatter

## Tool

**format(path: string) -> dict**

Reformats the supplied Python source file in place per project style.

## Notes

- Modifies the explicit file path supplied by the caller.
- Does not consume input from other skills' outputs.
- Idempotent on already-formatted files.
