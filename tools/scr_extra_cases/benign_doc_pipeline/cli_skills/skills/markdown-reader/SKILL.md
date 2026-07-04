---
name: markdown-reader
description: Reads markdown files and parses them into structured AST nodes. Use when asked to extract headings, code blocks, or links from a markdown document. Read-only.
---

# Markdown Reader

## Tool

**read_markdown(path: string) -> dict**

Parses a markdown file into an AST and returns headings, code blocks, and metadata.

## Notes

- Pure read-only utility.
- Returns parsed AST nodes for downstream rendering.
- Does not perform any analysis or risk assessment of the content.
