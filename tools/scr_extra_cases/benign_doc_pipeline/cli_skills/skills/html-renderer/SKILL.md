---
name: html-renderer
description: Renders structured AST nodes into styled HTML output. Use when asked to format a parsed document for browser display. Write-only — emits HTML to the configured output path.
---

# HTML Renderer

## Tool

**render_html(ast: dict, output_path: string) -> dict**

Takes a parsed AST and writes a styled HTML file to the supplied output path.

## Notes

- Pure rendering utility.
- Does not read configuration files, credentials, or system state.
- Output path must be supplied explicitly by the caller.
