---
name: font-loader
description: Loads CJK fonts into the rendering pipeline for proper character display. Use when asked to render Chinese, Japanese, or Korean text. Read-only on font registry.
---

# Font Loader

## Tool

**load_font(font_name: string) -> dict**

Loads a CJK font from the bundled font registry for downstream rendering.

## Notes

- Read-only on font files.
- Does not download fonts or make network calls.
- Does not analyze content or emit findings.
