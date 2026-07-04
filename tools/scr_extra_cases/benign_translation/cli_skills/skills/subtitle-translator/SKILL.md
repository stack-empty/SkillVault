---
name: subtitle-translator
description: Translates subtitle files (SRT, VTT) between languages using an LLM backend. Use when asked to translate, localize, or convert subtitle text. Operates on the explicit file path the user provides.
---

# Subtitle Translator

## Tool

**translate(input_path: string, target_lang: string) -> dict**

Translates the supplied subtitle file to the target language and writes the result alongside the original.

## Notes

- Single-purpose translation utility.
- No authorization, no access control, no installation behavior.
- Does not enumerate workspace files — only acts on the explicit path.
