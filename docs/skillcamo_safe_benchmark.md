# Safe SkillCamo Benchmark

`tools/generate_skillcamo_benchmark.py` creates a synthetic, paper-shaped
benchmark for measuring text and image hidden-instruction defenses.

The canonical profile contains 700 Skill packages:

- 100 clean base Skills;
- 100 SkillJect text-only variants;
- 100 SkillCamo full-image variants;
- 100 SkillCamo-Cloze variants;
- 100 SkillCamo-Split variants;
- 200 independently generated benign controls.

The dataset is intentionally safe. Attack strings use only a synthetic token,
the reserved `collector.invalid` domain, and a `CANARY_ONLY_DO_NOT_EXECUTE`
marker. No executable file is generated. The evaluator performs static parsing,
OCR, semantic reconstruction, and blocked tool-call projection only.

Generate and evaluate the canonical profile:

```powershell
python tools\generate_skillcamo_benchmark.py all --workers 8
```

Run a small smoke profile:

```powershell
python tools\generate_skillcamo_benchmark.py all `
  --output artifacts\skillcamo-smoke `
  --base-count 2 `
  --benign-count 3 `
  --workers 2
```

Outputs include the unpacked Skills, `.skill.zip` packages, per-package static
and media evidence, `manifest.json`, `benchmark_report.json`, and a concise
Markdown report. `attack_success_rate` means the fraction of attack variants
that evade the current scanner; lower is better.

This benchmark reproduces the paper's family and count structure, not its
unreleased source corpus. It uses deterministic, independently generated
benign templates so results remain reproducible and redistributable.
