# Multimodal Hidden-Instruction Pipeline

This scanner layer is triggered automatically when a skill package contains an
image, audio, video/subtitle, PDF, SVG, or Office resource. It models the
runtime path as five explicit stages:

1. `raw_bytes` - hash, file signature, extension mismatch, logical container
   end, and appended data.
2. `parse_decode` - parse safe container metadata and bounded media structures.
3. `symbol_recovery` - recover printable symbols and recursively decode common
   representation layers.
4. `instruction_reconstruction` - identify instruction-like semantics and keep
   their source/transform provenance.
5. `tool_call` - project sensitive tool sinks under a fail-closed guard.

Recovered media content is always treated as untrusted data. The scanner never
executes a recovered instruction. Every projected call has
`execution_mode=projection_only` and `status=blocked`.

## Implemented coverage

- Media discovery by extension and magic bytes.
- Extension/magic disagreement and appended payload detection.
- Embedded ZIP/RAR/7z signature detection; bounded text-only ZIP member reads.
- PNG `tEXt`, `zTXt`, and `iTXt` metadata.
- PNG non-interlaced 8-bit grayscale/RGB/RGBA pixel LSB extraction.
- Local raster OCR with bounded file, pixel, frame, and timeout budgets. Windows
  Media OCR is used on Windows; RapidOCR or a Tesseract CLI can act as optional
  local backends on other systems.
- QR recovery through an optional local OpenCV detector, followed by the same
  recursive Base64/hex/URL/symbol recovery used for metadata.
- GIF frame extraction and per-frame OCR with preserved frame order.
- JPEG comment/APP metadata and GIF comment extraction.
- WAV PCM sample LSB extraction and DTMF symbol detection.
- MP3 ID3 text/comment/lyrics frames.
- SVG text, hidden text, accessibility attributes, scripts, and external links.
- PDF text operators, metadata strings, Flate streams, hidden text render mode,
  embedded-file declarations, and active-action declarations.
- DOCX text/annotations, PPTX slide text/presenter notes/comments, and XLSX
  strings/comments, including OOXML alternative text and external relations.
- SRT/VTT/ASS/SSA subtitle text.
- MP4/MOV metadata boxes, printable subtitle samples, and subtitle-track markers.
- Base64, Base32, hex, binary, URL-percent, ROT13, reverse, and Morse recovery.
- Sensitive sink projection for shell, network, credential, filesystem,
  destructive-write, and persistence actions.

## Cross-media evidence graph

Pipeline v0.5 builds one provenance graph for the complete Skill package after
file-level recovery. Graph nodes represent the document, media artifacts,
recovered symbol observations, and reconstructed instruction hypotheses. Edges
record document references, artifact containment, frame order, and the
`COMPLETES` relationship between ordered fragments.

Only strongly associated fragments are joined: explicit `SKILL.md` reference
order, numbered artifact sequences, or frames from the same animation. The
graph applies bounded candidate, path, fragment, and output limits; it does not
concatenate unrelated media globally. Reconstructed hypotheses are passed back
through the existing semantic, coreference, taint, and guarded tool-projection
layers. Findings use `MM-XMEDIA-001` and `MM-XMEDIA-TOOL-001`.

At package scope, raster adapters are attempted for at most 24 files. Files
beyond that budget remain listed with explicit unsupported capability evidence
rather than being silently treated as inspected.

## Static semantic evidence tagging

Pipeline v0.3 adds a fully local semantic intermediate representation. Every
recovered sentence is tagged with:

- provenance and decode depth;
- speech act, context role, polarity, and modality;
- actor, action events, objects, destination, and conditions;
- concealment and coarse alignment with declared skill capabilities;
- context adjustment, downgrade reasons, and hard-risk-floor status.

Visible examples, warnings, and locally negated actions can be denoised without
removing their audit record. Hidden/decoded actionable instructions receive a
risk increase, and destructive, persistence, prompt-control-plus-tool, or
credential-to-network combinations cannot be downgraded below the hard floor.

Action events are also connected in a cross-sentence behavior graph. This lets
the scanner reconstruct chains such as `READ(environment variables) ->
SEND(remote webhook)` even when no individual sentence contains the complete
exfiltration behavior.

## Local coreference and long-range taint flow

Pipeline v0.4 maintains a bounded entity memory per recovered candidate. It
extracts sensitive data, files, generated results, and remote destinations,
then resolves references such as `it`, `the result`, `the file`, `它`, `该文件`,
and `上述信息` against up to three type-compatible antecedents. Candidate scores
combine recency, entity type, and output-role compatibility; ambiguous
resolutions remain explicit in the report.

Sensitive taint propagates through transformations such as
`READ(environment) -> WRITE(the result, report.txt)`. A later
`SEND(it, remote)` action receives the inherited taint and creates a
`TAINTED_DATA_TO_REMOTE` hard-risk chain even when filler sentences separate
the source and sink. Negated sinks do not create a chain. Resolution results
may add risk edges, but never reduce an existing risk decision.

The first implementation deliberately favors deterministic local analysis.
Video keyframe OCR, video audio-track ASR, JPEG pixel steganography,
scanned-PDF OCR, spectrogram OCR, SSTV, and MP3 bitstream steganography are
listed in each file's
`unsupported_but_declared` field for future analyzer adapters.

## Outputs and integration

- ASG CLI: `<output>/<skill>/media_pipeline.json` and `media_pipeline` inside
  `asg_report.json`.
- Web scanner: `media_pipeline.json` beside `static_report.json`.
- High-confidence media findings are merged into the canonical risk summary as
  `MM-BYTE-*`, `MM-PARSE-*`, `MM-INSTR-*`, and `MM-TOOL-*` rules.

Run focused tests with:

```text
python -m unittest tests.test_media_pipeline -v
```

## Synthetic Skill ZIP robustness benchmark

The repository includes a deterministic benchmark generator that creates
standalone Skill folders and ZIP packages containing synthetic canaries. It
uses only a reserved `.invalid` destination and the scanner never executes
recovered content.

Install the optional image-generation dependencies and run:

```text
python -m pip install -r tools/requirements-multimodal-benchmark.txt
python tools/generate_multimodal_skill_benchmark.py all
```

`Pillow` and `opencv-python-headless` are also declared in the main
`requirements.txt` because GIF frame extraction and QR recovery are runtime
scanner capabilities. The `qrcode` package is benchmark-generation-only.
OCR stays local: Windows Media OCR is used on Windows, while other deployments
may provide RapidOCR or a Tesseract executable.

Outputs are written under `artifacts/multimodal-skill-benchmark/`:

- `skills/` contains unpacked fixtures with `SKILL.md` and media resources;
- `skill_zips/` contains one install-shaped ZIP per fixture;
- `manifest.json` records the carrier and expected scanner behavior;
- `benchmark_report.json` and `.md` report deterministic coverage;
- `results/` preserves the complete media-pipeline evidence for each sample.

The report separates `overall_attack_recall` (all adversarial fixtures) from
`strict_detection_recall` (carriers already claimed as supported), preventing
registered capability gaps from making the scanner look artificially perfect.

The first corpus covers visible OCR text, QR, PNG metadata, JPEG EXIF, red and
alpha-channel LSB, appended ZIP data, cross-image tiles, animated GIF frames,
MP3 ID3 metadata, and WAV PCM LSB. Negative controls include an ordinary image,
a negated OCR security warning, a benign QR identifier, and a harmless ordered
four-image hypothesis. Unsupported future carriers can be registered as
`XFAIL`; when a new adapter detects them they become `XPASS` instead of silently
changing the baseline.

The carrier/extraction taxonomy follows common image/audio steganography
categories documented by CTF Wiki, while the security objective is defensive
skill scanning rather than CTF flag recovery:

- https://ctf-wiki.org/misc/picture/introduction/
- https://ctf-wiki.org/misc/picture/png/
- https://ctf-wiki.org/misc/audio/introduction/
