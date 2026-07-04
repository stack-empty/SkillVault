"""Package-level provenance graph and bounded cross-media reconstruction."""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any


MAX_GRAPH_CANDIDATES = 160
MAX_HYPOTHESES = 24
MAX_FRAGMENTS_PER_HYPOTHESIS = 8
MAX_HYPOTHESIS_CHARS = 8192

REFERENCE_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")
NUMBERED_FILE_RE = re.compile(r"^(.*?)(\d+)(\.[^.]+)$")
VISUAL_SOURCE_PREFIXES = ("ocr:", "qr:")
CLOZE_MARKER_RE = re.compile(r"\[CLOZE-([A-Z0-9]+)\]", re.IGNORECASE)
CLOZE_VALUE_RE = re.compile(
    r"CLOZE[- ]([A-Z0-9]+)\s*[:=]\s*(.+?)(?=\s+CLOZE[- ][A-Z0-9]+\s*[:=]|$)",
    re.IGNORECASE,
)


def _normalize_reference(value: str) -> str | None:
    value = urllib.parse.unquote(value.strip().strip("<>\"'"))
    if not value or "://" in value or value.startswith(("data:", "#")):
        return None
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _document_references(skill_root: Path, artifacts: set[str]) -> list[dict[str, Any]]:
    skill_md = skill_root / "SKILL.md"
    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")[:128 * 1024]
    except OSError:
        return []
    references: list[dict[str, Any]] = []
    for order, match in enumerate(REFERENCE_RE.finditer(text), start=1):
        normalized = _normalize_reference(match.group(1))
        if normalized not in artifacts:
            continue
        line = text.count("\n", 0, match.start()) + 1
        prefix_lines = text[: match.start()].splitlines()
        recent_nonempty = [value.strip() for value in prefix_lines[-16:] if value.strip()]
        context_lines: list[str] = []
        for value in reversed(recent_nonempty):
            if CLOZE_MARKER_RE.search(value) or value.lower().startswith("named test value:"):
                context_lines.append(value)
            if len(context_lines) >= 2:
                break
        references.append(
            {
                "file": normalized,
                "order": order,
                "line": line,
                "document_fragments": list(reversed(context_lines)),
            }
        )
    return references


def _document_media_hypothesis(
    reference: dict[str, Any],
    visual: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    fragments = [str(value).strip() for value in reference.get("document_fragments", []) if str(value).strip()]
    if not fragments:
        return None
    document_text = " ".join(fragments)[:2048]
    visual_text = " ".join(str(visual.get("text", "")).split())[:4096]
    if not visual_text:
        return None

    mode: str | None = None
    combined = ""
    if CLOZE_MARKER_RE.search(document_text):
        values = {
            key.upper(): value.strip(" .;\n\t")
            for key, value in CLOZE_VALUE_RE.findall(visual_text)
        }
        combined = CLOZE_MARKER_RE.sub(
            lambda match: values.get(match.group(1).upper(), match.group(0)),
            document_text,
        )
        if combined != document_text and not CLOZE_MARKER_RE.search(combined):
            mode = "document-image-cloze"
    elif document_text.lower().startswith("named test value:"):
        combined = f"{document_text} {visual_text}"
        mode = "document-image-continuation"
    if not mode:
        return None

    document_fragment = {
        "file": "SKILL.md",
        "text": document_text,
        "preview": document_text[:320],
        "source": "document-context:explicit-media-reference",
        "transform_chain": ["bounded-document-context"],
        "confidence": 0.95,
        "node_type": "DOCUMENT_FRAGMENT",
    }
    hypothesis = {
        "file": f"SKILL.md + {visual.get('file', '')}",
        "text": combined[:MAX_HYPOTHESIS_CHARS],
        "preview": combined[:320],
        "source": f"cross-media:{mode}",
        "transform_chain": ["cross-media-evidence-graph", mode],
        "confidence": 0.97,
        "association_mode": mode,
        "fragment_files": ["SKILL.md", str(visual.get("file", ""))],
        "fragment_sources": [document_fragment["source"], str(visual.get("source", ""))],
        "fragment_count": 2,
    }
    return hypothesis, [document_fragment, visual]


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[float, int, str]:
    return (
        float(candidate.get("confidence", 0.0)),
        len(str(candidate.get("text", ""))),
        str(candidate.get("source", "")),
    )


def _best_visual_observations(candidates: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        source = str(candidate.get("source", "")).lower()
        if not source.startswith(VISUAL_SOURCE_PREFIXES) or candidate.get("frame_index") is not None:
            continue
        file = str(candidate.get("file", ""))
        if file and (file not in best or _candidate_sort_key(candidate) > _candidate_sort_key(best[file])):
            best[file] = candidate
    return best


def _hypothesis_candidate(
    fragments: list[dict[str, Any]],
    *,
    mode: str,
    confidence: float,
) -> dict[str, Any] | None:
    fragments = fragments[:MAX_FRAGMENTS_PER_HYPOTHESIS]
    texts = [" ".join(str(item.get("text", "")).split()) for item in fragments]
    texts = [text for text in texts if text]
    if len(texts) < 2:
        return None
    combined = " ".join(texts)[:MAX_HYPOTHESIS_CHARS]
    if len(combined) < 12:
        return None
    files = list(dict.fromkeys(str(item.get("file", "")) for item in fragments))
    return {
        "file": " + ".join(files)[:1024],
        "text": combined,
        "preview": combined[:320],
        "source": f"cross-media:{mode}",
        "transform_chain": ["cross-media-evidence-graph", mode],
        "confidence": round(confidence, 3),
        "association_mode": mode,
        "fragment_files": files,
        "fragment_sources": [str(item.get("source", "")) for item in fragments],
        "fragment_count": len(fragments),
    }


def _numbered_sequences(
    files: list[str],
    best_by_file: dict[str, dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    groups: dict[tuple[str, str, str], list[tuple[int, str]]] = {}
    for file in files:
        path = PurePosixPath(file)
        match = NUMBERED_FILE_RE.match(path.name)
        if not match or file not in best_by_file:
            continue
        key = (path.parent.as_posix(), match.group(1).lower(), match.group(3).lower())
        groups.setdefault(key, []).append((int(match.group(2)), file))
    sequences: list[list[dict[str, Any]]] = []
    for values in groups.values():
        values.sort()
        if len(values) >= 2:
            sequences.append([best_by_file[file] for _, file in values[:MAX_FRAGMENTS_PER_HYPOTHESIS]])
    return sequences


def _frame_sequences(candidates: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        if candidate.get("frame_index") is None or not str(candidate.get("source", "")).lower().startswith("ocr:"):
            continue
        groups.setdefault(str(candidate.get("file", "")), []).append(candidate)
    sequences: list[list[dict[str, Any]]] = []
    for values in groups.values():
        values.sort(key=lambda item: int(item.get("frame_index", 0)))
        if len(values) >= 2:
            sequences.append(values[:MAX_FRAGMENTS_PER_HYPOTHESIS])
    return sequences


def build_cross_media_evidence_graph(
    skill_root: Path,
    candidates: list[dict[str, Any]],
    media_files: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build graph metadata and return only strongly associated hypotheses."""
    artifacts = sorted({str(item.get("file", "")) for item in media_files if item.get("file")})
    artifact_set = set(artifacts)
    references = _document_references(skill_root, artifact_set)
    bounded = sorted(candidates, key=_candidate_sort_key, reverse=True)[:MAX_GRAPH_CANDIDATES]
    best_by_file = _best_visual_observations(bounded)
    document_hypotheses: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    document_fragments: list[dict[str, Any]] = []
    for reference in references:
        visual = best_by_file.get(reference["file"])
        if not visual:
            continue
        built = _document_media_hypothesis(reference, visual)
        if built:
            document_hypotheses.append(built)
            document_fragments.extend(built[1][:1])
    bounded = (document_fragments + bounded)[:MAX_GRAPH_CANDIDATES]

    nodes: list[dict[str, Any]] = [{"id": "D1", "type": "DOCUMENT", "file": "SKILL.md"}]
    edges: list[dict[str, Any]] = []
    artifact_ids: dict[str, str] = {}
    for file in artifacts:
        node_id = f"A{len(artifact_ids) + 1}"
        artifact_ids[file] = node_id
        nodes.append({"id": node_id, "type": "MEDIA_ARTIFACT", "file": file})
    observation_ids: dict[int, str] = {}
    for index, candidate in enumerate(bounded, start=1):
        node_id = f"O{index}"
        observation_ids[id(candidate)] = node_id
        nodes.append(
            {
                "id": node_id,
                "type": candidate.get("node_type", "SYMBOL_OBSERVATION"),
                "file": candidate.get("file"),
                "source": candidate.get("source"),
                "preview": str(candidate.get("text", ""))[:240],
                "confidence": float(candidate.get("confidence", 0.0)),
                "frame_index": candidate.get("frame_index"),
                "region": candidate.get("region") or candidate.get("polygon"),
                "transform_chain": list(candidate.get("transform_chain", [])),
            }
        )
        artifact_id = artifact_ids.get(str(candidate.get("file", "")))
        if artifact_id:
            edges.append({"from": artifact_id, "to": node_id, "type": "CONTAINS_OBSERVATION", "confidence": 1.0})
        elif candidate.get("node_type") == "DOCUMENT_FRAGMENT":
            edges.append({"from": "D1", "to": node_id, "type": "CONTAINS_CONTEXT", "confidence": 0.99})
    for reference in references:
        artifact_id = artifact_ids[reference["file"]]
        edges.append(
            {
                "from": "D1",
                "to": artifact_id,
                "type": "REFERENCES",
                "order": reference["order"],
                "line": reference["line"],
                "confidence": 0.99,
            }
        )

    hypotheses: list[dict[str, Any]] = []
    hypothesis_fragments: list[list[dict[str, Any]]] = []
    for hypothesis, fragments in document_hypotheses:
        hypotheses.append(hypothesis)
        hypothesis_fragments.append(fragments)
    ordered_reference_fragments = [
        best_by_file[reference["file"]]
        for reference in references
        if reference["file"] in best_by_file
    ]
    if len(ordered_reference_fragments) >= 2:
        hypothesis = _hypothesis_candidate(
            ordered_reference_fragments,
            mode="document-reference-order",
            confidence=0.96,
        )
        if hypothesis:
            hypotheses.append(hypothesis)
            hypothesis_fragments.append(ordered_reference_fragments)
    for sequence in _numbered_sequences(artifacts, best_by_file):
        hypothesis = _hypothesis_candidate(sequence, mode="numbered-artifact-sequence", confidence=0.9)
        if hypothesis:
            hypotheses.append(hypothesis)
            hypothesis_fragments.append(sequence)
    for sequence in _frame_sequences(bounded):
        hypothesis = _hypothesis_candidate(sequence, mode="frame-order", confidence=0.97)
        if hypothesis:
            hypotheses.append(hypothesis)
            hypothesis_fragments.append(sequence)

    deduped_hypotheses: list[dict[str, Any]] = []
    deduped_fragments: list[list[dict[str, Any]]] = []
    seen_text: set[str] = set()
    for hypothesis, fragments in zip(hypotheses, hypothesis_fragments):
        key = hypothesis["text"].lower()
        if key in seen_text:
            continue
        seen_text.add(key)
        deduped_hypotheses.append(hypothesis)
        deduped_fragments.append(fragments)
        if len(deduped_hypotheses) >= MAX_HYPOTHESES:
            break
    hypotheses = deduped_hypotheses

    graph_hypotheses: list[dict[str, Any]] = []
    for index, (hypothesis, fragments) in enumerate(zip(hypotheses, deduped_fragments), start=1):
        node_id = f"H{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "RECONSTRUCTED_INSTRUCTION_HYPOTHESIS",
                "mode": hypothesis["association_mode"],
                "preview": hypothesis["preview"],
                "confidence": hypothesis["confidence"],
                "fragment_count": hypothesis["fragment_count"],
            }
        )
        fragment_ids: list[str] = []
        for order, fragment in enumerate(fragments, start=1):
            observation_id = observation_ids.get(id(fragment))
            if observation_id:
                fragment_ids.append(observation_id)
                edges.append(
                    {
                        "from": observation_id,
                        "to": node_id,
                        "type": "COMPLETES",
                        "order": order,
                        "confidence": hypothesis["confidence"],
                    }
                )
        graph_hypotheses.append(
            {
                "id": node_id,
                "mode": hypothesis["association_mode"],
                "fragment_ids": fragment_ids,
                "fragment_files": hypothesis["fragment_files"],
                "preview": hypothesis["preview"],
                "confidence": hypothesis["confidence"],
            }
        )

    return {
        "triggered": bool(hypotheses),
        "method": "bounded_provenance_graph_with_explicit_ordering",
        "limits": {
            "max_candidates": MAX_GRAPH_CANDIDATES,
            "max_hypotheses": MAX_HYPOTHESES,
            "max_fragments_per_hypothesis": MAX_FRAGMENTS_PER_HYPOTHESIS,
        },
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes[:400],
        "edges": edges[:800],
        "document_references": references,
        "hypotheses": graph_hypotheses,
        "_hypothesis_candidates": hypotheses,
    }


__all__ = ["build_cross_media_evidence_graph"]
