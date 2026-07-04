"""Fix 1 context classification and documentation-noise suppression."""

from __future__ import annotations

from pathlib import Path
from typing import Any


CONTEXT_WEIGHTS = {
    "main_skill_logic": 1.0,
    "skill_md_instruction": 0.9,
    "entrypoint_script": 1.0,
    "called_runtime_code": 0.9,
    "install_script": 0.7,
    "config_file": 0.6,
    "readme_doc": 0.35,
    "reference_doc": 0.25,
    "example_code": 0.2,
    "test_code": 0.15,
    "history_file": 0.1,
    "archive_file": 0.1,
    "unknown": 0.5,
}

DOCUMENTATION_CONTEXTS = {
    "readme_doc", "reference_doc", "example_code", "test_code",
    "history_file", "archive_file",
}
PRIMARY_CONTEXTS = {
    "main_skill_logic", "skill_md_instruction", "entrypoint_script",
    "called_runtime_code", "install_script", "config_file",
}
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def classify_file_context(path: str | Path, content: str | None = None) -> str:
    """Classify a file by its likely role in a Skill package."""
    rel = str(path).replace("\\", "/").lstrip("./")
    lower = rel.lower()
    parts = set(Path(lower).parts)
    name = Path(lower).name
    suffix = Path(lower).suffix

    if name == "skill.md":
        return "skill_md_instruction"
    if name.startswith("readme") or name in {"changelog.md", "contributing.md"}:
        return "readme_doc"
    if parts & {"reference", "references", "docs", "doc"}:
        return "reference_doc"
    if parts & {"example", "examples", "sample", "samples", "demo", "demos", "fixtures"}:
        return "example_code"
    if parts & {"test", "tests", "__tests__"} or name.startswith(("test_", "spec.")) or name.endswith(("_test.py", ".spec.js", ".spec.ts")):
        return "test_code"
    if parts & {"history", "old", "legacy"} or name.startswith(("history", "old_")):
        return "history_file"
    if parts & {"archive", "archives", "backup", "backups"} or suffix in {".bak", ".old"}:
        return "archive_file"
    if name in {"setup.py", "pyproject.toml", "package.json", "dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
        return "config_file"
    if suffix in {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env"}:
        return "config_file"
    if "install" in name and suffix in {".sh", ".py", ".js", ".ps1", ".bat"}:
        return "install_script"
    if name in {"main.py", "run.py", "run.sh", "index.js", "index.ts", "cli.py", "__main__.py"} or lower.startswith("bin/"):
        return "entrypoint_script"
    if lower.startswith(("src/", "lib/", "scripts/")) and suffix in {".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".ps1"}:
        return "called_runtime_code"
    if suffix in {".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".ps1", ".rb", ".go"}:
        return "main_skill_logic"
    return "unknown"


def classify_line_context(
    path: str | Path,
    line_text: str,
    surrounding_text: str | None = None,
) -> str:
    """Refine file context for a line without treating SKILL.md as ordinary docs."""
    context = classify_file_context(path, surrounding_text)
    stripped = str(line_text or "").lstrip()
    suffix = Path(str(path)).suffix.lower()
    if context in PRIMARY_CONTEXTS and suffix in {".py", ".sh", ".bash", ".zsh", ".js", ".ts"}:
        if stripped.startswith("#") or stripped.startswith("//"):
            return "reference_doc"
    return context


def is_primary_skill_instruction(path: str | Path) -> bool:
    return classify_file_context(path) == "skill_md_instruction"


def is_entrypoint_code(path: str | Path) -> bool:
    return classify_file_context(path) == "entrypoint_script"


def is_documentation_context(path_or_context: str | Path) -> bool:
    value = str(path_or_context)
    context = value if value in CONTEXT_WEIGHTS else classify_file_context(value)
    return context in DOCUMENTATION_CONTEXTS


def is_example_or_test_context(path_or_context: str | Path) -> bool:
    value = str(path_or_context)
    context = value if value in CONTEXT_WEIGHTS else classify_file_context(value)
    return context in {"example_code", "test_code"}


def context_confidence_multiplier(context_type: str) -> float:
    return CONTEXT_WEIGHTS.get(str(context_type or "unknown"), CONTEXT_WEIGHTS["unknown"])


def _severity_for_weight(severity: str, weight: float) -> str:
    upper = str(severity or "LOW").upper()
    try:
        index = SEVERITY_ORDER.index(upper)
    except ValueError:
        return upper
    if weight >= 0.7:
        return upper
    steps = 1 if weight >= 0.25 else 2
    return SEVERITY_ORDER[max(0, index - steps)]


def downgrade_finding_by_context(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with context metadata and adjusted severity."""
    result = dict(finding)
    context = str(result.get("context_type") or classify_file_context(result.get("file", "")))
    weight = context_confidence_multiplier(context)
    original = str(result.get("original_severity") or result.get("severity") or "LOW").upper()
    adjusted = _severity_for_weight(original, weight)
    downgraded = adjusted != original
    result.update({
        "context_type": context,
        "context_weight": weight,
        "original_severity": original,
        "adjusted_severity": adjusted,
        "severity": adjusted,
        "context_downgraded": downgraded,
        "context_downgrade_reason": (
            f"{context} context weight {weight:.2f} reduced severity from {original} to {adjusted}"
            if downgraded else None
        ),
    })
    result["confidence"] = round(
        min(1.0, float(result.get("confidence", 0.5) or 0.5) * max(weight, 0.2)), 3
    )
    return result


def summarize_context_downgrades(findings: list[dict[str, Any]] | None) -> dict[str, Any]:
    items = list(findings or [])
    documentary = [item for item in items if str(item.get("context_type")) in DOCUMENTATION_CONTEXTS]
    downgraded = [item for item in items if item.get("context_downgraded") or item.get("downgraded")]
    high_to_low = [
        item for item in downgraded
        if str(item.get("original_severity", "")).upper() in {"HIGH", "CRITICAL"}
        and str(item.get("severity", "")).upper() in {"LOW", "INFO"}
    ]
    return {
        "enabled": True,
        "documentation_findings_count": len(documentary),
        "downgraded_count": len(downgraded),
        "high_to_low_downgrade_count": len(high_to_low),
        "context_noise_count": len(documentary),
        "context_noise_ratio": round(len(documentary) / len(items), 4) if items else 0.0,
        "by_context": {
            context: sum(1 for item in items if item.get("context_type") == context)
            for context in CONTEXT_WEIGHTS
            if any(item.get("context_type") == context for item in items)
        },
    }
