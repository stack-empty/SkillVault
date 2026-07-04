from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
CODE_ROOT = REPO_ROOT / "code"
SEVERITIES = ("critical", "high", "medium", "low", "informational")


def discover_real_static_scanner() -> dict[str, Any]:
    """Discover a safe module-level static scanner without executing samples."""
    module_path = CODE_ROOT / "platforms" / "codex" / "static_scan.py"
    if not module_path.exists():
        return {
            "available": False,
            "scanner_mode": "fallback_static_adapter",
            "warnings": ["real static scanner module not found"],
            "errors": [],
        }
    if str(CODE_ROOT) not in sys.path:
        sys.path.insert(0, str(CODE_ROOT))
    try:
        from platforms.codex.static_scan import build_static_scan_result
    except Exception as exc:  # pragma: no cover - defensive discovery guard
        return {
            "available": False,
            "scanner_mode": "fallback_static_adapter",
            "warnings": ["real static scanner import failed"],
            "errors": [str(exc)],
        }
    if not callable(build_static_scan_result):
        return {
            "available": False,
            "scanner_mode": "fallback_static_adapter",
            "warnings": ["real static scanner entrypoint is not callable"],
            "errors": [],
        }
    return {
        "available": True,
        "scanner_mode": "real_static_scanner",
        "entrypoint": "platforms.codex.static_scan.build_static_scan_result",
        "warnings": [],
        "errors": [],
    }


def run_real_static_scanner(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Run the real static scanner by Python module call only."""
    discovery = discover_real_static_scanner()
    if not discovery["available"]:
        raise RuntimeError("real static scanner unavailable")
    if str(CODE_ROOT) not in sys.path:
        sys.path.insert(0, str(CODE_ROOT))
    from platforms.codex.static_scan import build_static_scan_result

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    raw_result = build_static_scan_result(Path(skill_path))
    normalized = normalize_static_findings(raw_result)
    supplemental = _collect_prototype_findings(Path(skill_path))
    if supplemental:
        normalized["findings"].extend(supplemental)
        normalized["risk_summary"] = _risk_summary(normalized["findings"])
    normalized["scanner_mode"] = "real_static_scanner"
    normalized["fallback_used"] = False
    normalized["warnings"].extend(discovery.get("warnings", []))
    _write_normalized_report(normalized, output)
    return normalized


def normalize_static_findings(raw_result: dict[str, Any]) -> dict[str, Any]:
    """Normalize real scanner output into the Web UI report shape."""
    findings: list[dict[str, Any]] = []
    files_seen: set[str] = set()
    for skill in raw_result.get("skills", []) or []:
        for key in ("skill_md_path", "agents_md_path", "openai_yaml_path"):
            if skill.get(key):
                files_seen.add(str(skill[key]))
        for key in ("scripts_paths", "references_paths", "assets_paths"):
            for path in skill.get(key) or []:
                files_seen.add(str(path))
        for finding in skill.get("findings", []) or []:
            severity = str(finding.get("severity", "LOW")).lower()
            files_seen.add(str(finding.get("file", "")))
            findings.append(
                {
                    "severity": severity if severity in SEVERITIES else "low",
                    "original_severity": severity,
                    "file": str(finding.get("file", "")),
                    "line": int(finding.get("line", 0) or 0),
                    "rule": str(finding.get("rule_id", finding.get("rule", ""))),
                    "keyword": str(finding.get("rule_id", "")),
                    "reason": str(finding.get("explanation", finding.get("title", ""))),
                    "context": str(finding.get("evidence", ""))[:240],
                    "confidence": str(skill.get("confidence", finding.get("confidence", "high"))),
                    "suppressed": False,
                    "message": str(finding.get("title", "")),
                    "path": str(finding.get("file", "")),
                }
            )

    risk_summary = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if finding.get("suppressed"):
            continue
        risk_summary[finding["severity"]] = risk_summary.get(finding["severity"], 0) + 1

    return {
        "scanner_mode": "real_static_scanner",
        "production_equivalent": False,
        "risk_summary": risk_summary,
        "findings": findings,
        "files_scanned": len([path for path in files_seen if path]),
        "file_count": len([path for path in files_seen if path]),
        "skill_found": bool(raw_result.get("skills")),
        "has_skill_md": bool(raw_result.get("skills")),
        "raw_summary": raw_result.get("summary", {}),
        "report_paths": {},
        "warnings": [],
        "errors": [],
    }


def fallback_to_prototype_adapter(skill_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Run a local prototype static adapter when the real scanner is unavailable."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    skill_root = Path(skill_path)
    findings = _collect_prototype_findings(skill_root)
    files = [str(path.relative_to(skill_root)) for path in sorted(skill_root.rglob("*")) if path.is_file() and not path.is_symlink()]

    has_skill_md = any(path.name == "SKILL.md" for path in skill_root.rglob("*") if path.is_file())
    if not has_skill_md:
        findings.append(
            {
                "severity": "medium",
                "original_severity": "medium",
                "file": ".",
                "line": 0,
                "rule": "missing_skill_md",
                "keyword": "missing_skill_md",
                "reason": "No SKILL.md file found in uploaded package",
                "context": "",
                "confidence": "high",
                "suppressed": False,
                "message": "No SKILL.md file found in uploaded package",
                "path": ".",
            }
        )

    risk_summary = _risk_summary(findings)

    normalized = {
        "scanner_mode": "fallback_static_adapter",
        "production_equivalent": False,
        "risk_summary": risk_summary,
        "findings": findings,
        "files_scanned": len(files),
        "file_count": len(files),
        "skill_found": has_skill_md,
        "has_skill_md": has_skill_md,
        "raw_summary": {},
        "report_paths": {},
        "warnings": ["Real scanner was unavailable or incompatible; prototype fallback adapter was used."],
        "errors": [],
        "fallback_used": True,
    }
    _write_normalized_report(normalized, output)
    return normalized


def _collect_prototype_findings(skill_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(skill_root.rglob("*")):
        if path.is_dir() or path.is_symlink():
            continue
        relative = str(path.relative_to(skill_root))
        if path.suffix.lower() not in {".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml"} and path.name != "SKILL.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        findings.extend(_prototype_findings(text, relative))
    return findings


def _risk_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    risk_summary = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if finding.get("suppressed"):
            continue
        severity = finding.get("severity", "low")
        risk_summary[severity] = risk_summary.get(severity, 0) + 1
    return risk_summary


def _prototype_findings(text: str, relative: str) -> list[dict[str, Any]]:
    patterns = [
        ("docker.sock", "critical", "Docker socket reference"),
        ("~/.ssh", "critical", "SSH credential path reference"),
        ("--" + "privileged", "critical", "Privileged container flag reference"),
        ("--network " + "host", "critical", "Host network mode reference"),
        ("OPENAI_API_KEY", "critical", "OpenAI token environment reference"),
        ("GITHUB_TOKEN", "critical", "GitHub token environment reference"),
        ("curl", "high", "Network download tool reference"),
        ("wget", "high", "Network download tool reference"),
    ]
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        for keyword, severity, reason in patterns:
            start = lowered.find(keyword.lower())
            if start == -1:
                continue
            suppressed = _negative_context(line, start)
            findings.append(
                {
                    "severity": "informational" if suppressed else severity,
                    "original_severity": severity,
                    "file": relative,
                    "line": line_number,
                    "rule": keyword,
                    "keyword": keyword,
                    "reason": "Suppressed documentation-only match: heuristic negative context" if suppressed else reason,
                    "context": line.strip()[:240],
                    "confidence": "low" if suppressed else "high",
                    "suppressed": suppressed,
                    "message": reason,
                    "path": relative,
                }
            )
    return findings


def _negative_context(line: str, start: int) -> bool:
    nearby = line[:start].lower()[-80:]
    return bool(
        re.search(r"\bdoes\s+not\s+(?:use|access|read|mount|run\s+with)\b", nearby)
        or re.search(r"\bdo\s+not\s+(?:use|access|read|mount|run\s+with)\b", nearby)
        or re.search(r"\bno\s+(?:real\s+)?\b", nearby)
        or re.search(r"\bwithout\b", nearby)
    )


def _write_normalized_report(report: dict[str, Any], output_dir: Path) -> None:
    json_path = output_dir / "static_report.json"
    md_path = output_dir / "report.md"
    report["report_paths"] = {
        "static_report_json": str(json_path),
        "static_report_md": str(md_path),
    }
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_report(report), encoding="utf-8")


def _render_report(report: dict[str, Any]) -> str:
    lines = [
        "# Web UI Static Scan Report",
        "",
        f"- Scanner mode: `{report.get('scanner_mode')}`",
        f"- Fallback used: `{str(report.get('fallback_used', False)).lower()}`",
        f"- Files scanned: `{report.get('files_scanned', 0)}`",
        f"- Skill found: `{str(report.get('skill_found', False)).lower()}`",
        "",
        "## Risk Summary",
        "",
    ]
    for key, value in report.get("risk_summary", {}).items():
        lines.append(f"- {key}: `{value}`")
    if report.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in report["warnings"])
    lines.extend(["", "## Findings", ""])
    if not report.get("findings"):
        lines.append("No static findings.")
    for finding in report.get("findings", []):
        lines.append(
            f"- {str(finding.get('severity', '')).upper()}: `{finding.get('file', '')}`"
            f"{':' + str(finding.get('line')) if finding.get('line') else ''} "
            f"{finding.get('reason', '')} ({finding.get('rule') or finding.get('keyword', '')})"
        )
        if finding.get("suppressed"):
            lines.append("  - Suppressed documentation-only match")
        if finding.get("context"):
            lines.append(f"  - Context: `{finding.get('context')}`")
        lines.append(f"  - Confidence: {finding.get('confidence', 'unknown')}")
    lines.extend(
        [
            "",
            "## Scope Note",
            "",
            "This is a research prototype integration, not a production scanning platform.",
            "Dynamic execution remains plan-only / fail-closed and is not performed by this scanner integration.",
            "",
        ]
    )
    return "\n".join(lines)
