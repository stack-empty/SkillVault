from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from job_store import REPO_ROOT, save_job
import dynamic_gate
import safe_dynamic_runner
import static_scanner_integration


DANGEROUS_PATTERNS = [
    ("docker.sock", "critical", "Docker socket reference"),
    ("--" + "privileged", "critical", "Privileged container flag reference"),
    ("--network " + "host", "critical", "Host network mode reference"),
    ("OPENAI_API_KEY", "critical", "OpenAI token environment reference"),
    ("ANTHROPIC_API_KEY", "critical", "Anthropic token environment reference"),
    ("GITHUB_TOKEN", "critical", "GitHub token environment reference"),
    ("SSH_AUTH_SOCK", "critical", "SSH agent socket reference"),
    ("~/.ssh", "critical", "SSH credential path reference"),
    ("~/.codex", "critical", "Codex credential home reference"),
    ("~/.agents", "critical", "Agents credential home reference"),
    (".env", "high", "Environment file reference"),
    ("curl", "high", "Network download tool reference"),
    ("wget", "high", "Network download tool reference"),
    ("npm install", "high", "Dependency installer reference"),
    ("pip install", "high", "Dependency installer reference"),
    ("apt install", "high", "System package installer reference"),
]

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".js",
    ".ts",
}

NEGATIVE_CONTEXT_PATTERNS = [
    r"\bdoes\s+not\s+(?:use|access|read|mount|run\s+with)\b",
    r"\bdo\s+not\s+(?:use|access|read|mount|run\s+with)\b",
    r"\bno\s+(?:real\s+)?\b",
    r"\bwithout\b",
    r"\bnever\s+(?:use|access|read|mount|run\s+with)\b",
]


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _job_output_dir(job: dict[str, Any], name: str) -> Path:
    path = REPO_ROOT / "analysis_results" / "web_ui_jobs" / job["job_id"] / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def _is_negative_context(line: str, start: int) -> bool:
    prefix = line[:start].lower()
    nearby = prefix[-80:]
    return any(re.search(pattern, nearby) for pattern in NEGATIVE_CONTEXT_PATTERNS)


def _scan_text_file(path: Path, skill_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [
            {
                "file": str(path.relative_to(skill_root)),
                "line": 0,
                "keyword": "read_error",
                "severity": "medium",
                "pattern": "read_error",
                "context": "",
                "reason": f"Could not read file: {exc}",
                "confidence": "high",
                "suppressed": False,
                "message": f"Could not read file: {exc}",
                "path": str(path.relative_to(skill_root)),
            }
        ]

    relative = str(path.relative_to(skill_root))
    for line_number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        for pattern, severity, message in DANGEROUS_PATTERNS:
            needle = pattern.lower()
            start = lowered.find(needle)
            if start == -1:
                continue
            suppressed = _is_negative_context(line, start)
            reason = (
                "Suppressed documentation-only match: heuristic negative context"
                if suppressed
                else message
            )
            findings.append(
                {
                    "file": relative,
                    "line": line_number,
                    "keyword": pattern,
                    "severity": "informational" if suppressed else severity,
                    "original_severity": severity,
                    "pattern": pattern,
                    "context": line.strip()[:240],
                    "reason": reason,
                    "confidence": "low" if suppressed else "high",
                    "suppressed": suppressed,
                    "message": message,
                    "path": relative,
                }
            )
    return findings


def run_static_scan(job: dict[str, Any]) -> dict[str, Any]:
    job["status"] = "static_running"
    job["static_scan_status"] = "running"
    save_job(job)

    skill_root = Path(job["extracted_skill_path"] or "")
    output_dir = _job_output_dir(job, "static_scan")

    if not skill_root.exists() or not skill_root.is_dir():
        job["status"] = "static_failed"
        job["static_scan_status"] = "failed"
        job.setdefault("errors", []).append({"message": "extracted skill path is missing"})
        save_job(job)
        return job

    discovery = static_scanner_integration.discover_real_static_scanner()
    scanner_errors: list[str] = []
    try:
        if discovery.get("available"):
            report = static_scanner_integration.run_real_static_scanner(skill_root, output_dir)
        else:
            report = static_scanner_integration.fallback_to_prototype_adapter(skill_root, output_dir)
    except Exception as exc:
        scanner_errors.append(str(exc))
        report = static_scanner_integration.fallback_to_prototype_adapter(skill_root, output_dir)
        report.setdefault("errors", []).extend(scanner_errors)

    scanner_mode = report.get("scanner_mode", "fallback_static_adapter")
    fallback_used = scanner_mode == "fallback_static_adapter" or bool(report.get("fallback_used"))
    json_path = output_dir / "static_report.json"
    md_path = output_dir / "report.md"

    job["status"] = "static_completed"
    job["static_scan_status"] = "completed"
    job["static_scanner_mode"] = scanner_mode
    job["static_scanner_fallback_used"] = fallback_used
    job["static_scanner_warnings"] = report.get("warnings", [])
    job["static_scanner_errors"] = report.get("errors", [])
    job["risk_summary"] = report.get("risk_summary", {})
    job.setdefault("report_paths", {})["static_scan_report_json"] = _relative_repo_path(json_path)
    job["report_paths"]["static_scan_report_md"] = _relative_repo_path(md_path)
    save_job(job)
    return job


def run_prototype_static_adapter(job: dict[str, Any]) -> dict[str, Any]:
    skill_root = Path(job["extracted_skill_path"] or "")
    output_dir = _job_output_dir(job, "static_scan")
    findings: list[dict[str, Any]] = []
    files: list[str] = []

    for path in sorted(skill_root.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink():
            findings.append(
                {
                    "severity": "critical",
                    "original_severity": "critical",
                    "pattern": "symlink",
                    "keyword": "symlink",
                    "message": "Symlink found in extracted upload",
                    "reason": "Symlink found in extracted upload",
                    "path": str(path.relative_to(skill_root)),
                    "file": str(path.relative_to(skill_root)),
                    "line": 0,
                    "context": "",
                    "confidence": "high",
                    "suppressed": False,
                }
            )
            continue
        files.append(str(path.relative_to(skill_root)))
        if path.suffix.lower() in TEXT_SUFFIXES or path.name == "SKILL.md":
            findings.extend(_scan_text_file(path, skill_root))

    has_skill_md = any(path.name == "SKILL.md" for path in skill_root.rglob("*") if path.is_file())
    if not has_skill_md:
        findings.append(
            {
                "severity": "medium",
                "original_severity": "medium",
                "pattern": "missing_skill_md",
                "keyword": "missing_skill_md",
                "message": "No SKILL.md file found in uploaded package",
                "reason": "No SKILL.md file found in uploaded package",
                "path": ".",
                "file": ".",
                "line": 0,
                "context": "",
                "confidence": "high",
                "suppressed": False,
            }
        )

    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for finding in findings:
        if finding.get("suppressed"):
            continue
        risk_summary[finding["severity"]] = risk_summary.get(finding["severity"], 0) + 1

    report = {
        "adapter": "web UI prototype static adapter",
        "production_equivalent": False,
        "job_id": job["job_id"],
        "skill_name": job["skill_name"],
        "file_count": len(files),
        "has_skill_md": has_skill_md,
        "risk_summary": risk_summary,
        "findings": findings,
        "safety_boundaries": job.get("safety_boundaries", []),
    }
    json_path = output_dir / "static_scan_report.json"
    md_path = output_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_static_report(report), encoding="utf-8")

    job["status"] = "static_completed"
    job["static_scan_status"] = "completed"
    job["risk_summary"] = risk_summary
    job.setdefault("report_paths", {})["static_scan_report_json"] = _relative_repo_path(json_path)
    job["report_paths"]["static_scan_report_md"] = _relative_repo_path(md_path)
    save_job(job)
    return job


def _render_static_report(report: dict[str, Any]) -> str:
    lines = [
        "# Web UI Prototype Static Scan Report",
        "",
        f"- Job ID: `{report['job_id']}`",
        f"- Skill name: `{report['skill_name']}`",
        "- Adapter: web UI prototype static adapter",
        "- Production equivalent: false",
        f"- Files scanned: {report['file_count']}",
        f"- SKILL.md found: {str(report['has_skill_md']).lower()}",
        "",
        "## Risk Summary",
        "",
    ]
    for key, value in report["risk_summary"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No prototype static findings.")
    else:
        for finding in report["findings"]:
            lines.append(
                f"- {finding['severity'].upper()}: `{finding['file']}`"
                f"{':' + str(finding['line']) if finding.get('line') else ''} "
                f"{finding['reason']} ({finding['keyword']})"
            )
            if finding.get("context"):
                lines.append(f"  - Context: `{finding['context']}`")
            lines.append(f"  - Confidence: {finding.get('confidence', 'unknown')}")
    lines.extend(
        [
            "",
            "## Scope Note",
            "",
            "This report is generated by the local Web UI prototype adapter. It checks package structure and selected dangerous text patterns, but it is not a production scanner.",
            "This is a heuristic false-positive reduction, not a production classifier.",
            "",
        ]
    )
    return "\n".join(lines)


def run_dynamic_scan_plan(job: dict[str, Any]) -> dict[str, Any]:
    dynamic_gate.build_safe_dynamic_plan(job)
    return job


def confirm_dynamic_execution(job: dict[str, Any], confirmation_text: str = "") -> dict[str, Any]:
    eligibility = dynamic_gate.evaluate_dynamic_eligibility(job)
    job["dynamic_eligibility"] = eligibility
    if not eligibility["allowed"]:
        job["dynamic_user_confirmed"] = False
        job["confirmed_at"] = None
        job["confirmation_text"] = ""
        save_job(job)
        return job
    return dynamic_gate.require_human_confirmation(job, confirmation_text)


def run_safe_dynamic_scan(job: dict[str, Any]) -> dict[str, Any]:
    eligibility = dynamic_gate.evaluate_dynamic_eligibility(job)
    job["dynamic_eligibility"] = eligibility
    if job.get("static_scan_status") != "completed" or not eligibility["allowed"]:
        job["dynamic_user_confirmed"] = False if not eligibility["allowed"] else job.get("dynamic_user_confirmed", False)
        save_job(job)
    safe_dynamic_runner.run_safe_dynamic_execution(job)
    return job


def collect_reports(job: dict[str, Any]) -> dict[str, str]:
    collected: dict[str, str] = {}
    for key, rel_path in job.get("report_paths", {}).items():
        path = REPO_ROOT / rel_path
        if path.exists() and path.suffix == ".md":
            collected[key] = path.read_text(encoding="utf-8", errors="replace")
    return collected


def summarize_job(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "skill_name": job["skill_name"],
        "status": job["status"],
        "static_scan_status": job["static_scan_status"],
        "static_scanner_mode": job.get("static_scanner_mode", "not_started"),
        "static_scanner_fallback_used": job.get("static_scanner_fallback_used", False),
        "static_scanner_warnings": job.get("static_scanner_warnings", []),
        "static_scanner_errors": job.get("static_scanner_errors", []),
        "dynamic_scan_status": job["dynamic_scan_status"],
        "dynamic_plan_status": job.get("dynamic_plan_status", "not_started"),
        "dynamic_user_confirmed": job.get("dynamic_user_confirmed", False),
        "dynamic_eligibility": job.get("dynamic_eligibility", {}),
        "dynamic_execution_report": job.get("dynamic_execution_report", {}),
        "risk_summary": job.get("risk_summary", {}),
        "report_paths": job.get("report_paths", {}),
    }
