from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import job_store


REQUIRED_CONTROLS = [
    "no_network",
    "fake_home",
    "fake_codex_home",
    "readonly_sample_mount",
    "output_rw",
    "no_docker_sock",
    "no_privileged",
    "no_network_host",
    "no_real_token",
    "timeout",
    "policy_gate_required",
    "runtime_monitor_required",
    "kill_on_high_critical",
    "fail_closed_by_default",
]


def _job_root(job: dict[str, Any]) -> Path:
    return job_store.job_dir(job["job_id"]).resolve()


def _dynamic_plan_dir(job: dict[str, Any]) -> Path:
    path = _job_root(job) / "dynamic_plan"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(job_store.REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _load_static_report(job: dict[str, Any]) -> dict[str, Any]:
    rel_path = (job.get("report_paths") or {}).get("static_scan_report_json")
    if not rel_path:
        return {}
    path = (job_store.REPO_ROOT / rel_path).resolve()
    try:
        path.relative_to(_job_root(job))
    except ValueError:
        return {}
    if not path.exists() or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def evaluate_dynamic_eligibility(job: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []

    try:
        job_store.job_dir(job["job_id"])
    except ValueError:
        blockers.append("invalid job id")

    if job.get("static_scan_status") != "completed":
        blockers.append("static_scan_status must be completed")

    static_report = _load_static_report(job)
    risk_summary = static_report.get("risk_summary") or job.get("risk_summary") or {}
    critical = int(risk_summary.get("critical", 0))
    high = int(risk_summary.get("high", 0))
    if critical > 0 or high > 0:
        blockers.append("HIGH / CRITICAL static findings block dynamic execution")
    if critical > 0:
        blockers.append("critical static findings block dynamic execution")
    if high > 0:
        blockers.append("high static findings block dynamic execution")

    extracted = Path(str(job.get("extracted_skill_path") or ""))
    expected = _job_root(job) / "uploaded_skill"
    try:
        extracted_resolved = extracted.resolve()
        extracted_resolved.relative_to(expected.resolve())
    except (OSError, ValueError):
        blockers.append("extracted_skill_path must stay under uploaded_skill")
    if not extracted.exists() or not extracted.is_dir():
        blockers.append("extracted_skill_path is missing")

    boundaries = job_store.normalize_safety_boundaries(
        job.get("safety_boundaries"),
        required_controls=REQUIRED_CONTROLS,
        legacy_defaults=False,
    )
    if not boundaries and job.get("required_controls"):
        boundaries = job_store.normalize_safety_boundaries(
            job.get("required_controls"),
            required_controls=REQUIRED_CONTROLS,
            legacy_defaults=True,
        )
    for label in REQUIRED_CONTROLS:
        if boundaries.get(label) is not True:
            blockers.append(f"safety boundary missing {label}")

    allowed = not blockers
    reason = "eligible for confirmed safe dynamic inspection"
    if not allowed:
        reason = "blocked by dynamic gate"
        if critical > 0 or high > 0:
            reason = "HIGH or CRITICAL static findings block dynamic execution"
    return {
        "allowed": allowed,
        "reason": reason,
        "required_controls": REQUIRED_CONTROLS,
        "blockers": blockers,
        "warnings": warnings,
        "eligibility_status": "allowed" if allowed else "denied",
        "risk_summary": risk_summary,
        "safety_boundaries": boundaries,
    }


def build_safe_dynamic_plan(job: dict[str, Any]) -> dict[str, Any]:
    job["required_controls"] = list(REQUIRED_CONTROLS)
    job["safety_boundaries"] = job_store.normalize_safety_boundaries(
        job.get("safety_boundaries"),
        required_controls=REQUIRED_CONTROLS,
        legacy_defaults=True,
    )
    eligibility = evaluate_dynamic_eligibility(job)
    output_dir = _dynamic_plan_dir(job)
    plan = {
        "job_id": job["job_id"],
        "mode": "safe_dynamic_gate",
        "dynamic_execution_performed": False,
        "eligibility": eligibility,
        "network_mode": "none",
        "fake_home": "/home/codexsafe",
        "fake_codex_home": "/home/codexsafe/.codex",
        "sample_mount": "read-only",
        "output_mount": "writable",
        "docker_sock_mounted": False,
        "privileged": False,
        "network_host": False,
        "real_tokens_present": False,
        "timeout_seconds": 30,
        "policy_gate_required": True,
        "runtime_monitor_required": True,
        "kill_on_high_critical": True,
        "fail_closed_by_default": True,
        "benign_inspection_only": True,
        "uploaded_scripts_executed": False,
        "required_controls": REQUIRED_CONTROLS,
        "safety_boundaries": eligibility["safety_boundaries"],
    }
    json_path = output_dir / "dynamic_plan.json"
    md_path = output_dir / "report.md"
    json_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_plan(plan), encoding="utf-8")
    job.setdefault("report_paths", {})["dynamic_plan_json"] = _relative_repo_path(json_path)
    job["report_paths"]["dynamic_plan_md"] = _relative_repo_path(md_path)
    job["dynamic_plan_path"] = _relative_repo_path(json_path)
    job["required_controls"] = list(REQUIRED_CONTROLS)
    job["safety_boundaries"] = eligibility["safety_boundaries"]
    job["dynamic_plan_status"] = "ready" if eligibility["allowed"] else "blocked"
    job["dynamic_eligibility"] = eligibility
    job["dynamic_scan_status"] = "plan_ready" if eligibility["allowed"] else "blocked"
    job["status"] = "dynamic_plan_ready" if eligibility["allowed"] else "dynamic_blocked"
    job_store.save_job(job)
    return plan


def require_human_confirmation(job: dict[str, Any], confirmation_text: str = "") -> dict[str, Any]:
    job["dynamic_user_confirmed"] = True
    job["confirmed_at"] = job_store.now_iso()
    job["confirmation_text"] = confirmation_text[:500]
    job_store.save_job(job)
    return job


def _render_plan(plan: dict[str, Any]) -> str:
    eligibility = plan["eligibility"]
    lines = [
        "# Web UI Safe Dynamic Execution Gate Plan",
        "",
        f"- Job ID: `{plan['job_id']}`",
        f"- Eligibility: `{eligibility['eligibility_status']}`",
        f"- Reason: `{eligibility['reason']}`",
        "- Dynamic execution performed: `false`",
        "- Benign inspection only: `true`",
        "- Uploaded scripts executed: `false`",
        "",
        "## Required Controls",
        "",
    ]
    lines.extend(f"- {control}" for control in plan["required_controls"])
    if eligibility["blockers"]:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- {blocker}" for blocker in eligibility["blockers"])
    lines.append("")
    return "\n".join(lines)
