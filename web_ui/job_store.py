from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
JOBS_ROOT = REPO_ROOT / "analysis_results" / "web_ui_jobs"
JOB_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")
STATUS_VALUES = {
    "created",
    "uploaded",
    "extracted",
    "static_running",
    "static_completed",
    "static_failed",
    "dynamic_plan_ready",
    "dynamic_blocked",
    "dynamic_completed",
    "failed",
}
DEFAULT_SAFETY_BOUNDARIES = {
    "no_network": True,
    "fake_home": True,
    "fake_codex_home": True,
    "readonly_sample_mount": True,
    "output_rw": True,
    "no_docker_sock": True,
    "no_privileged": True,
    "no_network_host": True,
    "no_real_token": True,
    "timeout": True,
    "policy_gate_required": True,
    "runtime_monitor_required": True,
    "kill_on_high_critical": True,
    "fail_closed_by_default": True,
}

BOUNDARY_ALIASES = {
    "network_none": "no_network",
    "no_real_tokens": "no_real_token",
    "no_docker_socket": "no_docker_sock",
    "no_host_network": "no_network_host",
    "fake_codex": "fake_codex_home",
    "read_only_sample_mount": "readonly_sample_mount",
    "writable_output": "output_rw",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_text(value: str, limit: int = 120) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_. -]", "_", value.strip())
    cleaned = re.sub(r"\s+", " ", cleaned)
    return (cleaned[:limit] or "uploaded_skill").strip()


def default_safety_boundaries() -> dict[str, bool]:
    return dict(DEFAULT_SAFETY_BOUNDARIES)


def _canonical_boundary_key(value: str) -> str:
    key = value.strip().lower().replace("-", "_").replace(" ", "_")
    return BOUNDARY_ALIASES.get(key, key)


def normalize_safety_boundaries(
    value: object,
    *,
    required_controls: list[str] | None = None,
    legacy_defaults: bool = False,
) -> dict[str, bool]:
    controls = required_controls or list(DEFAULT_SAFETY_BOUNDARIES)
    normalized: dict[str, bool] = {}

    if isinstance(value, dict):
        for key, raw in value.items():
            normalized[_canonical_boundary_key(str(key))] = bool(raw)
    elif isinstance(value, list):
        joined = " ".join(str(item).lower().replace("-", "_") for item in value)
        for item in value:
            key = _canonical_boundary_key(str(item))
            if key in DEFAULT_SAFETY_BOUNDARIES:
                normalized[key] = True
        phrase_map = {
            "no_network": ("network_none", "no_network"),
            "fake_home": ("fake_home", "fake home"),
            "fake_codex_home": ("fake_codex_home", "fake codex"),
            "readonly_sample_mount": ("readonly_sample_mount", "read_only_sample", "read-only sample"),
            "output_rw": ("output_rw", "writable output", "output rw"),
            "no_docker_sock": ("no_docker_sock", "docker socket", "docker.sock"),
            "no_privileged": ("no_privileged", "no privileged"),
            "no_network_host": ("no_network_host", "host network", "network host"),
            "no_real_token": ("no_real_token", "no real token", "no real tokens"),
            "timeout": ("timeout",),
            "policy_gate_required": ("policy_gate_required", "policy gate"),
            "runtime_monitor_required": ("runtime_monitor_required", "runtime monitor"),
            "kill_on_high_critical": ("kill_on_high_critical", "high critical"),
            "fail_closed_by_default": ("fail_closed_by_default", "fail_closed", "fail-closed"),
        }
        for key, phrases in phrase_map.items():
            if any(phrase in joined for phrase in phrases):
                normalized[key] = True
        if legacy_defaults and normalized:
            for key in controls:
                normalized.setdefault(key, True)
    elif value is None and legacy_defaults:
        normalized = {key: True for key in controls}

    return normalized


def new_job_id() -> str:
    return f"job_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


def job_dir(job_id: str) -> Path:
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("invalid job id")
    return JOBS_ROOT / job_id


def job_path(job_id: str) -> Path:
    return job_dir(job_id) / "job.json"


def create_job(skill_name: str, note: str) -> dict[str, Any]:
    job_id = new_job_id()
    created = now_iso()
    job = {
        "job_id": job_id,
        "skill_name": sanitize_text(skill_name),
        "note": note.strip()[:1000],
        "status": "created",
        "created_at": created,
        "updated_at": created,
        "uploaded_archive": None,
        "extracted_skill_path": None,
        "static_scan_status": "not_started",
        "static_scanner_mode": "not_started",
        "static_scanner_fallback_used": False,
        "static_scanner_warnings": [],
        "static_scanner_errors": [],
        "dynamic_scan_status": "not_started",
        "dynamic_plan_status": "not_started",
        "dynamic_user_confirmed": False,
        "confirmed_at": None,
        "confirmation_text": "",
        "dynamic_eligibility": {},
        "dynamic_execution_report": {},
        "risk_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        },
        "report_paths": {},
        "safety_boundaries": default_safety_boundaries(),
        "errors": [],
    }
    save_job(job)
    return job


def load_job(job_id: str) -> dict[str, Any]:
    path = job_path(job_id)
    if not path.exists():
        raise FileNotFoundError(f"job not found: {job_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_job(job: dict[str, Any]) -> None:
    status = job.get("status")
    if status not in STATUS_VALUES:
        raise ValueError(f"invalid job status: {status}")
    path = job_path(job["job_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    job["updated_at"] = now_iso()
    path.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def update_job(job: dict[str, Any], **changes: Any) -> dict[str, Any]:
    job.update(changes)
    save_job(job)
    return job


def append_error(job: dict[str, Any], message: str) -> dict[str, Any]:
    job.setdefault("errors", []).append({"at": now_iso(), "message": message[:1000]})
    job["status"] = "failed"
    save_job(job)
    return job


def list_jobs() -> list[dict[str, Any]]:
    JOBS_ROOT.mkdir(parents=True, exist_ok=True)
    jobs: list[dict[str, Any]] = []
    for path in sorted(JOBS_ROOT.glob("job_*/job.json"), reverse=True):
        try:
            jobs.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return jobs
