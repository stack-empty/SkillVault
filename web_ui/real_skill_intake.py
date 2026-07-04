from __future__ import annotations

import hashlib
import json
import shutil
import stat
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dynamic_gate
import job_store
import static_scanner_integration
from safe_extract import SafeExtractError, safe_extract_archive


INTAKE_ROOT = job_store.REPO_ROOT / "analysis_results" / "real_skill_intake"
INBOX_DIR = INTAKE_ROOT / "inbox"
QUARANTINE_DIR = INTAKE_ROOT / "quarantine"
REPORTS_DIR = INTAKE_ROOT / "reports"
MANIFESTS_DIR = INTAKE_ROOT / "manifests"
ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz")
TEXT_SUFFIXES = {".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".js", ".ts"}
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024
SUSPICIOUS_NAMES = {"install.sh", "setup.sh", "run_skill.sh", ".env", "id_rsa", "id_ed25519"}


def ensure_intake_dirs() -> None:
    for path in (INBOX_DIR, QUARANTINE_DIR, REPORTS_DIR, MANIFESTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def _is_supported_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _archive_extension(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    if name.endswith(".tgz"):
        return ".tgz"
    if name.endswith(".zip"):
        return ".zip"
    return path.suffix.lower()


def _safe_sample_id(archive_name: str, sha256: str) -> str:
    stem = archive_name
    for suffix in ARCHIVE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    safe = job_store.sanitize_text(stem, limit=80).replace(" ", "_")
    return f"{safe}_{sha256[:12]}"


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(job_store.REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def discover_real_skill_archives(inbox_dir: str | Path = INBOX_DIR) -> list[Path]:
    inbox = Path(inbox_dir)
    if not inbox.exists():
        return []
    return sorted(path for path in inbox.iterdir() if path.is_file() and _is_supported_archive(path))


def compute_archive_manifest(path: str | Path) -> dict[str, Any]:
    archive = Path(path).resolve()
    digest = hashlib.sha256()
    with archive.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    stat_result = archive.stat()
    sha256 = digest.hexdigest()
    return {
        "archive_name": archive.name,
        "archive_path": str(archive),
        "sha256": sha256,
        "sample_id": _safe_sample_id(archive.name, sha256),
        "size_bytes": stat_result.st_size,
        "modified_time": datetime.fromtimestamp(stat_result.st_mtime, timezone.utc).isoformat(),
        "extension": _archive_extension(archive),
        "intake_status": "manifested",
    }


def _validate_archive_metadata(archive_path: Path) -> None:
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise SafeExtractError(f"zip symlink rejected: {member.filename}")
                if member.file_size > MAX_SINGLE_FILE_BYTES:
                    raise SafeExtractError(f"single file size limit exceeded: {member.filename}")
        return
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if member.issym() or member.islnk():
                    raise SafeExtractError(f"symlink or hardlink rejected: {member.name}")
                if member.isfile() and member.size > MAX_SINGLE_FILE_BYTES:
                    raise SafeExtractError(f"single file size limit exceeded: {member.name}")
        return
    raise SafeExtractError("unsupported archive extension")


def safe_extract_real_skill(archive_path: str | Path, quarantine_root: str | Path = QUARANTINE_DIR) -> dict[str, Any]:
    ensure_intake_dirs()
    archive = Path(archive_path).resolve()
    quarantine = Path(quarantine_root).resolve()
    quarantine.mkdir(parents=True, exist_ok=True)
    manifest = compute_archive_manifest(archive)
    sample_root = quarantine / manifest["sample_id"]
    extracted_dir = sample_root / "uploaded_skill"
    try:
        sample_root.resolve().relative_to(quarantine)
    except ValueError as exc:
        raise SafeExtractError("quarantine target escapes quarantine root") from exc
    if sample_root.exists():
        shutil.rmtree(sample_root)
    extracted_dir.mkdir(parents=True, exist_ok=True)
    try:
        _validate_archive_metadata(archive)
        result = safe_extract_archive(archive, extracted_dir)
    except Exception:
        if sample_root.exists():
            shutil.rmtree(sample_root)
        raise
    extracted_resolved = Path(result.extracted_path).resolve()
    try:
        extracted_resolved.relative_to(quarantine)
    except ValueError as exc:
        raise SafeExtractError("extracted path escapes quarantine root") from exc
    return {
        "sample_id": manifest["sample_id"],
        "extracted_path": str(extracted_resolved),
        "file_count": result.file_count,
        "total_bytes": result.total_bytes,
        "files": result.files,
    }


def summarize_extracted_skill(extracted_dir: str | Path) -> dict[str, Any]:
    root = Path(extracted_dir).resolve()
    files: list[str] = []
    suspicious_names: list[str] = []
    executable_count = 0
    total_size = 0
    flags = {
        "has_skill_md": False,
        "has_scripts": False,
        "has_env_file": False,
        "has_ssh_references": False,
        "has_docker_references": False,
        "has_network_references": False,
    }
    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.is_symlink():
            continue
        relative = str(path.relative_to(root))
        files.append(relative)
        name = path.name
        lower_name = name.lower()
        size = path.stat().st_size
        total_size += size
        if lower_name in SUSPICIOUS_NAMES:
            suspicious_names.append(relative)
        if path.name == "SKILL.md":
            flags["has_skill_md"] = True
        if path.suffix.lower() in {".sh", ".py", ".js", ".ts"} or lower_name in {"install.sh", "setup.sh", "run_skill.sh"}:
            flags["has_scripts"] = True
        if lower_name == ".env" or relative.endswith("/.env"):
            flags["has_env_file"] = True
        if path.stat().st_mode & 0o111:
            executable_count += 1
        if path.suffix.lower() in TEXT_SUFFIXES or path.name == "SKILL.md":
            text = path.read_text(encoding="utf-8", errors="replace")[:1024 * 1024]
            lowered = text.lower()
            if ".ssh" in lowered or "id_rsa" in lowered or "ssh_auth_sock" in lowered:
                flags["has_ssh_references"] = True
            if "docker.sock" in lowered or "/var/run/docker.sock" in lowered:
                flags["has_docker_references"] = True
            if "curl" in lowered or "wget" in lowered or "http://" in lowered or "https://" in lowered:
                flags["has_network_references"] = True
    return {
        "file_count": len(files),
        "total_size": total_size,
        "file_tree": files,
        "suspicious_file_names": suspicious_names,
        "executable_file_count": executable_count,
        **flags,
    }


def _build_static_only_job(sample_id: str, extracted_path: Path, static_report_path: Path, risk_summary: dict[str, Any]) -> dict[str, Any]:
    now = job_store.now_iso()
    return {
        "job_id": sample_id,
        "skill_name": sample_id,
        "note": "Stage 19 real skill static-only intake shadow job",
        "status": "static_completed",
        "created_at": now,
        "updated_at": now,
        "uploaded_archive": None,
        "extracted_skill_path": str(extracted_path),
        "static_scan_status": "completed",
        "static_scanner_mode": "real_skill_intake_static_only",
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
        "risk_summary": risk_summary,
        "report_paths": {"static_scan_report_json": _relative_repo_path(static_report_path)},
        "safety_boundaries": job_store.default_safety_boundaries(),
        "errors": [],
    }


def build_dynamic_gate_plan_only(sample_id: str, extracted_path: Path, static_report_path: Path, risk_summary: dict[str, Any]) -> dict[str, Any]:
    job = _build_static_only_job(sample_id, extracted_path, static_report_path, risk_summary)
    critical = int(risk_summary.get("critical", 0))
    high = int(risk_summary.get("high", 0))
    blockers: list[str] = []
    if critical > 0 or high > 0:
        blockers.append("HIGH / CRITICAL static findings block dynamic execution")
    allowed = not blockers
    eligibility = {
        "allowed": allowed,
        "reason": "eligible for manual review only; real skill dynamic execution is not enabled in Stage 19" if allowed else "HIGH or CRITICAL static findings block dynamic execution",
        "required_controls": list(dynamic_gate.REQUIRED_CONTROLS),
        "blockers": blockers,
        "warnings": ["Stage 19 is static-only; low-risk real skills still require manual review before any later dynamic stage."],
        "eligibility_status": "allowed_for_manual_review" if allowed else "denied",
        "risk_summary": risk_summary,
        "safety_boundaries": job["safety_boundaries"],
    }
    return {
        "sample_id": sample_id,
        "mode": "real_skill_static_only_dynamic_gate_plan",
        "dynamic_execution_performed": False,
        "execution_performed": False,
        "container_started": False,
        "uploaded_scripts_executed": False,
        "codex_executed": False,
        "strace_executed": False,
        "docker_executed": False,
        "network_enabled": False,
        "stage19_static_only": True,
        "requires_manual_review_before_stage21": True,
        "eligibility": eligibility,
        "required_controls": list(dynamic_gate.REQUIRED_CONTROLS),
    }


def _render_summary(result: dict[str, Any]) -> str:
    manifest = result["manifest"]
    summary = result["extracted_summary"]
    risk = result["static_report"].get("risk_summary", {})
    gate = result["dynamic_gate_plan"]["eligibility"]
    lines = [
        "# Real Skill Intake Static-only Summary",
        "",
        f"- sample_id: `{manifest['sample_id']}`",
        f"- archive_name: `{manifest['archive_name']}`",
        f"- sha256: `{manifest['sha256']}`",
        f"- intake_status: `{manifest['intake_status']}`",
        f"- file_count: `{summary['file_count']}`",
        f"- total_size: `{summary['total_size']}`",
        f"- has_skill_md: `{summary['has_skill_md']}`",
        f"- has_scripts: `{summary['has_scripts']}`",
        f"- risk_summary: `{json.dumps(risk, sort_keys=True)}`",
        f"- dynamic_gate: `{gate['eligibility_status']}`",
        f"- dynamic_gate_reason: `{gate['reason']}`",
        "- dynamic_execution_performed: `false`",
        "- container_started: `false`",
        "- uploaded_scripts_executed: `false`",
        "- codex_executed: `false`",
        "- strace_executed: `false`",
        "",
        "## File Tree",
        "",
    ]
    lines.extend(f"- `{item}`" for item in summary["file_tree"][:200])
    if len(summary["file_tree"]) > 200:
        lines.append("- `... truncated after 200 paths ...`")
    lines.extend(
        [
            "",
            "## Safety Boundary",
            "",
            "Stage 19 is static-only. It does not execute real skills, Docker, Codex, strace, uploaded scripts, network workflows, or real-token workflows.",
            "",
        ]
    )
    return "\n".join(lines)


def run_real_skill_static_only(archive_path: str | Path) -> dict[str, Any]:
    ensure_intake_dirs()
    archive = Path(archive_path).resolve()
    manifest = compute_archive_manifest(archive)
    sample_id = manifest["sample_id"]
    extract_info = safe_extract_real_skill(archive, QUARANTINE_DIR)
    extracted_path = Path(extract_info["extracted_path"]).resolve()
    extracted_summary = summarize_extracted_skill(extracted_path)

    sample_report_dir = REPORTS_DIR / sample_id
    if sample_report_dir.exists():
        shutil.rmtree(sample_report_dir)
    sample_report_dir.mkdir(parents=True, exist_ok=True)
    static_report = static_scanner_integration.run_real_static_scanner(extracted_path, sample_report_dir)
    static_json = sample_report_dir / "static_report.json"
    static_md = sample_report_dir / "report.md"
    target_static_json = REPORTS_DIR / f"{sample_id}_static_report.json"
    target_static_md = REPORTS_DIR / f"{sample_id}_static_report.md"
    _copy_file(static_json, target_static_json)
    _copy_file(static_md, target_static_md)

    dynamic_gate_plan = build_dynamic_gate_plan_only(sample_id, extracted_path, target_static_json, static_report.get("risk_summary", {}))
    target_gate_json = REPORTS_DIR / f"{sample_id}_dynamic_gate_plan.json"
    target_gate_json.write_text(json.dumps(dynamic_gate_plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest.update(
        {
            "intake_status": "static_only_completed",
            "quarantine_path": str(extracted_path),
            "extract_info": extract_info,
            "extracted_summary": extracted_summary,
            "report_paths": {
                "static_report_json": _relative_repo_path(target_static_json),
                "static_report_md": _relative_repo_path(target_static_md),
                "dynamic_gate_plan_json": _relative_repo_path(target_gate_json),
                "summary_md": _relative_repo_path(REPORTS_DIR / f"{sample_id}_summary.md"),
            },
            "execution_performed": False,
            "docker_executed": False,
            "codex_executed": False,
            "strace_executed": False,
            "uploaded_scripts_executed": False,
        }
    )
    manifest_path = MANIFESTS_DIR / f"{sample_id}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = {
        "manifest": manifest,
        "manifest_path": _relative_repo_path(manifest_path),
        "extracted_summary": extracted_summary,
        "static_report": static_report,
        "dynamic_gate_plan": dynamic_gate_plan,
    }
    summary_md = REPORTS_DIR / f"{sample_id}_summary.md"
    summary_md.write_text(_render_summary(result), encoding="utf-8")
    return result


def run_inbox_static_only(inbox_dir: str | Path = INBOX_DIR) -> dict[str, Any]:
    ensure_intake_dirs()
    archives = discover_real_skill_archives(inbox_dir)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for archive in archives:
        try:
            result = run_real_skill_static_only(archive)
            results.append(
                {
                    "sample_id": result["manifest"]["sample_id"],
                    "archive_name": result["manifest"]["archive_name"],
                    "sha256": result["manifest"]["sha256"],
                    "risk_summary": result["static_report"].get("risk_summary", {}),
                    "dynamic_gate_status": result["dynamic_gate_plan"]["eligibility"]["eligibility_status"],
                    "manifest_path": result["manifest_path"],
                }
            )
        except Exception as exc:
            failures.append({"archive_name": archive.name, "error": str(exc)})
    summary = {
        "inbox": str(Path(inbox_dir).resolve()),
        "archives_discovered": len(archives),
        "processed": len(results),
        "failed": len(failures),
        "results": results,
        "failures": failures,
        "docker_executed": False,
        "codex_executed": False,
        "strace_executed": False,
        "real_skills_executed": False,
        "network_enabled": False,
    }
    (REPORTS_DIR / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORTS_DIR / "report.md").write_text(_render_inbox_report(summary), encoding="utf-8")
    return summary


def _render_inbox_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Real Skill Intake Static-only Report",
        "",
        f"- inbox: `{summary['inbox']}`",
        f"- archives_discovered: `{summary['archives_discovered']}`",
        f"- processed: `{summary['processed']}`",
        f"- failed: `{summary['failed']}`",
        "- docker_executed: `false`",
        "- codex_executed: `false`",
        "- strace_executed: `false`",
        "- real_skills_executed: `false`",
        "- network_enabled: `false`",
        "",
        "## Results",
        "",
    ]
    if not summary["results"]:
        lines.append("No archives processed.")
    for item in summary["results"]:
        lines.append(
            f"- `{item['sample_id']}` `{item['archive_name']}` gate={item['dynamic_gate_status']} risk=`{json.dumps(item['risk_summary'], sort_keys=True)}`"
        )
    if summary["failures"]:
        lines.extend(["", "## Failures", ""])
        for item in summary["failures"]:
            lines.append(f"- `{item['archive_name']}`: {item['error']}")
    lines.extend(
        [
            "",
            "## Safety Boundary",
            "",
            "Stage 19 only quarantines, manifests, safely extracts, statically scans, and writes dynamic gate plan-only reports. It does not execute real skills.",
            "",
        ]
    )
    return "\n".join(lines)
