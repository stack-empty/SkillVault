from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import dynamic_gate
import job_store


DEFAULT_IMAGE = "python:3.11-slim"
TIMEOUT_SECONDS = 30
HARDENING_POLICY_VERSION = "stage22-runtime-hardening-v1"
PIDS_LIMIT = "256"
MEMORY_LIMIT = "512m"
CPU_LIMIT = "1.0"
ALLOWED_RUNTIME_IMAGES = {
    "python:3.11-slim",
    "ubuntu:24.04",
    "codex-safe-smoke:trace",
    "codex-safe-smoke:manual",
}
SENSITIVE_ENV_EXACT = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "CODEX_HOME",
    "SSH_AUTH_SOCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
}
SENSITIVE_ENV_SUFFIXES = ("_TOKEN", "_KEY", "_SECRET")
FAKE_CONTAINER_ENV = {
    "HOME": "/home/codexsafe",
    "CODEX_HOME": "/home/codexsafe/.codex",
}


def _job_root(job: dict[str, Any]) -> Path:
    return job_store.job_dir(job["job_id"]).resolve()


def _output_dir(job: dict[str, Any]) -> Path:
    path = _job_root(job) / "dynamic_execution"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(job_store.REPO_ROOT.resolve()))
    except ValueError:
        return str(path)


def _sensitive_env_names(env: dict[str, str] | None = None) -> list[str]:
    source = os.environ if env is None else env
    names: list[str] = []
    for name in source:
        if name in SENSITIVE_ENV_EXACT or name.endswith(SENSITIVE_ENV_SUFFIXES):
            names.append(name)
    return sorted(set(names))


def _sanitized_subprocess_env(output_dir: Path, env: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if env is None else env
    docker_home = output_dir / "subprocess_home"
    docker_home.mkdir(parents=True, exist_ok=True)
    clean_env = {
        "PATH": source.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": FAKE_CONTAINER_ENV["HOME"],
        "CODEX_HOME": FAKE_CONTAINER_ENV["CODEX_HOME"],
    }
    if source.get("LANG"):
        clean_env["LANG"] = source["LANG"]
    if source.get("LC_ALL"):
        clean_env["LC_ALL"] = source["LC_ALL"]
    return clean_env


def _clean_env_has_sensitive_passthrough(clean_env: dict[str, str]) -> bool:
    for name, value in clean_env.items():
        if name in FAKE_CONTAINER_ENV and value == FAKE_CONTAINER_ENV[name]:
            continue
        if name in SENSITIVE_ENV_EXACT or name.endswith(SENSITIVE_ENV_SUFFIXES):
            return True
    return False


def _docker_command_has_sensitive_env_passthrough(command: list[str]) -> bool:
    for index, item in enumerate(command[:-1]):
        if item != "-e":
            continue
        env_spec = command[index + 1]
        name, _, value = env_spec.partition("=")
        if name in FAKE_CONTAINER_ENV and value == FAKE_CONTAINER_ENV[name]:
            continue
        if name in SENSITIVE_ENV_EXACT or name.endswith(SENSITIVE_ENV_SUFFIXES):
            return True
    return False


def _environment_report_fields(output_dir: Path) -> dict[str, Any]:
    clean_env = _sanitized_subprocess_env(output_dir)
    sensitive_names = _sensitive_env_names()
    return {
        "host_sensitive_env_detected": bool(sensitive_names),
        "host_sensitive_env_names_redacted": sensitive_names,
        "sanitized_subprocess_env_used": True,
        "sanitized_subprocess_env_keys": sorted(clean_env),
        "real_tokens_passed_to_container": False,
    }


def _runtime_image() -> str:
    return DEFAULT_IMAGE


def _image_allowlisted(image: str) -> bool:
    return image in ALLOWED_RUNTIME_IMAGES


def _inspect_local_runtime_image(image: str, clean_env: dict[str, str]) -> dict[str, Any]:
    if not _image_allowlisted(image):
        return {
            "runtime_image": image,
            "image_allowlisted": False,
            "image_present_locally": False,
            "image_pull_prevented": True,
            "docker_pull_executed": False,
            "image_inspect_performed": False,
            "image_inspect_exit_code": None,
        }
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=TIMEOUT_SECONDS,
        env=clean_env,
        check=False,
    )
    return {
        "runtime_image": image,
        "image_allowlisted": True,
        "image_present_locally": completed.returncode == 0,
        "image_pull_prevented": completed.returncode != 0,
        "docker_pull_executed": False,
        "image_inspect_performed": True,
        "image_inspect_exit_code": completed.returncode,
    }


def build_safe_dynamic_command(job: dict[str, Any], output_dir: Path, image: str | None = None) -> dict[str, Any]:
    image = image or _runtime_image()
    if not _image_allowlisted(image):
        raise ValueError("runtime image is not allowlisted")
    skill_path = Path(str(job["extracted_skill_path"])).resolve()
    output = output_dir.resolve()
    container_name = f"codex-webui-safe-{job['job_id']}"
    inspect_script = (
        "set -eu; "
        "pwd; "
        "find /workspace/skill -maxdepth 3 -type f -print; "
        "grep -RInE 'docker[.]sock|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|[.]ssh|[.]codex|[.]agents' /workspace/skill || true"
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        PIDS_LIMIT,
        "--memory",
        MEMORY_LIMIT,
        "--cpus",
        CPU_LIMIT,
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "--tmpfs",
        "/home/codexsafe:rw,nosuid,nodev,uid=1000,gid=1000,mode=700",
        "-e",
        "HOME=/home/codexsafe",
        "-e",
        "CODEX_HOME=/home/codexsafe/.codex",
        "-v",
        f"{skill_path}:/workspace/skill:ro",
        "-v",
        f"{output}:/output:rw",
        image,
        "/bin/sh",
        "-c",
        inspect_script,
    ]
    return {
        "command": command,
        "runtime_image": image,
        "image_allowlisted": True,
        "image_present_locally": None,
        "image_pull_prevented": True,
        "docker_pull_executed": False,
        "container_name": container_name,
        "network_mode": "none",
        "sample_mount_mode": "read-only",
        "output_mount_mode": "writable",
        "fake_home_used": True,
        "fake_codex_home_used": True,
        "docker_sock_mounted": False,
        "privileged": False,
        "network_host": False,
        "hardening_policy_version": HARDENING_POLICY_VERSION,
        "no_new_privileges": True,
        "cap_drop_all": True,
        "read_only_rootfs": True,
        "pids_limit": PIDS_LIMIT,
        "memory_limit": MEMORY_LIMIT,
        "cpu_limit": CPU_LIMIT,
        "docker_network_none": True,
        "docker_network_host_forbidden": True,
        "docker_sock_forbidden": True,
        "privileged_forbidden": True,
        "real_home_forbidden": True,
        "real_codex_home_forbidden": True,
        "real_token_forbidden": True,
        "uploaded_script_execution_forbidden": True,
        "install_command_forbidden": True,
        "docker_pull_forbidden": True,
        "local_image_preflight_required": True,
        "sanitized_env_required": True,
        "runtime_audit_complete": True,
        "timeout_seconds": TIMEOUT_SECONDS,
        "uploaded_scripts_executed": False,
        "codex_executed": False,
        "strace_executed": False,
    }


def run_safe_dynamic_execution(job: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    output_dir = _output_dir(job)
    stdout_path = output_dir / "stdout.txt"
    stderr_path = output_dir / "stderr.txt"
    report_path = output_dir / "runtime_execution_report.json"
    md_path = output_dir / "report.md"
    eligibility = dynamic_gate.evaluate_dynamic_eligibility(job)
    command_info: dict[str, Any] | None = None
    clean_env = _sanitized_subprocess_env(output_dir)
    env_report = _environment_report_fields(output_dir)

    if not eligibility["allowed"] or not job.get("dynamic_user_confirmed"):
        report = _base_report(job, eligibility)
        report.update(env_report)
        report.update(
            {
                "execution_attempted": False,
                "execution_performed": False,
                "container_started": False,
                "container_removed": False,
                "final_verdict": "fail closed: dynamic gate denied or human confirmation missing",
            }
        )
        _write_outputs(report, report_path, md_path, stdout_path, stderr_path)
        _update_job(job, report_path, md_path, stdout_path, stderr_path, report, "blocked")
        return report

    command_info = build_safe_dynamic_command(job, output_dir)
    report = _base_report(job, eligibility)
    report.update(command_info)
    report.update(env_report)
    report["execution_attempted"] = True

    if dry_run:
        report.update(
            {
                "execution_performed": False,
                "container_started": False,
                "container_removed": False,
                "final_verdict": "dry run: safe dynamic command validated but not executed",
            }
        )
        _write_outputs(report, report_path, md_path, stdout_path, stderr_path)
        _update_job(job, report_path, md_path, stdout_path, stderr_path, report, "dry_run")
        return report

    if (
        _clean_env_has_sensitive_passthrough(clean_env)
        or _docker_command_has_sensitive_env_passthrough(command_info["command"])
    ):
        report = _base_report(job, eligibility)
        report.update(command_info)
        report.update(env_report)
        report.update(
            {
                "execution_attempted": False,
                "execution_performed": False,
                "container_started": False,
                "container_removed": False,
                "real_tokens_present": True,
                "real_tokens_passed_to_container": True,
                "final_verdict": "fail closed: sanitized subprocess environment would leak sensitive data",
            }
        )
        _write_outputs(report, report_path, md_path, stdout_path, stderr_path)
        _update_job(job, report_path, md_path, stdout_path, stderr_path, report, "blocked")
        return report

    image_preflight = _inspect_local_runtime_image(command_info["runtime_image"], clean_env)
    report.update(image_preflight)
    if not image_preflight["image_allowlisted"] or not image_preflight["image_present_locally"]:
        report.update(
            {
                "execution_attempted": False,
                "execution_performed": False,
                "container_started": False,
                "container_removed": False,
                "final_verdict": "fail closed: required local runtime image is missing",
            }
        )
        _write_outputs(report, report_path, md_path, stdout_path, stderr_path)
        _update_job(job, report_path, md_path, stdout_path, stderr_path, report, "blocked")
        return report

    completed = subprocess.run(
        command_info["command"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=TIMEOUT_SECONDS,
        env=clean_env,
        check=False,
    )
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    report.update(
        {
            "execution_performed": True,
            "container_started": True,
            "container_removed": True,
            "exit_code": completed.returncode,
            "final_verdict": "safe dynamic benign inspection completed" if completed.returncode == 0 else "safe dynamic benign inspection completed with nonzero exit",
        }
    )
    _write_outputs(report, report_path, md_path, stdout_path, stderr_path, preserve_logs=True)
    _update_job(job, report_path, md_path, stdout_path, stderr_path, report, "completed")
    return report


def _base_report(job: dict[str, Any], eligibility: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "execution_attempted": False,
        "execution_performed": False,
        "container_started": False,
        "container_removed": False,
        "network_mode": "none",
        "sample_mount_mode": "read-only",
        "output_mount_mode": "writable",
        "fake_home_used": True,
        "fake_codex_home_used": True,
        "docker_sock_mounted": False,
        "privileged": False,
        "network_host": False,
        "hardening_policy_version": HARDENING_POLICY_VERSION,
        "no_new_privileges": True,
        "cap_drop_all": True,
        "read_only_rootfs": True,
        "pids_limit": PIDS_LIMIT,
        "memory_limit": MEMORY_LIMIT,
        "cpu_limit": CPU_LIMIT,
        "docker_network_none": True,
        "docker_network_host_forbidden": True,
        "docker_sock_forbidden": True,
        "privileged_forbidden": True,
        "real_home_forbidden": True,
        "real_codex_home_forbidden": True,
        "real_token_forbidden": True,
        "real_tokens_present": False,
        "runtime_image": DEFAULT_IMAGE,
        "image_allowlisted": True,
        "image_present_locally": None,
        "image_pull_prevented": True,
        "docker_pull_executed": False,
        "image_inspect_performed": False,
        "image_inspect_exit_code": None,
        "host_sensitive_env_detected": bool(_sensitive_env_names()),
        "host_sensitive_env_names_redacted": _sensitive_env_names(),
        "sanitized_subprocess_env_used": True,
        "sanitized_subprocess_env_keys": [],
        "real_tokens_passed_to_container": False,
        "uploaded_script_execution_forbidden": True,
        "install_command_forbidden": True,
        "docker_pull_forbidden": True,
        "local_image_preflight_required": True,
        "sanitized_env_required": True,
        "runtime_audit_complete": True,
        "timeout_seconds": TIMEOUT_SECONDS,
        "exit_code": None,
        "killed_by_monitor": False,
        "high": 0,
        "critical": 0,
        "eligibility": eligibility,
        "uploaded_scripts_executed": False,
        "codex_executed": False,
        "strace_executed": False,
        "final_verdict": "not run",
    }


def _write_outputs(
    report: dict[str, Any],
    report_path: Path,
    md_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    *,
    preserve_logs: bool = False,
) -> None:
    if not preserve_logs:
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Web UI Safe Dynamic Execution Report",
        "",
        f"- execution_attempted: `{report.get('execution_attempted')}`",
        f"- execution_performed: `{report.get('execution_performed')}`",
        f"- container_started: `{report.get('container_started')}`",
        f"- container_removed: `{report.get('container_removed')}`",
        f"- network_mode: `{report.get('network_mode')}`",
        f"- sample_mount_mode: `{report.get('sample_mount_mode')}`",
        f"- output_mount_mode: `{report.get('output_mount_mode')}`",
        f"- fake_home_used: `{report.get('fake_home_used')}`",
        f"- fake_codex_home_used: `{report.get('fake_codex_home_used')}`",
        f"- docker_sock_mounted: `{report.get('docker_sock_mounted')}`",
        f"- privileged: `{report.get('privileged')}`",
        f"- network_host: `{report.get('network_host')}`",
        f"- hardening_policy_version: `{report.get('hardening_policy_version')}`",
        f"- no_new_privileges: `{report.get('no_new_privileges')}`",
        f"- cap_drop_all: `{report.get('cap_drop_all')}`",
        f"- read_only_rootfs: `{report.get('read_only_rootfs')}`",
        f"- pids_limit: `{report.get('pids_limit')}`",
        f"- memory_limit: `{report.get('memory_limit')}`",
        f"- cpu_limit: `{report.get('cpu_limit')}`",
        f"- docker_network_none: `{report.get('docker_network_none')}`",
        f"- docker_network_host_forbidden: `{report.get('docker_network_host_forbidden')}`",
        f"- docker_sock_forbidden: `{report.get('docker_sock_forbidden')}`",
        f"- privileged_forbidden: `{report.get('privileged_forbidden')}`",
        f"- real_home_forbidden: `{report.get('real_home_forbidden')}`",
        f"- real_codex_home_forbidden: `{report.get('real_codex_home_forbidden')}`",
        f"- real_token_forbidden: `{report.get('real_token_forbidden')}`",
        f"- real_tokens_present: `{report.get('real_tokens_present')}`",
        f"- runtime_image: `{report.get('runtime_image')}`",
        f"- image_allowlisted: `{report.get('image_allowlisted')}`",
        f"- image_present_locally: `{report.get('image_present_locally')}`",
        f"- image_pull_prevented: `{report.get('image_pull_prevented')}`",
        f"- docker_pull_executed: `{report.get('docker_pull_executed')}`",
        f"- image_inspect_performed: `{report.get('image_inspect_performed')}`",
        f"- image_inspect_exit_code: `{report.get('image_inspect_exit_code')}`",
        f"- host_sensitive_env_detected: `{report.get('host_sensitive_env_detected')}`",
        f"- host_sensitive_env_names_redacted: `{', '.join(report.get('host_sensitive_env_names_redacted') or [])}`",
        f"- sanitized_subprocess_env_used: `{report.get('sanitized_subprocess_env_used')}`",
        f"- sanitized_subprocess_env_keys: `{', '.join(report.get('sanitized_subprocess_env_keys') or [])}`",
        f"- real_tokens_passed_to_container: `{report.get('real_tokens_passed_to_container')}`",
        f"- uploaded_script_execution_forbidden: `{report.get('uploaded_script_execution_forbidden')}`",
        f"- install_command_forbidden: `{report.get('install_command_forbidden')}`",
        f"- docker_pull_forbidden: `{report.get('docker_pull_forbidden')}`",
        f"- local_image_preflight_required: `{report.get('local_image_preflight_required')}`",
        f"- sanitized_env_required: `{report.get('sanitized_env_required')}`",
        f"- runtime_audit_complete: `{report.get('runtime_audit_complete')}`",
        f"- uploaded_scripts_executed: `{report.get('uploaded_scripts_executed')}`",
        f"- codex_executed: `{report.get('codex_executed')}`",
        f"- strace_executed: `{report.get('strace_executed')}`",
        "",
        "## Final Verdict",
        "",
        str(report.get("final_verdict", "")),
        "",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")


def _update_job(
    job: dict[str, Any],
    report_path: Path,
    md_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    report: dict[str, Any],
    status: str,
) -> None:
    job.setdefault("report_paths", {})["dynamic_execution_report_json"] = _relative_repo_path(report_path)
    job["report_paths"]["dynamic_execution_report_md"] = _relative_repo_path(md_path)
    job["report_paths"]["dynamic_stdout"] = _relative_repo_path(stdout_path)
    job["report_paths"]["dynamic_stderr"] = _relative_repo_path(stderr_path)
    job["dynamic_execution_report"] = report
    job["dynamic_scan_status"] = "completed" if status == "completed" else "blocked" if status == "blocked" else "dry_run"
    job["status"] = "dynamic_completed" if status == "completed" else "dynamic_blocked"
    job_store.save_job(job)
