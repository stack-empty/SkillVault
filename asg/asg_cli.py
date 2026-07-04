"""ASG unified CLI entry point.

Usage:
    python -m asg.asg_cli scan <skill_path> [--output-dir DIR] [--enable-claude] [--enable-honeypot]
    python -m asg.asg_cli scan-all-samples [--output-dir DIR] [--enable-claude]
    python -m asg.asg_cli build-dashboard [--output dashboard/dashboard_data.json]
    python -m asg.asg_cli release-check

The CLI performs a 4-layer analysis and writes a dashboard-compatible
JSON report:

    1. Static rule scan        (asg/rules.py — 17 paper-aligned patterns)
    2. Attack chain analysis   (asg/attack_chain.py — paper Table 11)
    3. Composite risk scoring  (asg/risk_scorer.py — math formula)
    4. Optional Claude eval    (asg/claude_runner.py — agent-in-the-loop)

Honeypot detection is integrated when --enable-honeypot is set: markers
are generated, optionally injected into a fake-HOME tree under the
output dir, and the Claude evaluator looks for marker leakage.

The CLI is fail-open: if anthropic SDK / API key is missing, the Claude
layer is skipped with a neutral score (0.5).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Module imports work whether invoked via `python -m asg.asg_cli ...`
# or `python asg/asg_cli.py ...`.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from asg import (
    attack_chain,
    claude_runner,
    dashboard_builder,
    honeypot,
    risk_scorer,
    rules,
    skill_graph,
    vm_evidence,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "analysis_results" / "asg"


def _runtime_layer_from_vm_record(vm_record: dict[str, Any] | None) -> dict[str, Any]:
    """Convert ingested VM evidence into the report's layer_5 shape."""
    if not vm_record:
        return {"present": False}
    return {
        "present": True,
        "evidence_dir": vm_record.get("evidence_dir"),
        "mode": (
            "paper_no_claude"
            if not vm_record.get("claude", {}).get("output_path")
            else "agent_in_the_loop"
        ),
        "claude_output_present": bool(
            vm_record.get("claude", {}).get("output_path")
        ),
        "claude_output_size_chars": vm_record.get("claude", {}).get(
            "response_length_chars", 0
        ),
        "claude_output_preview": vm_record.get("claude", {}).get(
            "output_preview", ""
        )[:600],
        "strace": vm_record.get("strace", {}),
        "tcpdump": vm_record.get("tcpdump", {}),
        "filesystem": vm_record.get("filesystem", {}),
        "inotify": vm_record.get("inotify", {}),
        "anthropic_refusal": vm_record.get("anthropic_refusal", {}),
        "nova": vm_record.get("nova", {}),
        "honeypot": {
            "touched": vm_record.get("honeypot_evidence", {}).get("touched", False),
            "leaked": vm_record.get("honeypot_evidence", {}).get("any_honeypot_leaked", False),
            "touched_files": vm_record.get("honeypot_evidence", {}).get("touched_files", []),
            "leak_sources": vm_record.get("honeypot_evidence", {}).get("leak_sources", []),
        },
    }


def _find_existing_vm_evidence_dir(skill_name: str, output_dir: Path) -> Path | None:
    """Reuse already-pulled VM evidence when scan-all-samples is rerun.

    Accepts vm_paper_logs (strace/pcap/honeypot present) and vm_ssh_logs
    (mode-3 Claude conversation in ssh_run_stdout.log — usable even when
    strace.log etc are missing because the container TEST_DIR_MOUNT bug
    used to drop them on the ephemeral container fs).
    """
    skill_out = output_dir / skill_name
    for dirname in ("vm_paper_logs", "vm_ssh_logs"):
        candidate = skill_out / dirname
        if not candidate.is_dir():
            continue
        primary_evidence = any(
            (candidate / name).exists()
            for name in ("strace.log", "claude_output.txt", "network.pcap")
        )
        mode3_fallback = (candidate / "ssh_run_stdout.log").exists()
        if primary_evidence or mode3_fallback:
            return candidate
    return None


# ============================================================
# Single-skill analysis
# ============================================================
SKILL_CONTENT_TEXT_EXTENSIONS = {
    ".md", ".py", ".sh", ".txt", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".js", ".ts",
}


def _walk_skill_contents(
    skill_path: Path,
    max_files: int = 50,
    max_chars_per_file: int = 4000,
    max_total_preview_bytes: int = 200_000,
) -> dict[str, Any]:
    """Collect file list + content preview for every text file in the skill.

    Each text file gets a content preview (capped at max_chars_per_file).
    Binary files get path + size only.
    """
    files: list[dict[str, Any]] = []
    total_bytes = 0
    total_preview = 0
    if not skill_path.exists():
        return {"file_count": 0, "total_bytes": 0, "files": [], "skill_md_preview": ""}
    truncated = False
    skill_md_preview = ""
    for p in sorted(skill_path.rglob("*")):
        if not p.is_file():
            continue
        if len(files) >= max_files:
            truncated = True
            break
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        rel = p.relative_to(skill_path).as_posix()
        ext = p.suffix.lower()
        kind = "text" if ext in SKILL_CONTENT_TEXT_EXTENSIONS else "binary"
        entry: dict[str, Any] = {
            "path": rel, "size_bytes": size, "kind": kind,
            "content_preview": "", "content_truncated": False,
        }
        if kind == "text" and total_preview < max_total_preview_bytes:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            preview = text[:max_chars_per_file]
            if len(text) > max_chars_per_file:
                entry["content_truncated"] = True
            entry["content_preview"] = preview
            total_preview += len(preview)
            if rel == "SKILL.md":
                skill_md_preview = preview
        files.append(entry)
        total_bytes += size
    return {
        "file_count": len(files),
        "total_bytes": total_bytes,
        "files": files,
        "files_truncated": truncated,
        "skill_md_preview": skill_md_preview,
    }


def analyze_skill(
    skill_path: Path,
    output_dir: Path,
    enable_claude: bool = False,
    enable_honeypot: bool = False,
    claude_model: str = "claude-sonnet-4-5",
    vm_evidence_dir: Path | None = None,
) -> dict[str, Any]:
    """Run the full 4-layer analysis for one skill.

    Writes:
        <output_dir>/<skill_name>/scan_result.json
        <output_dir>/<skill_name>/chain_result.json
        <output_dir>/<skill_name>/agent_eval.json
        <output_dir>/<skill_name>/honeypot_bundle.json
        <output_dir>/<skill_name>/asg_report.json    (canonical bundle)
    Returns the asg_report dict.
    """
    skill_path = Path(skill_path).resolve()
    if not skill_path.exists():
        raise FileNotFoundError(f"Skill path does not exist: {skill_path}")

    skill_out = output_dir / skill_path.name
    skill_out.mkdir(parents=True, exist_ok=True)

    # === Layer 1: Static scan ===
    scan_result = rules.scan_skill_directory(skill_path)
    (skill_out / "scan_result.json").write_text(
        json.dumps(scan_result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # === Layer 2: Attack chain analysis ===
    chain_result = attack_chain.analyze(scan_result)
    (skill_out / "chain_result.json").write_text(
        json.dumps(chain_result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # === Layer 4 (computed before risk scoring): honeypot bundle ===
    honeypot_record: dict[str, Any] = {
        "enabled": enable_honeypot,
        "bundle": None,
        "any_honeypot_leaked": False,
        "deployed": False,
        "honeypot_deployed": False,
        "deployment_mode": None,
        "honeypot_deployment_mode": None,
        "files_created": [],
        "honeypot_files_created": [],
        "marker_count": 0,
        "honeypot_marker_count": 0,
        "redacted_preview": {},
        "honeypot_markers_redacted_preview": {},
        "touched": False,
        "honeypot_touched": False,
        "touched_files": [],
        "leak_sources": [],
        "honeypot_leak_sources": [],
        "matches": [],
    }
    honeypot_markers: list[str] = []
    if enable_honeypot:
        bundle = honeypot.generate_bundle(sample_name=skill_path.name)
        honeypot_record["bundle"] = bundle.to_redacted_dict()
        honeypot_record["redacted_preview"] = bundle.redacted_preview
        honeypot_record["honeypot_markers_redacted_preview"] = bundle.redacted_preview
        honeypot_record["marker_count"] = len(bundle.all_markers())
        honeypot_record["honeypot_marker_count"] = len(bundle.all_markers())
        honeypot_markers = bundle.all_markers()
        (skill_out / "honeypot_bundle.json").write_text(
            json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # === Layer 3: Claude agent eval (live API OR ingested VM evidence) ===
    vm_record: dict[str, Any] | None = None
    if vm_evidence_dir:
        try:
            vm_record = vm_evidence.ingest_evidence_dir(
                vm_evidence_dir,
                honeypot_markers=honeypot_markers or None,
            )
            (skill_out / "vm_evidence.json").write_text(
                json.dumps(vm_record, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            agent_eval = vm_evidence.vm_evidence_to_agent_eval(vm_record)
            # Honeypot leak status from VM evidence overrides synthetic bundle
            hp_vm = vm_record.get("honeypot_evidence", {})
            if honeypot_record.get("enabled") and hp_vm:
                honeypot_record.update(
                    {
                        "deployed": hp_vm.get("deployed", False),
                        "honeypot_deployed": hp_vm.get("deployed", False),
                        "deployment_mode": hp_vm.get("deployment_mode"),
                        "honeypot_deployment_mode": hp_vm.get("deployment_mode"),
                        "bundle_id": hp_vm.get("bundle_id"),
                        "files_created": hp_vm.get("files_created", []),
                        "honeypot_files_created": hp_vm.get("files_created", []),
                        "marker_count": hp_vm.get("marker_count", honeypot_record.get("marker_count", 0)),
                        "honeypot_marker_count": hp_vm.get("marker_count", honeypot_record.get("marker_count", 0)),
                        "redacted_preview": hp_vm.get("redacted_preview", honeypot_record.get("redacted_preview", {})),
                        "honeypot_markers_redacted_preview": hp_vm.get("redacted_preview", honeypot_record.get("redacted_preview", {})),
                        "touched": hp_vm.get("touched", False),
                        "honeypot_touched": hp_vm.get("touched", False),
                        "touched_files": hp_vm.get("touched_files", []),
                        "leak_sources": hp_vm.get("leak_sources", []),
                        "honeypot_leak_sources": hp_vm.get("leak_sources", []),
                        "matches": hp_vm.get("matches", []),
                    }
                )
            if honeypot_record.get("enabled") and hp_vm.get("any_honeypot_leaked"):
                honeypot_record["any_honeypot_leaked"] = True
                honeypot_record["leaked_from_vm_evidence"] = True
        except FileNotFoundError as exc:
            agent_eval = {
                "tested": False,
                "skipped_reason": f"vm_evidence_dir invalid: {exc}",
                "refusal_score": 1.0,
                "disclosure_score": 0.0,
                "compliance_signal": 0.0,
                "raw_response_preview": "",
                "model": claude_model,
            }
    elif enable_claude:
        agent_eval = claude_runner.evaluate_skill(
            skill_path=skill_path,
            honeypot_markers=honeypot_markers or None,
            model=claude_model,
        )
    else:
        agent_eval = {
            "tested": False,
            "skipped_reason": "--enable-claude not set and no VM evidence provided",
            "refusal_score": 1.0,
            "disclosure_score": 0.0,
            "compliance_signal": 0.0,
            "raw_response_preview": "",
            "model": claude_model,
        }
    (skill_out / "agent_eval.json").write_text(
        json.dumps(agent_eval, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # If honeypot ran AND Claude responded, check Claude's text for marker leakage.
    if (
        enable_honeypot
        and agent_eval.get("tested")
        and agent_eval.get("honeypot_response_leak_detected")
    ):
        honeypot_record["any_honeypot_leaked"] = True
        honeypot_record["leaked_markers"] = agent_eval.get(
            "honeypot_markers_leaked_in_response", []
        )

    # === Layer 5: VM Docker Runtime evidence (if any) ===
    layer_5_runtime = _runtime_layer_from_vm_record(vm_record)

    # === 增量合并：保留之前已经跑过的 layer 数据，避免重跑某层时丢失其他层 ===
    # 例：如果之前跑过 Claude AI 评判（layer 3），现在只跑 vm-paper-run（只产生 layer 5），
    # 应该保留 layer 3 数据，而不是用本次的空 agent_eval 覆盖。
    existing_report_path = skill_out / "asg_report.json"
    if existing_report_path.exists():
        try:
            prev = json.loads(existing_report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            prev = {}
        # Layer 3: 保留真正调过 LLM 的结果，不被 vm-paper-run 的伪 agent_eval 覆盖
        prev_ae = prev.get("layer_3_agent_eval") or {}
        prev_has_real_llm = bool(prev_ae.get("verdict_from_llm")
                                 or prev_ae.get("detailed_audit"))
        cur_has_real_llm = bool(agent_eval.get("verdict_from_llm")
                                or agent_eval.get("detailed_audit"))
        if not agent_eval.get("tested") and prev_ae.get("tested"):
            agent_eval = prev_ae
        elif prev_has_real_llm and not cur_has_real_llm:
            # 本次是 paper-mode 等只产生 runtime 证据的扫描，
            # 不应覆盖之前真调 Claude API 拿到的 verdict/risks。
            agent_eval = prev_ae
        # Layer 5: 本次没新 runtime 证据但旧的有 → 保留旧的
        prev_rt = prev.get("layer_5_runtime") or {}
        if not layer_5_runtime.get("present") and prev_rt.get("present"):
            layer_5_runtime = prev_rt
        # === Mode-2 / Mode-3 双槽合并：保留之前跑的另一个模式 ===
        # layer_5_runtime_mode2 = paper-mode 证据
        # layer_5_runtime_mode3 = Claude in Docker 证据
        # 两者独立保存，互不覆盖；UI 分别渲染。
        prev_m2 = prev.get("layer_5_runtime_mode2") or {}
        prev_m3 = prev.get("layer_5_runtime_mode3") or {}
        # 用变量先存，下面写 asg_report 时合并
        cur_mode = layer_5_runtime.get("mode")
        if cur_mode == "paper_no_claude":
            new_m2 = layer_5_runtime
            new_m3 = prev_m3
        elif cur_mode == "agent_in_the_loop":
            new_m3 = layer_5_runtime
            new_m2 = prev_m2
        else:
            new_m2 = prev_m2
            new_m3 = prev_m3
        # Layer 4: 本次没开 honeypot 但旧的开过 → 保留旧的（防止 honeypot 数据被清空）
        prev_hp = prev.get("layer_4_honeypot") or {}
        if not honeypot_record.get("enabled") and prev_hp.get("enabled"):
            honeypot_record = prev_hp
    else:
        cur_mode = layer_5_runtime.get("mode")
        new_m2 = layer_5_runtime if cur_mode == "paper_no_claude" else {}
        new_m3 = layer_5_runtime if cur_mode == "agent_in_the_loop" else {}

    # === Composite risk scoring ===
    # layer_5_runtime 给 risk_scorer 用「合并视图」：优先 Mode-3（含 floor #5
    # Anthropic 拒绝信号），如果 Mode-3 未跑则用 Mode-2 的脚本裸跑信号。
    runtime_for_score = (new_m3 if new_m3.get("present") else
                         new_m2 if new_m2.get("present") else
                         layer_5_runtime)
    risk = risk_scorer.compute_risk(
        scan_result=scan_result,
        chain_result=chain_result,
        agent_eval=agent_eval if agent_eval.get("tested") else None,
        honeypot_result=honeypot_record if enable_honeypot else None,
        layer_5_runtime=runtime_for_score,
    )

    asg_report = {
        "asg_version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "skill_name": scan_result["skill_name"],
        "skill_path": scan_result["skill_path"],
        "skill_contents": _walk_skill_contents(skill_path),
        "layer_1_static_scan": {
            "total_findings": scan_result["total_findings"],
            "by_severity": scan_result["by_severity"],
            "by_pattern": scan_result["by_pattern"],
            "by_kill_chain_phase": scan_result["by_kill_chain_phase"],
            "rule_ids_hit": scan_result["rule_ids_hit"],
            "files_scanned_count": scan_result["files_scanned_count"],
        },
        "layer_2_attack_chain": chain_result,
        "layer_3_agent_eval": agent_eval,
        "layer_4_honeypot": honeypot_record,
        "layer_5_runtime": layer_5_runtime,
        "layer_5_runtime_mode2": new_m2,
        "layer_5_runtime_mode3": new_m3,
        "composite_risk": risk,
        "findings": scan_result["findings"],
    }
    (skill_out / "asg_report.json").write_text(
        json.dumps(asg_report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return asg_report


# ============================================================
# Multi-skill batch
# ============================================================
def scan_all_samples(
    samples_root: Path,
    output_dir: Path,
    enable_claude: bool = False,
    enable_honeypot: bool = False,
) -> dict[str, Any]:
    """Walk the samples/ directory and run analyze_skill() on each subfolder
    containing a SKILL.md."""
    samples_root = Path(samples_root).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    reports: list[dict[str, Any]] = []
    for entry in sorted(samples_root.iterdir()):
        if not entry.is_dir():
            continue
        skill_md = entry / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            report = analyze_skill(
                skill_path=entry,
                output_dir=output_dir,
                enable_claude=enable_claude,
                enable_honeypot=enable_honeypot,
                vm_evidence_dir=_find_existing_vm_evidence_dir(entry.name, output_dir),
            )
            reports.append(report)
        except Exception as exc:  # keep batch resilient
            reports.append(
                {
                    "skill_name": entry.name,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    summary = build_batch_summary(reports)
    (output_dir / "batch_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return summary


def build_batch_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    by_verdict: dict[str, int] = {}
    by_archetype: dict[str, int] = {}
    by_soph_level: dict[str, int] = {}
    total_findings = 0
    total_chains = 0
    rows: list[dict[str, Any]] = []
    chain_counts: dict[str, int] = {}

    for r in reports:
        if "error" in r:
            rows.append({"skill_name": r["skill_name"], "error": r["error"]})
            continue
        verdict = r["composite_risk"]["verdict"]
        archetype = r["layer_2_attack_chain"]["archetype"]["archetype"]
        soph_label = r["layer_2_attack_chain"]["sophistication"]["label"]
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        by_archetype[archetype] = by_archetype.get(archetype, 0) + 1
        by_soph_level[soph_label] = by_soph_level.get(soph_label, 0) + 1
        total_findings += r["layer_1_static_scan"]["total_findings"]
        total_chains += r["layer_2_attack_chain"]["chain_count"]
        for chain in r["layer_2_attack_chain"]["chains_triggered"]:
            chain_counts[chain["chain_id"]] = chain_counts.get(chain["chain_id"], 0) + 1
        rows.append(
            {
                "skill_name": r["skill_name"],
                "composite_score": r["composite_risk"]["composite_score"],
                "verdict": verdict,
                "archetype": archetype,
                "sophistication": soph_label,
                "static_findings": r["layer_1_static_scan"]["total_findings"],
                "chains_triggered": r["layer_2_attack_chain"]["chain_count"],
                "agent_tested": r["layer_3_agent_eval"]["tested"],
                "agent_refusal_score": r["layer_3_agent_eval"]["refusal_score"],
                "honeypot_leaked": r["layer_4_honeypot"]["any_honeypot_leaked"],
                "S_runtime": r["composite_risk"].get("sub_scores", {}).get("S_runtime", 0.0),
                "runtime_score_delta": r["composite_risk"].get("runtime_score_delta", 0.0),
            }
        )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_skills": len(reports),
        "total_static_findings": total_findings,
        "total_chains_triggered": total_chains,
        "by_verdict": by_verdict,
        "by_archetype": by_archetype,
        "by_sophistication_level": by_soph_level,
        "chain_trigger_counts": chain_counts,
        "rows": rows,
        "runtime_score_delta_total": round(
            sum(row.get("runtime_score_delta", 0.0) for row in rows if "error" not in row),
            2,
        ),
    }


# ============================================================
# Dashboard builder
# ============================================================
def build_dashboard_payload(
    batch_summary: dict[str, Any],
    existing_dashboard_path: Path | None = None,
) -> dict[str, Any]:
    """Merge ASG output into the existing Codex dashboard JSON, preserving
    teammate's fields."""
    base: dict[str, Any] = {}
    if existing_dashboard_path and existing_dashboard_path.exists():
        try:
            base = json.loads(existing_dashboard_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            base = {}

    base["asg_extension"] = {
        "version": "1.0.0",
        "generated_at_utc": batch_summary["generated_at_utc"],
        "module": "SkillVault ASG (AgentSkillGuard)",
        "paper_alignment": "arXiv:2602.06547v2 Table 3/Table 9/Table 11",
        "rule_count": 17,
        "rule_breakdown": {"paper_original": 14, "asg_extensions": 3},
        "extension_rules": ["P5 Authority Impersonation", "P6 Persistence", "P7 Cross-tool Coercion"],
        "composite_score_formula": (
            "R = 100 * (0.22*S_static + 0.18*S_chain + 0.10*S_soph "
            "+ 0.08*S_phases + 0.17*(1 - S_resilience) "
            "+ 0.10*S_honeypot + 0.15*S_runtime)"
        ),
        "total_skills_evaluated": batch_summary["total_skills"],
        "total_static_findings": batch_summary["total_static_findings"],
        "total_chains_triggered": batch_summary["total_chains_triggered"],
        "by_verdict": batch_summary["by_verdict"],
        "by_archetype": batch_summary["by_archetype"],
        "by_sophistication_level": batch_summary["by_sophistication_level"],
        "chain_trigger_counts": batch_summary["chain_trigger_counts"],
        "skill_rows": batch_summary["rows"],
    }
    return base


# ============================================================
# CLI
# ============================================================
def _cmd_scan(args: argparse.Namespace) -> int:
    out = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
    vm_dir = Path(args.vm_evidence_dir) if getattr(args, "vm_evidence_dir", None) else None
    report = analyze_skill(
        skill_path=Path(args.skill_path),
        output_dir=out,
        enable_claude=args.enable_claude,
        enable_honeypot=args.enable_honeypot,
        claude_model=args.claude_model,
        vm_evidence_dir=vm_dir,
    )

    # --- 可选: SSD (SkillSieve §4.3) 4 子任务 LLM 审计 ---
    ssd_ran = False
    if getattr(args, "enable_ssd", False):
        score = report["composite_risk"]["composite_score"]
        # 区间过滤
        gate_range = getattr(args, "ssd_when_score_between", None)
        in_range = True
        if gate_range:
            try:
                lo, hi = [float(x) for x in gate_range.split(",")]
                in_range = lo <= score <= hi
            except (ValueError, AttributeError):
                in_range = True
        if in_range:
            ssd_ran = _run_ssd_for_skill(
                report=report,
                skill_path=Path(args.skill_path),
                out=out,
                prefer=getattr(args, "ssd_llm", "fast"),
                mode=getattr(args, "ssd_mode", "single"),
                borderline_low=getattr(args, "ssd_borderline_low", 0.35),
                borderline_high=getattr(args, "ssd_borderline_high", 0.7),
            )
            # L1 review：让 LLM 复核每条静态命中是 TP/FP，防止误判
            if not getattr(args, "no_l1_review", False):
                _run_l1_review_for_skill(
                    report=report,
                    skill_path=Path(args.skill_path),
                    out=out,
                    prefer=getattr(args, "ssd_llm", "fast"),
                )
            # 可疑 + 有脚本 → 自动触发 Mode-3 沙箱动态执行
            if getattr(args, "auto_dynamic_on_suspicious", False):
                _maybe_auto_dynamic_run(
                    report=report,
                    skill_path=Path(args.skill_path),
                    out=out,
                )

    html_path = REPO_ROOT / "asg" / "dashboard.html"
    dashboard_builder.build_from_results(
        out, html_path, only_skill=report["skill_name"]
    )
    print(json.dumps(
        {
            "skill_name": report["skill_name"],
            "composite_score": report["composite_risk"]["composite_score"],
            "verdict": report["composite_risk"]["verdict"],
            "dashboard_html": str(html_path),
            "archetype": report["layer_2_attack_chain"]["archetype"]["archetype"],
            "sophistication": report["layer_2_attack_chain"]["sophistication"]["label"],
            "chains_triggered": report["layer_2_attack_chain"]["chain_count"],
            "agent_tested": report["layer_3_agent_eval"]["tested"],
            "agent_refusal_score": report["layer_3_agent_eval"]["refusal_score"],
            "honeypot_leaked": report["layer_4_honeypot"]["any_honeypot_leaked"],
            "S_runtime": report["composite_risk"].get("sub_scores", {}).get("S_runtime", 0.0),
            "runtime_score_delta": report["composite_risk"].get("runtime_score_delta", 0.0),
            "ssd_ran": ssd_ran,
            "ssd_R2": report.get("layer_2_ssd", {}).get("R2") if ssd_ran else None,
            "ssd_verdict": report.get("layer_2_ssd", {}).get("verdict") if ssd_ran else None,
            "report_path": str(out / report["skill_name"] / "asg_report.json"),
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 0


def _maybe_auto_dynamic_run(
    report: dict[str, Any],
    skill_path: Path,
    out: Path,
) -> bool:
    """可疑 + 有脚本 → 自动触发 Mode-3 Claude Docker 沙箱执行。
       触发条件（全部满足）：
         1. SSD verdict ∈ {SUSPICIOUS, MALICIOUS}
         2. skill 含可执行脚本（.py / .sh / .js）
         3. 还没跑过 Mode-3
    """
    # 条件 1: verdict
    cr = report.get("composite_risk") or {}
    verdict = cr.get("verdict", "SAFE")
    if verdict not in ("SUSPICIOUS", "MALICIOUS", "CRITICAL_MALICIOUS"):
        print("[auto-dynamic] skipped: verdict=SAFE")
        return False
    # 条件 2: 有脚本
    has_script = False
    for p in skill_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".py", ".sh", ".js", ".ts"):
            has_script = True
            break
    if not has_script:
        print("[auto-dynamic] skipped: no executable scripts")
        return False
    # 条件 3: 还没跑过 Mode-3
    if (report.get("layer_5_runtime") or {}).get("present"):
        print("[auto-dynamic] skipped: layer_5_runtime already present")
        return False
    # 触发 Mode-3
    print(f"[auto-dynamic] verdict={verdict} + has scripts → triggering Mode-3...")
    try:
        from asg import vm_ssh
        cfg_path = Path("asg/vm_config.json")
        if not cfg_path.exists():
            print(f"[auto-dynamic] skipped: {cfg_path} not found")
            return False
        cfg = vm_ssh.VMConfig.from_json(cfg_path)
        ssh_log_dir = out / report["skill_name"] / "vm_ssh_logs"
        ssh_log_dir.mkdir(parents=True, exist_ok=True)
        result = vm_ssh.trigger_remote_run(
            config=cfg,
            skill_path_local=skill_path,
            timeout_seconds=300,
            local_log_dir=ssh_log_dir,
            enable_honeypot=True,
        )
        status = result.get("status")
        print(f"[auto-dynamic] Mode-3 status={status}")
        if status in ("completed", "completed_no_logs"):
            # 重新 analyze_skill 把 layer_5 拉进 report
            re_report = analyze_skill(
                skill_path=skill_path,
                output_dir=out,
                enable_claude=False,
                enable_honeypot=True,
                vm_evidence_dir=ssh_log_dir,
            )
            report["layer_5_runtime"] = re_report.get("layer_5_runtime", {})
            report["composite_risk"] = re_report.get("composite_risk", {})
            # 写回
            (out / report["skill_name"] / "asg_report.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return True
    except Exception as exc:
        print(f"[auto-dynamic] failed: {type(exc).__name__}: {exc}")
    return False


def _run_l1_review_for_skill(
    report: dict[str, Any],
    skill_path: Path,
    out: Path,
    prefer: str = "fast",
) -> bool:
    """让 LLM 复核每条静态命中（TP/FP/UNCERTAIN），写回 findings[].llm_review，
    并把 FP 的 finding 在 risk_scorer 复算时降权。"""
    try:
        from asg.ssd_runner import review_l1_findings
    except ImportError:
        return False

    findings = report.get("findings") or []
    if not findings:
        return False

    # 收集 SKILL.md + 至多 8 个脚本（复用 SSD 的打包逻辑）
    skill_md_path = None
    for p in skill_path.rglob("*"):
        if p.is_file() and p.name.lower() == "skill.md":
            skill_md_path = p
            break
    if not skill_md_path:
        return False
    try:
        skill_md = skill_md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    extras: list[tuple[str, str]] = []
    for p in sorted(skill_path.rglob("*")):
        if not p.is_file() or p == skill_md_path:
            continue
        if p.suffix.lower() not in {".py", ".sh", ".js", ".ts", ".md",
                                     ".yaml", ".yml", ".json"}:
            continue
        try:
            extras.append((str(p.relative_to(skill_path)),
                            p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            pass
        if len(extras) >= 8:
            break

    review = review_l1_findings(skill_md, extras, findings, prefer=prefer)
    if not review.get("tested"):
        report["l1_review_meta"] = {
            "tested": False,
            "skipped_reason": review.get("skipped_reason"),
        }
        return False

    # 把每条 review 挂回对应的 finding（通过 file+line+rule_id 匹配）
    review_map = {
        (r["file"], r["line"], r["rule_id"]): r
        for r in review.get("reviews", [])
    }
    fp_count = 0
    for f in findings:
        key = (f.get("file"), f.get("line"), f.get("rule_id"))
        r = review_map.get(key)
        if r:
            f["llm_review"] = {
                "verdict": r["verdict"],
                "confidence": r["confidence"],
                "reason": r["reason"],
            }
            if r["verdict"] == "FP":
                fp_count += 1
                # 给 finding 加 ai_downgraded 标记 + 复用 risk_scorer 已支持的
                # downgraded 字段，让评分自动过滤
                f["ai_downgraded"] = True
                f["downgraded"] = True
                f["downgrade_reason"] = f"AI 复核标 FP: {r['reason'][:120]}"
                f["ai_downgrade_reason"] = r["reason"][:120]

    report["l1_review_meta"] = {
        "tested": True,
        "model": review.get("model"),
        "llm_provider": review.get("llm_provider"),
        "total_reviewed": review.get("total_reviewed", 0),
        "total_findings": review.get("total_findings", 0),
        "tp_count": review.get("tp_count", 0),
        "fp_count": review.get("fp_count", 0),
        "uncertain_count": review.get("uncertain_count", 0),
        "api_calls": review.get("api_calls", 0),
    }

    # AI 标 FP 后，重算 composite_score：如果有 FP 被识别且原 verdict 是
    # SUSPICIOUS/MALICIOUS 是因为静态触发，降级 composite_score。
    if fp_count > 0:
        from asg import attack_chain, risk_scorer
        scan_result = json.loads(
            (out / report["skill_name"] / "scan_result.json").read_text(encoding="utf-8")
        )
        # 把 ai_downgraded 标记同步到 scan_result.findings
        sr_finds = scan_result.get("findings", [])
        fp_keys = {
            (f.get("file"), f.get("line"), f.get("rule_id"))
            for f in findings if f.get("ai_downgraded")
        }
        for f in sr_finds:
            key = (f.get("file"), f.get("line"), f.get("rule_id"))
            if key in fp_keys:
                f["ai_downgraded"] = True
                f["downgraded"] = True
                f["downgrade_reason"] = "AI 复核标 FP"
        # 关键修复：scan_result.by_severity / by_pattern 是基于全部 finding 算的，
        # downgrade 字段不会自动影响它们 → 必须基于 not downgraded 重算
        live_finds = [f for f in sr_finds if not f.get("downgraded")]
        from collections import Counter
        scan_result["by_severity"] = dict(Counter(
            (f.get("severity") or "INFO") for f in live_finds
        ))
        # 保证所有等级都有键
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            scan_result["by_severity"].setdefault(sev, 0)
        scan_result["by_pattern"] = dict(Counter(
            (f.get("rule_id") or "UNKNOWN") for f in live_finds
        ))
        scan_result["total_findings"] = len(live_finds)
        # 重算 chain（attack_chain 也应该忽略 downgraded）
        scan_result_for_chain = dict(scan_result)
        scan_result_for_chain["findings"] = live_finds
        chain_result = attack_chain.analyze(scan_result_for_chain)
        risk = risk_scorer.compute_risk(
            scan_result=scan_result,
            chain_result=chain_result,
            agent_eval=report.get("layer_3_agent_eval") if report.get("layer_3_agent_eval", {}).get("tested") else None,
            honeypot_result=report.get("layer_4_honeypot") if report.get("layer_4_honeypot", {}).get("enabled") else None,
            layer_5_runtime=report.get("layer_5_runtime"),
        )
        # 保留 SSD 的升级（不被 L1 review 抹掉）
        cr_old = report["composite_risk"]
        ssd_pre = cr_old.get("composite_score_pre_ssd")
        if ssd_pre is not None:
            # SSD 已经升级过，AI review 降的是静态层。这里取 max(新静态分, SSD 升级后)
            # 因为 SSD 升级是基于 LLM 判定，不应被 L1 review 抹掉
            risk["composite_score"] = max(risk["composite_score"],
                                           cr_old.get("composite_score", 0))
        else:
            cr_old.setdefault("score_notes", []).append(
                f"L1 review: {fp_count} 条命中被 AI 标为 FP，"
                f"composite_score {cr_old.get('composite_score')} → {risk['composite_score']}"
            )
            # 保留 score_notes
            risk["score_notes"] = cr_old.get("score_notes", [])
            report["composite_risk"] = risk
        report["layer_1_static_scan"]["ai_downgraded_count"] = fp_count

    # 写回
    report_path = out / report["skill_name"] / "asg_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return True


def _run_ssd_for_skill(
    report: dict[str, Any],
    skill_path: Path,
    out: Path,
    prefer: str = "fast",
    mode: str = "single",
    borderline_low: float = 0.35,
    borderline_high: float = 0.7,
) -> bool:
    """跑 SSD 4 子任务 + 把结果合并进 asg_report.json 并升级 verdict。
       mode="single": 用 prefer 指定的单家 LLM
       mode="triage": DeepSeek 全量 + borderline 区间升级到 Claude
    返回 True 表示成功跑了 SSD。"""
    try:
        from asg.ssd_runner import run_ssd, run_ssd_triage
    except ImportError:
        return False

    # 收集 SKILL.md + extra files (max 8)
    skill_md_path = None
    for p in skill_path.rglob("*"):
        if p.is_file() and p.name.lower() == "skill.md":
            skill_md_path = p
            break
    if not skill_md_path:
        return False
    try:
        skill_md = skill_md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    extras: list[tuple[str, str]] = []
    for p in sorted(skill_path.rglob("*")):
        if not p.is_file() or p == skill_md_path:
            continue
        if p.suffix.lower() not in {".py", ".sh", ".js", ".ts", ".md",
                                     ".yaml", ".yml", ".json"}:
            continue
        try:
            extras.append((str(p.relative_to(skill_path)),
                            p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            pass
        if len(extras) >= 8:
            break

    l1_findings = report.get("findings", [])
    if mode == "triage":
        ssd = run_ssd_triage(
            skill_md, extras, l1_findings,
            borderline_low=borderline_low,
            borderline_high=borderline_high,
        )
    else:
        ssd = run_ssd(skill_md, extras, l1_findings, prefer=prefer)
    if not ssd.get("tested"):
        return False

    # 合并 SSD 结果到 report
    report["layer_2_ssd"] = ssd

    # 升降 verdict（双向）：
    #   - R2 ≥ 0.7 → MALICIOUS，R2 ≥ 0.4 → SUSPICIOUS（升级，无条件）
    #   - R2 < 0.2 且静态 composite_score < 25 → 允许从 SUSPICIOUS 降到 SAFE
    #     （避免对真实证据强的样本误降；R2 阈值保守）
    cr = report["composite_risk"]
    verdict_order = ["SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL_MALICIOUS"]
    cur_idx = verdict_order.index(cr["verdict"]) if cr["verdict"] in verdict_order else 0
    ssd_verdict = ssd["verdict"]
    ssd_idx = verdict_order.index(ssd_verdict) if ssd_verdict in verdict_order else 0
    r2 = ssd.get("R2", 0)
    cur_score = cr.get("composite_score", 0)

    # === 新：任一子任务 MALICIOUS（risk ≥ 0.7）强制升级 ===
    # 即使整体 R2 加权后仍 SAFE，单维度强信号也应升级 verdict
    subtask_risks = [t.get("risk_score", 0.0)
                     for t in (ssd.get("subtasks") or {}).values()
                     if isinstance(t.get("risk_score"), (int, float))]
    max_subtask_risk = max(subtask_risks, default=0.0)
    if max_subtask_risk >= 0.7 and ssd_idx < 2:  # 升 verdict 时 ssd_idx 还是 SAFE/SUSP
        # 强升至 SUSPICIOUS（保守，不直接到 MALICIOUS），分数贡献 max_subtask * 30
        forced_contrib = round(max_subtask_risk * 30, 2)
        forced_score = max(round(cur_score + forced_contrib, 2), 20.0)
        cr["composite_score_pre_subtask_boost"] = cur_score
        cr["composite_score"] = min(forced_score, 100.0)
        cr["verdict"] = "SUSPICIOUS" if max_subtask_risk < 0.85 else "MALICIOUS"
        cr.setdefault("score_notes", []).append(
            f"子任务强信号: max_subtask_risk={max_subtask_risk} ≥ 0.7 → "
            f"强升 {cur_score} → {cr['composite_score']} (+{forced_contrib} from subtask × 30)"
        )
        cur_score = cr["composite_score"]
        cur_idx = verdict_order.index(cr["verdict"])

    if ssd_idx > cur_idx:
        # SSD 升级时把 R2 加进 composite_score：贡献最多 25 分
        # （对应 risk_scorer 里 w_llm_verdict=0.25 的权重）。
        ssd_contrib = round(r2 * 25, 2)
        new_score = max(round(cur_score + ssd_contrib, 2), cur_score)
        cr["composite_score_pre_ssd"] = cur_score
        cr["composite_score"] = min(new_score, 100.0)
        cr["verdict"] = ssd_verdict
        # triage 模式 + escalated 时标注两家是否分歧
        provider_tag = ssd["llm_provider"]
        if ssd.get("mode") == "triage":
            provider_tag = (
                f"triage(DS+Claude{'，分歧' if ssd.get('disagreement') else '，一致'})"
                if ssd.get("escalated") else "triage(仅DS)"
            )
        cr.setdefault("score_notes", []).append(
            f"SSD upgrade: R2={r2} ({provider_tag}) → "
            f"{ssd_verdict}, score {cur_score} → {cr['composite_score']} "
            f"(+{ssd_contrib} from R2×25)"
        )
    elif (cr["verdict"] == "SUSPICIOUS" and r2 < 0.2 and cur_score < 25
          and ssd["llm_provider"] != "env"):
        # SSD 降级：LLM 看了 SKILL.md+scripts 全文判 SAFE 且静态分数中等以下，
        # 把 SUSPICIOUS（多半由 verdict floor 触发）降到 SAFE。同时
        # composite_score × 0.3 让分数也反映 LLM 判定，不只是 verdict 跳变。
        # 仅对 borderline 样本生效（cur_score < 25），高分数样本即使 SSD SAFE
        # 也保留警示。
        new_score = round(cur_score * 0.3, 2)
        cr["verdict"] = "SAFE"
        cr["composite_score_pre_ssd"] = cur_score
        cr["composite_score"] = new_score
        cr.setdefault("score_notes", []).append(
            f"SSD downgrade: R2={r2} ({ssd['llm_provider']}) — "
            f"LLM 全文审计判 SAFE → score {cur_score} → {new_score} (×0.3)"
        )

    # 写回 report
    report_path = out / report["skill_name"] / "asg_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return True


def _cmd_scan_all(args: argparse.Namespace) -> int:
    out = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
    samples_root = Path(args.samples_root or REPO_ROOT / "asg" / "samples")
    summary = scan_all_samples(
        samples_root=samples_root,
        output_dir=out,
        enable_claude=args.enable_claude,
        enable_honeypot=args.enable_honeypot,
    )
    print(json.dumps(
        {k: v for k, v in summary.items() if k != "rows"},
        indent=2,
        ensure_ascii=False,
    ))
    print(f"\nBatch summary: {out / 'batch_summary.json'}")
    print(f"Per-skill reports: {out}/<skill_name>/asg_report.json")
    return 0


def _cmd_ingest_vm(args: argparse.Namespace) -> int:
    out = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
    skill = Path(args.skill_path)
    evidence = Path(args.evidence_dir)
    if not evidence.exists():
        print(f"error: evidence dir does not exist: {evidence}", file=sys.stderr)
        return 1
    report = analyze_skill(
        skill_path=skill,
        output_dir=out,
        enable_claude=False,
        enable_honeypot=args.enable_honeypot,
        vm_evidence_dir=evidence,
    )
    print(json.dumps(
        {
            "skill_name": report["skill_name"],
            "composite_score": report["composite_risk"]["composite_score"],
            "verdict": report["composite_risk"]["verdict"],
            "agent_tested_from_vm": report["layer_3_agent_eval"].get("tested"),
            "refusal_score": report["layer_3_agent_eval"].get("refusal_score"),
            "disclosure_score": report["layer_3_agent_eval"].get("disclosure_score"),
            "S_runtime": report["composite_risk"].get("sub_scores", {}).get("S_runtime", 0.0),
            "runtime_score_delta": report["composite_risk"].get("runtime_score_delta", 0.0),
            "evidence_dir": str(evidence),
            "report_path": str(out / report["skill_name"] / "asg_report.json"),
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 0


def _cmd_vm_ssh_run(args: argparse.Namespace) -> int:
    from asg import vm_ssh

    cfg_path = Path(args.vm_config)
    if not cfg_path.exists():
        print(
            f"error: VM config not found at {cfg_path}.\n"
            "Create asg/vm_config.json with host/username/password/etc.",
            file=sys.stderr,
        )
        return 1
    try:
        cfg = vm_ssh.VMConfig.from_json(cfg_path)
    except (KeyError, json.JSONDecodeError) as exc:
        print(f"error: bad VM config: {exc}", file=sys.stderr)
        return 1

    skill = Path(args.skill_path).resolve()
    if not skill.is_dir():
        print(f"error: skill path not a directory: {skill}", file=sys.stderr)
        return 1

    out = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
    ssh_log_dir = out / skill.name / "vm_ssh_logs"
    ssh_log_dir.mkdir(parents=True, exist_ok=True)

    print(f"[vm-ssh] Connecting to {cfg.host}:{cfg.port} as {cfg.username}...")
    ssh_result = vm_ssh.trigger_remote_run(
        config=cfg,
        skill_path_local=skill,
        timeout_seconds=args.timeout_seconds,
        local_log_dir=ssh_log_dir,
        enable_honeypot=args.enable_honeypot,
        no_honeypot_materialize=args.no_honeypot_materialize,
    )
    print(f"[vm-ssh] status={ssh_result.get('status')}")
    if ssh_result.get("status") not in ("completed", "completed_no_logs"):
        print(json.dumps(ssh_result, indent=2, ensure_ascii=False))
        return 2

    print(f"[vm-ssh] Ingesting evidence from {ssh_log_dir}...")
    report = analyze_skill(
        skill_path=skill,
        output_dir=out,
        enable_claude=False,
        enable_honeypot=args.enable_honeypot,
        vm_evidence_dir=ssh_log_dir,
    )
    print(json.dumps(
        {
            "skill_name": report["skill_name"],
            "composite_score": report["composite_risk"]["composite_score"],
            "verdict": report["composite_risk"]["verdict"],
            "agent_tested": report["layer_3_agent_eval"].get("tested"),
            "refusal_score": report["layer_3_agent_eval"].get("refusal_score"),
            "S_runtime": report["composite_risk"].get("sub_scores", {}).get("S_runtime", 0.0),
            "runtime_score_delta": report["composite_risk"].get("runtime_score_delta", 0.0),
            "ssh_log_dir": str(ssh_log_dir),
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 0


def _cmd_vm_paper_run(args: argparse.Namespace) -> int:
    """Paper-style direct Docker execution — no agent, no API key needed."""
    from asg import vm_ssh

    cfg_path = Path(args.vm_config)
    if not cfg_path.exists():
        print(f"error: VM config not found at {cfg_path}.", file=sys.stderr)
        return 1
    cfg = vm_ssh.VMConfig.from_json(cfg_path)

    skill = Path(args.skill_path).resolve()
    if not skill.is_dir():
        print(f"error: skill path not a directory: {skill}", file=sys.stderr)
        return 1

    out = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
    paper_log_dir = out / skill.name / "vm_paper_logs"
    paper_log_dir.mkdir(parents=True, exist_ok=True)

    print(f"[vm-paper] Connecting to {cfg.host}:{cfg.port} as {cfg.username}...")
    result = vm_ssh.trigger_paper_mode_run(
        config=cfg,
        skill_path_local=skill,
        timeout_seconds=args.timeout_seconds,
        local_log_dir=paper_log_dir,
        enable_honeypot=args.enable_honeypot,
        no_honeypot_materialize=args.no_honeypot_materialize,
    )
    print(f"[vm-paper] status={result.get('status')}")
    if result.get("status") not in ("completed", "completed_no_logs"):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2

    print(f"[vm-paper] Ingesting evidence from {paper_log_dir}...")
    report = analyze_skill(
        skill_path=skill,
        output_dir=out,
        enable_claude=False,
        enable_honeypot=args.enable_honeypot,
        vm_evidence_dir=paper_log_dir,
    )
    print(json.dumps(
        {
            "skill_name": report["skill_name"],
            "composite_score": report["composite_risk"]["composite_score"],
            "verdict": report["composite_risk"]["verdict"],
            "mode": "paper_no_claude",
            "scripts_executed": result.get("pulled_any_logs"),
            "S_runtime": report["composite_risk"].get("sub_scores", {}).get("S_runtime", 0.0),
            "runtime_score_delta": report["composite_risk"].get("runtime_score_delta", 0.0),
            "paper_log_dir": str(paper_log_dir),
            "outbound_ips": report["layer_3_agent_eval"]
                .get("ingested_from_vm_evidence", False),
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 0


def _cmd_build_html(args: argparse.Namespace) -> int:
    results_dir = Path(args.results_dir or DEFAULT_OUTPUT_DIR)
    output = Path(args.output or REPO_ROOT / "asg" / "dashboard.html")
    out_path = dashboard_builder.build_from_results(
        results_dir, output, only_skill=args.skill
    )
    print(f"Wrote: {out_path.resolve()}")
    return 0


def _cmd_build_dashboard(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir or DEFAULT_OUTPUT_DIR)
    batch_path = out_dir / "batch_summary.json"
    if not batch_path.exists():
        print(f"error: {batch_path} not found. Run 'scan-all-samples' first.",
              file=sys.stderr)
        return 2
    batch_summary = json.loads(batch_path.read_text(encoding="utf-8"))

    dashboard_path = Path(args.dashboard_path or REPO_ROOT / "dashboard" / "dashboard_data.json")
    merged = build_dashboard_payload(batch_summary, existing_dashboard_path=dashboard_path)

    # Write to a separate asg_dashboard_data.json by default so teammate's
    # file stays untouched, unless --in-place is passed.
    target = dashboard_path if args.in_place else (
        REPO_ROOT / "dashboard" / "asg_dashboard_data.json"
    )
    target.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Wrote merged dashboard data: {target}")
    return 0


def _cmd_scan_graph(args: argparse.Namespace) -> int:
    sandbox_dir = Path(args.sandbox_dir).resolve()
    if not sandbox_dir.exists():
        print(f"[scan-graph] sandbox dir not found: {sandbox_dir}", file=sys.stderr)
        return 2

    report = skill_graph.analyze_sandbox(
        sandbox_dir,
        enable_llm=not args.no_llm,
        max_llm_calls=args.max_llm_calls,
    )

    if args.verify_hit:
        hit = skill_graph.verify_capflow_hit(sandbox_dir)
        report["path_level_hit"] = hit
        # If the path is truly hit, that's the only way to reach MALICIOUS.
        if hit["hit"]:
            report["verdict"] = "MALICIOUS"
            report["verdict_reason"] = (
                f"verified capability_flow HIT: intersect_sensitive="
                f"{hit['intersect_sensitive']}"
            )
            report["scr_floor_triggered"] = True

    out = Path(args.output) if args.output else (sandbox_dir / "skill_graph.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    stats = report.get("stats", {})
    verdict = report.get("verdict", "?")
    n_edges = stats.get("n_edges", 0)
    by_type = stats.get("by_type", {})
    llm_calls = stats.get("llm_calls", 0)

    print(f"[scan-graph] {sandbox_dir.name}: verdict={verdict} "
          f"edges={n_edges} by_type={by_type} llm_calls={llm_calls}")
    if report.get("verdict_reason"):
        print(f"[scan-graph] reason: {report['verdict_reason']}")
    hit = report.get("path_level_hit")
    if hit is not None:
        marker = "HIT" if hit["hit"] else "miss"
        print(f"[scan-graph] path-level: {marker} — {hit['reason']}")
    print(f"[scan-graph] report: {out}")
    return 0


def _cmd_release_check(args: argparse.Namespace) -> int:
    scripts_dir = REPO_ROOT / "code" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from release_safety_check import print_summary, run_release_safety_check

    output_dir = Path(args.output_dir or REPO_ROOT / "analysis_results" / "release_safety_check")
    report = run_release_safety_check(repo_root=REPO_ROOT, output_dir=output_dir, write_reports=True)
    print_summary(report, output_dir)
    return 0 if report["passed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asg", description="SkillVault ASG CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan one skill directory")
    p_scan.add_argument("skill_path")
    p_scan.add_argument("--output-dir", default=None)
    p_scan.add_argument("--enable-claude", action="store_true")
    p_scan.add_argument("--enable-honeypot", action="store_true")
    p_scan.add_argument("--claude-model", default="claude-opus-4-7")
    p_scan.add_argument(
        "--vm-evidence-dir",
        default=None,
        help="Path to a directory with claude_output.txt + strace.log from VM Docker run",
    )
    # SSD (SkillSieve §4.3) 4 子任务 LLM 审计
    p_scan.add_argument(
        "--enable-ssd", action="store_true",
        help="Run Structured Semantic Decomposition (SkillSieve arXiv:2604.06550 §4.3): "
             "4 parallel LLM sub-tasks (Intent/Permission/Covert/Cross-file). "
             "Default: DeepSeek V4-Pro (~$0.02 per skill with caching)",
    )
    p_scan.add_argument(
        "--ssd-llm", default="fast", choices=("fast", "smart"),
        help="(single mode) fast=DeepSeek V4-Pro (~0.02元/skill), "
             "smart=Claude Sonnet 4.6 (~$0.06/skill)",
    )
    p_scan.add_argument(
        "--ssd-mode", default="single", choices=("single", "triage"),
        help="single = 用 --ssd-llm 指定的单家 LLM 跑 SSD；"
             "triage = DeepSeek 全量 + borderline (R2∈[low,high]) 升级到 Claude 复审。"
             "triage 模式只对 ~5-10%% borderline 样本调 Claude，控成本。",
    )
    p_scan.add_argument(
        "--ssd-borderline-low", type=float, default=0.35,
        help="triage 模式 borderline 区间下界 (R2)。低于此值 = DeepSeek 单家定 SAFE。",
    )
    p_scan.add_argument(
        "--ssd-borderline-high", type=float, default=0.7,
        help="triage 模式 borderline 区间上界 (R2)。高于此值 = DeepSeek 单家定 MALICIOUS。",
    )
    p_scan.add_argument(
        "--ssd-when-score-between", default=None,
        metavar="LOW,HIGH",
        help="Only run SSD when static composite_score falls in [LOW, HIGH] range. "
             "E.g. '10,30' to only audit borderline samples. Default: always.",
    )
    p_scan.add_argument(
        "--no-l1-review", action="store_true",
        help="禁用 L1 review（默认 --enable-ssd 时联动启用 LLM 逐条复核静态命中）。"
             "L1 review 让 LLM 标 TP/FP/UNCERTAIN，FP 的不计入 composite_score。",
    )
    p_scan.add_argument(
        "--auto-dynamic-on-suspicious", action="store_true",
        help="可疑 + 有脚本 → 自动触发 Mode-3 Claude Docker 沙箱动态执行。"
             "触发条件：SSD verdict ∈ {SUSPICIOUS, MALICIOUS} 且 skill 含 .py/.sh/.js。",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_all = sub.add_parser("scan-all-samples", help="Scan every sample in asg/samples/")
    p_all.add_argument("--samples-root", default=None)
    p_all.add_argument("--output-dir", default=None)
    p_all.add_argument("--enable-claude", action="store_true")
    p_all.add_argument("--enable-honeypot", action="store_true")
    p_all.set_defaults(func=_cmd_scan_all)

    p_dash = sub.add_parser("build-dashboard", help="Merge ASG output into dashboard JSON")
    p_dash.add_argument("--output-dir", default=None,
                        help="Directory containing batch_summary.json")
    p_dash.add_argument("--dashboard-path", default=None,
                        help="Existing dashboard_data.json to extend")
    p_dash.add_argument("--in-place", action="store_true",
                        help="Overwrite teammate's dashboard_data.json directly")
    p_dash.set_defaults(func=_cmd_build_dashboard)

    p_html = sub.add_parser("build-html", help="Build standalone ASG HTML dashboard")
    p_html.add_argument("--results-dir", default=None,
                        help="Directory containing per-skill asg_report.json files")
    p_html.add_argument("--output", default=None,
                        help="Output HTML path (default: asg/dashboard.html)")
    p_html.add_argument("--skill", default=None,
                        help="Only render this skill (by directory name); "
                             "default renders the full aggregated history")
    p_html.set_defaults(func=_cmd_build_html)

    p_ingest = sub.add_parser(
        "ingest-vm-evidence",
        help="Ingest claude_output.txt + strace.log + tcpdump.pcap from a VM Docker run",
    )
    p_ingest.add_argument("skill_path", help="Original skill directory (for static scan)")
    p_ingest.add_argument(
        "evidence_dir",
        help="VM-side directory containing claude_output.txt etc",
    )
    p_ingest.add_argument("--output-dir", default=None)
    p_ingest.add_argument("--enable-honeypot", action="store_true")
    p_ingest.set_defaults(func=_cmd_ingest_vm)

    p_ssh = sub.add_parser(
        "vm-ssh-run",
        help="SSH to remote VM, trigger run_skill.sh, pull logs back, then ingest",
    )
    p_ssh.add_argument("skill_path", help="Local skill directory to upload + run")
    p_ssh.add_argument(
        "--vm-config",
        default="asg/vm_config.json",
        help="Path to VM SSH config JSON (host, user, password, etc.)",
    )
    p_ssh.add_argument("--output-dir", default=None)
    p_ssh.add_argument("--enable-honeypot", action="store_true")
    p_ssh.add_argument("--no-honeypot-materialize", action="store_true")
    p_ssh.add_argument("--timeout-seconds", type=int, default=300)
    p_ssh.set_defaults(func=_cmd_vm_ssh_run)

    p_paper = sub.add_parser(
        "vm-paper-run",
        help="SSH to VM, run skill scripts DIRECTLY in Docker (NO Claude / NO API).",
    )
    p_paper.add_argument("skill_path", help="Local skill directory to upload + run")
    p_paper.add_argument("--vm-config", default="asg/vm_config.json")
    p_paper.add_argument("--output-dir", default=None)
    p_paper.add_argument("--enable-honeypot", action="store_true")
    p_paper.add_argument("--no-honeypot-materialize", action="store_true")
    p_paper.add_argument("--timeout-seconds", type=int, default=60)
    p_paper.set_defaults(func=_cmd_vm_paper_run)

    p_graph = sub.add_parser(
        "scan-graph",
        help="SCR composition analyzer: scan a sandbox dir with multiple SKILL.md "
             "and report capability_flow / trust_transfer / auth_blur edges.",
    )
    p_graph.add_argument(
        "sandbox_dir",
        help="Directory containing 2+ SKILL.md files "
             "(e.g. SCR-Bench/SCR-AuthBlur/cases/case1)",
    )
    p_graph.add_argument(
        "--output", default=None,
        help="Where to write JSON report. Default: <sandbox_dir>/skill_graph.json",
    )
    p_graph.add_argument(
        "--no-llm", action="store_true",
        help="Heuristic only — skip DS escalation for borderline edges (free, faster).",
    )
    p_graph.add_argument(
        "--max-llm-calls", type=int, default=skill_graph.MAX_LLM_CALLS_PER_GRAPH,
        help=f"DS escalation budget. Default: {skill_graph.MAX_LLM_CALLS_PER_GRAPH}.",
    )
    p_graph.add_argument(
        "--verify-hit", action="store_true",
        help="Also run path-level ground-truth check on this sandbox "
             "(paper §3.4: discover ∧ act ∧ same target). Requires a "
             "POST-EXECUTION sandbox dir — i.e. discovery.json + side effect "
             "files must already exist from a Mode-3 / paper-mode run.",
    )
    p_graph.set_defaults(func=_cmd_scan_graph)

    p_release = sub.add_parser(
        "release-check",
        help="Run level_3 GitHub release safety checks",
    )
    p_release.add_argument("--output-dir", default=None)
    p_release.set_defaults(func=_cmd_release_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
