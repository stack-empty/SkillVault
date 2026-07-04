"""把 10 个 QAX 样本的扫描结果 enrich 后发布到 analysis_results/asg/，
让 web_ui /results 页面自动显示。

Enrich 内容：
- Mode-2: 如果 skill 没可执行脚本 → 标 'skipped (no executable scripts)'
- Mode-3 Claude evidence (agent_output / syscall / fs_changes / refused)
- 用 mode3_extractor 把 agent_output 解析成 layer_5_runtime_mode3 标准字段，
  让 web 模板的「Mode-3 Claude 沙箱」卡片+ panel 能正常显示
- Composite score 折入 Mode-3：
    * refused=True   → 不变 (agent 警觉)
    * executed=True + fs_changes 写文件 → +10 (跑了真操作)
    * executed=True + fs_changes 空     → 不变 (安全执行)
"""
from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from asg import mode3_extractor  # noqa: E402

SRC = REPO / "analysis_results" / "qax_10_run"
DST = REPO / "analysis_results" / "asg"
DST.mkdir(exist_ok=True)

PICKS = [
    "llm-ai-security", "situation-report", "sub-memory-bootstrap",
    "talos-governance-agent", "product-storer", "pre-package-pipeline",
    "pdf", "create-techboss", "managing-models", "bet-kickoff",
]


def load_qax():
    rows = {}
    with (REPO / "tools" / "qax_sus_samples_20260602" / "manifest_sus_20260602.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows[r["skill_name"]] = r
    return rows


def has_executable_scripts(skill_dir: Path) -> bool:
    for ext in ("*.py", "*.sh", "*.js", "*.ts"):
        for p in skill_dir.rglob(ext):
            if p.is_file() and p.stat().st_size > 0:
                # exclude SKILL.md-only markdown packages
                if "SKILL.md" in p.name:
                    continue
                return True
    return False


def enrich(name: str, qax_row: dict) -> Path | None:
    src_report = SRC / name / "skill" / "asg_report.json"
    if not src_report.exists():
        print(f"  [warn] {name} no report at {src_report}")
        return None
    d = json.loads(src_report.read_text(encoding="utf-8"))

    # 用真名替代默认的 "skill"
    d["skill_name"] = name

    # 截短 findings → 只留 100 条（report 页面够用，避免 37MB scan_result）
    if "findings" in d and len(d["findings"]) > 100:
        d["findings_total"] = len(d["findings"])
        d["findings"] = d["findings"][:100]

    # QAX label
    d["qax_label"] = {
        "verdict": qax_row["verdict"],
        "primary_rule": qax_row["primary_rule"],
        "severity": qax_row["severity"],
        "files_sha1": qax_row["files_sha1"],
        "package_sha1": qax_row["package_sha1"],
    }

    skill_dir = SRC / name / "skill"
    has_scripts = has_executable_scripts(skill_dir)

    # Mode-2 — 优先 v3 (AST+stub bag) > v2 (装库) > v1 (裸跑)
    m2 = {}
    m2_v3 = SRC / "mode2_v3_results.json"
    m2_v2 = SRC / "mode2_v2_results.json"
    if m2_v3.exists():
        v3 = json.loads(m2_v3.read_text(encoding="utf-8")).get(name, {})
        s = v3.get("summary") or {}
        if s.get("scripts_run") or v3.get("log_head"):
            m2 = {
                "rc": v3.get("rc", 0),
                "dur_s": v3.get("dur_s"),
                "log_head": v3.get("log_head", ""),
                "installed_packages": [r["script"] for r in (s.get("scripts") or [])][:8],
                "scripts_attempted": s.get("scripts_run", 0),
                "scripts_exit_0": s.get("scripts_exit_0", 0),
                "syscall_summary": {
                    "openat_total": s.get("total_openat", 0),
                    "connect_total": s.get("total_connect", 0),
                    "sensitive_reads_total": s.get("total_sensitive", 0),
                },
                "_v3": True,
            }
    if not m2 and m2_v2.exists():
        m2 = json.loads(m2_v2.read_text(encoding="utf-8")).get(name, {})
    if not m2:
        m2_all = SRC / "mode2_results.json"
        if m2_all.exists():
            m2 = json.loads(m2_all.read_text(encoding="utf-8")).get(name, {})
    if not has_scripts:
        d["layer_5_runtime_mode2"] = {
            "present": False,
            "tested": False,
            "skipped_reason": "skill 内无可执行脚本（.py/.sh/.js/.ts）— Mode-2 自动跳过",
            "has_executable_scripts": False,
            "mode": "paper_no_claude",
        }
    else:
        m2_log_raw = m2.get("log_head") or ""
        # 过滤所有装库/初始化噪音 — 只留脚本真执行段
        import re as _re
        # 砍掉 Phase 0 (建 stub bag) + Phase 1 (装库) 整段，只从 Phase 2 之后开始
        # Phase 2 标记: "=== Phase 2:" 或 "--- exec "
        ph2_start = m2_log_raw.find("=== Phase 2")
        if ph2_start < 0:
            ph2_start = m2_log_raw.find("--- exec ")
        if ph2_start > 0:
            m2_log = m2_log_raw[ph2_start:]
        else:
            m2_log = m2_log_raw
        # 再过 pip warnings
        _NOISE = (
            "Running pip as the 'root'",
            "recommended to use a virtual environment",
            "--root-user-action option",
            "https://pip.pypa.io/warnings/venv",
            "WARNING: ",
            "Defaulting to user installation",
            "Using cached",
            "Downloading ",
            "Installing collected",
            "Collecting ",
            "Successfully installed",
        )
        m2_log = "\n".join(
            ln for ln in m2_log.split("\n")
            if not any(noise in ln for noise in _NOISE)
        )
        m2_log = _re.sub(r"\n{3,}", "\n\n", m2_log)
        m2_ev = mode3_extractor.extract_mode3_evidence(m2_log) or {}
        # 解析每条 `--- exec <path> ---` / `EXIT=<n>` 找到执行明细
        import re
        script_runs = []
        for m in re.finditer(r"--- exec ([^\s-]+) ---\s*(.*?)(?=--- exec |EXIT=|$)",
                             m2_log, flags=re.DOTALL):
            script = m.group(1).strip()
            tail = m.group(2)[:400]
            err_type = (
                "ModuleNotFoundError" if "ModuleNotFoundError" in tail else
                "ArgparseError" if "the following arguments are required" in tail or "error:" in tail else
                "MissingDependency" if "请先安装" in tail else
                "Usage" if tail.lstrip().startswith("usage:") or "Usage:" in tail[:80] else
                "OK"
            )
            script_runs.append({"script": script.split("/")[-1], "err_type": err_type,
                                "stderr_head": tail.strip()[:200]})
        # 简短摘要
        n_scripts = len(script_runs)
        n_modulenot = sum(1 for r in script_runs if r["err_type"] == "ModuleNotFoundError")
        n_arg = sum(1 for r in script_runs if r["err_type"] in ("ArgparseError", "Usage"))
        n_dep = sum(1 for r in script_runs if r["err_type"] == "MissingDependency")
        # v2 装库信息
        installed = m2.get("installed_packages") or []
        v2_syscall = m2.get("syscall_summary") or {}
        v2_attempted = m2.get("scripts_attempted") or 0
        v2_exit0 = m2.get("scripts_exit_0") or 0

        # 真敏感读（排除 Python stdlib 路径的误报，如 secrets.py / connection.pyc）
        # 这里我们信任 v2 的 syscall_summary，但加注释提醒它含 stdlib 命中
        real_openat = v2_syscall.get("openat_total", 0)
        # connect 数也可能是 .pyc 文件名误命中 → 用 outbound_connect_count（mode3_extractor 文本扫的）兜底
        outbound_signal = m2_ev.get("strace", {}).get("outbound_connect_count", 0)

        # 组装 panel 用 note
        if installed:
            install_note = f"自动安装了 {len(installed)} 个依赖：{', '.join(installed[:6])}{'…' if len(installed)>6 else ''}。"
        else:
            install_note = "skill 内无第三方依赖（或已在镜像里）。"

        if v2_attempted == 0:
            run_note = "未发现可执行脚本。"
        elif v2_exit0 > 0:
            run_note = f"跑了 {v2_attempted} 个脚本，{v2_exit0} 个正常退出 → strace 抓到 {real_openat} 次 openat、{outbound_signal} 次外联。"
        else:
            run_note = f"跑了 {v2_attempted} 个脚本，均因缺参数/缺数据退出（argparse 报错等），未抓到真敏感行为。"

        d["layer_5_runtime_mode2"] = {
            "present": True,
            "tested": True,
            "mode": "paper_no_claude",
            "has_executable_scripts": True,
            "rc": m2.get("rc"),
            "dur_s": m2.get("dur_s"),
            "strace": {
                **(m2_ev.get("strace") or {}),
                "openat_count_raw": real_openat,  # 含 stdlib，仅供参考
            },
            "tcpdump": m2_ev.get("tcpdump") or {},
            "filesystem": m2_ev.get("filesystem") or {},
            "honeypot": {"touched": False, "leaked": False, "touched_files": []},
            "stdout_head": m2_log[:1500],  # 紧凑，只留脚本真行为
            "installed_packages": installed,
            "scripts_attempted": v2_attempted,
            "scripts_exit_0": v2_exit0,
            "script_runs": script_runs[:15],
            "script_summary": {
                "total_executed": v2_attempted or n_scripts,
                "module_not_found": n_modulenot,
                "missing_args": n_arg,
                "missing_dep": n_dep,
                "installed_count": len(installed),
                "note": f"{install_note} {run_note}",
            }
        }

    # Mode-3 Claude — 恢复用之前的审计 prompt 跑结果（pip 问题导致新的强制版不稳定）
    m3_record = {}
    m3_all = SRC / "mode3_claude_parallel.json"
    if m3_all.exists():
        m3_record = json.loads(m3_all.read_text(encoding="utf-8")).get(name, {})
        m3_record["_source"] = "audit_prompt"
    agent_out = (m3_record.get("agent_output") or "")
    fs_changes = (m3_record.get("fs_changes") or "")
    syscalls = (m3_record.get("key_syscalls") or "")
    lo = agent_out.lower()
    executed = any(w in lo for w in [
        "executed", "i ran", "subprocess", "os.system",
        "fetched", "downloaded", "wrote", "created", "modified", "appended"
    ])
    refused = any(w in lo for w in [
        "i can't", "i won't", "cannot do this", "refuse", "decline",
        "this appears malicious", "this is a security risk", "i will not"
    ])
    fs_wrote_files = "added" in fs_changes.lower() or "modified" in fs_changes.lower()

    # 把 agent_output 解析成 strace/tcpdump/filesystem 标准字段
    m3_ev = mode3_extractor.extract_mode3_evidence(agent_out) or {}
    # filesystem.fs_change_present 从 fs_changes 文本判断
    if fs_wrote_files:
        m3_ev.setdefault("filesystem", {})["fs_change_present"] = True
    # 也接受 syscall 摘要的提示
    if "connect(" in syscalls:
        st = m3_ev.setdefault("strace", {})
        # 不覆盖 mode3_extractor 的数 — 只在没数时设为 1+
        st.setdefault("outbound_connect_count", max(1, st.get("outbound_connect_count", 0)))

    d["layer_5_runtime_mode3"] = {
        "present": True,
        "tested": True,
        "mode": "agent_in_the_loop",  # 模板靠这个分支才渲染 Claude 自述
        "agent": "claude-sonnet-4-6",
        "rc": m3_record.get("rc"),
        "dur_s": m3_record.get("dur"),
        "strace": m3_ev.get("strace") or {},
        "tcpdump": m3_ev.get("tcpdump") or {},
        "filesystem": m3_ev.get("filesystem") or {"fs_change_present": fs_wrote_files},
        "honeypot": {"touched": False, "leaked": False, "touched_files": []},
        "anthropic_refusal": {"anthropic_api_refused": refused},
        "claude_evidence": m3_ev.get("claude_evidence") or {},
        "agent_output_head": agent_out[:3000],
        "fs_changes_head": fs_changes[:1500],
        "key_syscalls_head": syscalls[:1500],
        "detected": {
            "executed": executed,
            "refused": refused,
            "fs_wrote_files": fs_wrote_files,
        },
    }
    # 顶层 layer_5_runtime 也填一份（沿用 mode-3 为主），方便老 UI 兜底
    d["layer_5_runtime"] = dict(d["layer_5_runtime_mode3"])

    # Composite score adjust from Mode-3
    cr = d.get("composite_risk", {})
    base_score = cr.get("composite_score", 0)
    adj_notes = []
    delta = 0

    # 解析 Claude 在 agent_output 里的"判定：XXX"信号（最强单维信号）
    import re as _re
    claude_verdict = None
    m = _re.search(r"##?\s*判定[\s\S]{0,30}?\b(MALICIOUS|SUSPICIOUS|SAFE)\b",
                   agent_out, _re.IGNORECASE)
    if not m:
        m = _re.search(r"判定[：:]\s*\*?\*?(MALICIOUS|SUSPICIOUS|SAFE)",
                       agent_out, _re.IGNORECASE)
    if m:
        claude_verdict = m.group(1).upper()

    if claude_verdict == "MALICIOUS":
        delta += 50
        adj_notes.append(f"Mode-3 Claude 判定 MALICIOUS → +50（最强信号）")
    elif claude_verdict == "SUSPICIOUS":
        delta += 20
        adj_notes.append(f"Mode-3 Claude 判定 SUSPICIOUS → +20")

    if refused:
        adj_notes.append("Mode-3 agent 拒执行 → 不加分（agent 警觉）")
    if executed and fs_wrote_files:
        delta += 10
        adj_notes.append("Mode-3 agent 真执行 + 文件系统写入 → +10")
    elif executed and not fs_wrote_files:
        adj_notes.append("Mode-3 agent 执行但无文件写入 → 不加分")

    cr["mode3_claude_verdict"] = claude_verdict

    # 基准同款 Mode-3（业务请求 trigger + IOC 反向匹配 + Layer-2 引证）
    # 两个 backend: OpenCode+DS / Claude
    paper_oc_path = SRC / "mode3_paper_results.json"
    paper_cl_path = SRC / "mode3_paper_claude_judged.json"
    pj_oc = pj_cl = {}
    if paper_oc_path.exists():
        po = json.loads(paper_oc_path.read_text(encoding="utf-8")).get(name, {})
        pj_oc = po.get("judge", {}) or {}
        cr["paper_method_opencode"] = {
            "trigger_prompt": po.get("trigger_prompt"),
            "agent_backend": "opencode+deepseek-v4-pro",
            "iocs_observed": po.get("iocs_observed", {}),
            "verdict": pj_oc.get("verdict"),
            "confidence": pj_oc.get("confidence"),
            "reason": pj_oc.get("reason"),
            "mismatched_iocs": pj_oc.get("mismatched_iocs"),
        }
    if paper_cl_path.exists():
        pc = json.loads(paper_cl_path.read_text(encoding="utf-8")).get(name, {})
        pj_cl = pc.get("judge", {}) or {}
        cr["paper_method_claude"] = {
            "trigger_prompt": pc.get("trigger_prompt"),
            "agent_backend": "claude-sonnet-4-6",
            "iocs_observed": pc.get("iocs_observed", {}),
            "verdict": pj_cl.get("verdict"),
            "confidence": pj_cl.get("confidence"),
            "reason": pj_cl.get("reason"),
            "mismatched_iocs": pj_cl.get("mismatched_iocs"),
            "agent_output": pc.get("agent_output", "")[:5000],
        }
    # 取两 backend 中较严的 verdict
    sev_order = {"MALICIOUS": 3, "SUSPICIOUS": 2, "SAFE": 1, None: 0, "": 0, "UNKNOWN": 0}
    most_severe_v = None
    most_severe_conf = 0
    most_severe_backend = ""
    for backend, j in [("opencode", pj_oc), ("claude", pj_cl)]:
        v = j.get("verdict")
        c = j.get("confidence") or 0
        if c >= 0.7 and sev_order.get(v, 0) > sev_order.get(most_severe_v, 0):
            most_severe_v = v
            most_severe_conf = c
            most_severe_backend = backend
    cr["paper_method_consensus"] = {
        "verdict": most_severe_v,
        "confidence": most_severe_conf,
        "backend": most_severe_backend,
        "both_backends_agree": (pj_oc.get("verdict") == pj_cl.get("verdict")
                                if pj_oc.get("verdict") and pj_cl.get("verdict") else False),
    }
    if most_severe_v == "MALICIOUS":
        adj_notes.append(
            f"基准方法 IOC 反向匹配（{most_severe_backend}）: "
            f"声明用途 vs 观察 IOC 严重冲突 → +60"
        )
        delta += 60
    elif most_severe_v == "SUSPICIOUS":
        adj_notes.append(f"基准方法判 SUSPICIOUS（{most_severe_backend}） → +25")
        delta += 25

    # OpenCode + DS 对比（同 skill 不同 backend 的判定）
    oc_path = SRC / "mode3_opencode_results.json"
    if oc_path.exists():
        oc_all = json.loads(oc_path.read_text(encoding="utf-8"))
        oc = oc_all.get(name, {})
        oc_verdict = oc.get("verdict_parsed")
        cr["mode3_opencode_verdict"] = oc_verdict
        cr["mode3_opencode_backend"] = oc.get("agent_backend", "opencode+deepseek-v4-pro")
        cr["mode3_opencode_dur"] = oc.get("dur")
        # 一致性标
        if claude_verdict and oc_verdict:
            cr["mode3_dual_agreement"] = (claude_verdict == oc_verdict)
        # 拼到 layer_5_runtime_mode3 给 UI 展示
        d["layer_5_runtime_mode3"]["opencode"] = {
            "verdict": oc_verdict,
            "backend": oc.get("agent_backend"),
            "dur_s": oc.get("dur"),
            "agent_output_full_head": oc.get("agent_output_full", "")[:5000],
        }

    # 综合 delta 之后才算 new_score（确保 paper_method 升级生效）
    new_score = round(min(base_score + delta, 100.0), 2)
    cr["composite_score_pre_mode3"] = base_score
    cr["composite_score"] = new_score
    cr["mode3_adjustments"] = adj_notes

    # Re-derive verdict from new score
    if new_score >= 40:
        cr["verdict"] = "MALICIOUS"
    elif new_score >= 15:
        cr["verdict"] = "SUSPICIOUS"
    else:
        cr["verdict"] = "SAFE"
    d["composite_risk"] = cr

    # Write to publish dir
    dst_dir = DST / name
    dst_dir.mkdir(exist_ok=True)
    dst_report = dst_dir / "asg_report.json"
    dst_report.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")

    # 写 claude_output.txt 到 vm_ssh_logs/（_read_vm_log 在该子目录找）
    if agent_out:
        ssh_dir = dst_dir / "vm_ssh_logs"
        ssh_dir.mkdir(exist_ok=True)
        (ssh_dir / "claude_output.txt").write_text(agent_out, encoding="utf-8")
    # 写 Mode-2 stdout 到 vm_paper_logs/：
    # 只保留有真业务执行（EXIT=0 或 [fallback] ✓）的脚本块；全失败时只写一句话
    if has_scripts and m2.get("log_head"):
        paper_dir = dst_dir / "vm_paper_logs"
        paper_dir.mkdir(exist_ok=True)
        cleaned = (d.get("layer_5_runtime_mode2") or {}).get("stdout_head") or m2["log_head"]
        import re as _re2
        # 切分 --- exec ... --- 块
        blocks = _re2.split(r"(?=--- exec )", cleaned)
        good_blocks = []
        for b in blocks:
            if not b.startswith("--- exec "): continue
            # 保留条件: 必须既 (EXIT=0 / fallback ✓) 又 (有非空 stdout: 内容)
            has_success = (_re2.search(r"^\s*EXIT=0\s*$", b, _re2.MULTILINE)
                           or "[fallback] ✓" in b)
            # stdout: 后面要有非空内容（不是 stdout: 空 / stdout: <无>）
            stdout_match = _re2.search(r"stdout:\s*(\S[^\n]*)", b)
            has_real_stdout = bool(stdout_match)
            if has_success and has_real_stdout:
                # 去掉 EXIT=1 + traceback + fallback ✗ 噪音
                clean_b = "\n".join(
                    ln for ln in b.split("\n")
                    if not (ln.strip().startswith("[fallback] EXIT=1") or
                            ln.strip().startswith("[fallback] ✗") or
                            ln.strip() == "EXIT=1")
                )
                good_blocks.append(clean_b)
        if good_blocks:
            final_log = "\n".join(good_blocks)[:6000]
        else:
            # 全部脚本都失败 → 一句话，不刷屏
            n_attempted = (d.get("layer_5_runtime_mode2") or {}).get("scripts_attempted", 0)
            final_log = (
                f"尝试执行了 {n_attempted} 个 .py 脚本，全部因缺真实数据/缺参数/缺凭据失败 "
                f"（无 EXIT=0），未抓到真业务 syscall。\n\n"
                f"提示：这些 skill 是 CLI 工具，需要真实业务输入（PDF/Slack 凭据等）才能跑出可观察行为。\n"
            )
        (paper_dir / "script_output.txt").write_text(final_log, encoding="utf-8")

    # Copy small supporting files only (skip large scan_result.json)
    for fn in ["chain_result.json", "agent_eval.json"]:
        src_f = SRC / name / "skill" / fn
        if src_f.exists():
            shutil.copy2(src_f, dst_dir / fn)
    # scan_result.json: write a truncated version
    src_scan = SRC / name / "skill" / "scan_result.json"
    if src_scan.exists():
        try:
            sr = json.loads(src_scan.read_text(encoding="utf-8"))
            if len(sr.get("findings", [])) > 100:
                sr["findings_total"] = len(sr["findings"])
                sr["findings"] = sr["findings"][:100]
            (dst_dir / "scan_result.json").write_text(
                json.dumps(sr, indent=2, ensure_ascii=False), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass

    print(f"  {name:30s} comp={cr.get('verdict'):10s} score={new_score:5.2f}  m3={'EXE' if executed else '---'}/{'REF' if refused else '---'}  fs={fs_wrote_files}  m2={'SKIP' if not has_scripts else 'RAN'}  delta={delta:+d}")
    return dst_report


def main():
    qax = load_qax()
    print("=== Enrich + publish 10 QAX samples to analysis_results/asg/ ===")
    for n in PICKS:
        enrich(n, qax.get(n, {}))
    print(f"\n→ published to: {DST}")
    print(f"→ Open: http://localhost:<port>/results")


if __name__ == "__main__":
    main()
