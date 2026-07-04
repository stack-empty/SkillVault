"""给已跑过的 unified_15 样本补跑 asg_cli scan --enable-ssd，
生成 SAFESKILL 标准 asg_report.json（含 SSD 4 维），供 /report/<name> 用同款 UI 渲染。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

from malskillbench_runner import DATASET_ROOT

ASG_OUT = REPO / "analysis_results" / "asg"


def load_anthropic_env() -> dict:
    cfg_path = REPO / "asg" / "vm_config.json"
    if not cfg_path.exists():
        return {}
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    key = cfg.get("remote_anthropic_api_key", "")
    env = {}
    if key and "REPLACE" not in key:
        env["ANTHROPIC_API_KEY"] = key
        base = cfg.get("remote_anthropic_base_url")
        if base:
            env["ANTHROPIC_BASE_URL"] = base
    return env


def one(name: str, env: dict) -> tuple[str, bool, str]:
    skill_path = DATASET_ROOT / "adhoc" / name
    if not skill_path.exists():
        return name, False, "skill not in adhoc dir"
    out_dir = ASG_OUT / name
    if (out_dir / "asg_report.json").exists():
        return name, True, "已存在，跳过"
    full_env = {**os.environ, **env}
    cmd = [
        sys.executable, "-m", "asg.asg_cli", "scan", str(skill_path),
        "--enable-honeypot", "--enable-ssd",
    ]
    t0 = time.time()
    try:
        subprocess.run(cmd, cwd=str(REPO), check=True,
                       capture_output=True, text=True, timeout=180, env=full_env)
    except subprocess.CalledProcessError as e:
        return name, False, f"scan failed: {(e.stderr or '')[:120]}"
    except subprocess.TimeoutExpired:
        return name, False, "scan timeout"
    try:
        subprocess.run(
            [sys.executable, "-m", "asg.asg_cli", "build-html", "--skill", name],
            cwd=str(REPO), check=True, capture_output=True, text=True,
            timeout=30, env=full_env,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    dur = time.time() - t0
    return name, True, f"OK {dur:.0f}s"


def main():
    env = load_anthropic_env()
    if not env:
        print("⚠ vm_config.json 中无 Claude API key，SSD 仍可用（DS 优先），但跨模型升级不可用。")

    # 找出所有 unified_scans 里有的样本名
    unified_root = REPO / "analysis_results" / "unified_scans"
    names = [p.name for p in unified_root.iterdir()
             if p.is_dir() and not p.name.startswith("_")]
    print(f"待补跑 SSD: {len(names)} 个样本")
    for n in names:
        print(f"  - {n}")
    print()

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(one, n, env): n for n in names}
        done = 0
        for f in as_completed(futs):
            done += 1
            name, ok, msg = f.result()
            mark = "✓" if ok else "✗"
            print(f"  [{done:2d}/{len(names)}] {mark} {name[:45]:45s} {msg}")
    print(f"\n总耗时 {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
