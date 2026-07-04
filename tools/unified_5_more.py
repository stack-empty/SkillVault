"""再扫 5 个新样本（PI 攻击向量，B10-B11），看 OpenCode 真跑情况。"""
from __future__ import annotations

import json
import re
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

from malskillbench_runner import DATASET_ROOT
from unified_runner import UNIFIED_ROOT, run_unified

try:
    from inject_stage2b_runtime import inject as inject_s2b
except ImportError:
    def inject_s2b(*_args, **_kwargs):  # graceful no-op fallback
        return None

# 5 个 PI 攻击新样本（不在 unified_15 里）
PICKS = [
    ("3d-games__PI_B10", "malware", "PI", "B10"),
    ("3d-web-experience__PI_B11", "malware", "PI", "B11"),
    ("Backend Testing__PI_B10", "malware", "PI", "B10"),
    ("Council__PI_B12", "malware", "PI", "B12"),
    ("Bankr Agent - NFT Operations__PI_B10", "malware", "PI", "B10"),
]


def stage_to_adhoc(name: str, category: str) -> str:
    src = DATASET_ROOT / category / name
    safe = re.sub(r"[^A-Za-z0-9_\-]", "_", name)[:60]
    dst = DATASET_ROOT / "adhoc" / safe
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    return safe


def one(name, category, gt_vec, gt_beh):
    print(f"  [{gt_vec}/{gt_beh}] {name[:50]} ...")
    try:
        safe = stage_to_adhoc(name, category)
    except Exception as e:
        return {"original_name": name, "ground_truth": {"vector": gt_vec, "behavior": gt_beh},
                "error": f"stage: {e}"}
    try:
        r = run_unified(safe, enable_stage3=False)
        r["original_name"] = name
        r["ground_truth"] = {"vector": gt_vec, "behavior": gt_beh}
        save = UNIFIED_ROOT / safe / "result.json"
        save.parent.mkdir(parents=True, exist_ok=True)
        save.write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        # 跑完立刻补跑 asg_cli scan 生成 SSD + 注入 Mode-3
        _safeskill_gen(safe)
        return r
    except Exception as e:
        return {"original_name": name, "ground_truth": {"vector": gt_vec, "behavior": gt_beh},
                "error": f"run: {e}"}


def _safeskill_gen(safe_name):
    """跑 asg_cli scan 生成 SSD + 注入 Stage 2B 到 Mode-3。"""
    import subprocess, os
    asg_p = REPO / "analysis_results" / "asg" / safe_name
    cfg_p = REPO / "asg" / "vm_config.json"
    env = {**os.environ}
    if cfg_p.exists():
        try:
            cfg = json.loads(cfg_p.read_text(encoding="utf-8"))
            key = cfg.get("remote_anthropic_api_key", "")
            if key and "REPLACE" not in key:
                env["ANTHROPIC_API_KEY"] = key
                base = cfg.get("remote_anthropic_base_url")
                if base:
                    env["ANTHROPIC_BASE_URL"] = base
        except json.JSONDecodeError:
            pass
    skill_path = DATASET_ROOT / "adhoc" / safe_name
    try:
        subprocess.run(
            [sys.executable, "-m", "asg.asg_cli", "scan", str(skill_path),
             "--enable-honeypot", "--enable-ssd"],
            cwd=str(REPO), check=True, capture_output=True, text=True,
            timeout=180, env=env,
        )
    except Exception:
        pass
    try:
        subprocess.run(
            [sys.executable, "-m", "asg.asg_cli", "build-html", "--skill", safe_name],
            cwd=str(REPO), check=True, capture_output=True, text=True,
            timeout=30, env=env,
        )
    except Exception:
        pass
    try:
        inject_s2b(safe_name)
    except Exception:
        pass


def main():
    print("=" * 70)
    print(f"再扫 {len(PICKS)} 个新样本（PI 攻击向量）")
    print("=" * 70)
    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = {ex.submit(one, *p): p for p in PICKS}
        done = 0
        for f in as_completed(futs):
            done += 1
            r = f.result()
            results.append(r)
            n = r.get("original_name", "?")
            gt_vec = r.get("ground_truth", {}).get("vector", "?")
            gt_beh = r.get("ground_truth", {}).get("behavior", "?")
            if "error" in r:
                print(f"  [{done}/{len(PICKS)}] ✗ EXC {n[:40]} {r['error'][:60]}")
                continue
            v = r.get("verdict", "?")
            score = r.get("fusion", {}).get("risk_score", 0)
            ok = v in ("MALICIOUS", "SUSPICIOUS")
            mark = "✓" if ok else "✗"
            # 升级路径
            stages = r.get("stages", {})
            ran_s2b = stages.get("stage2b_opencode_ds") is not None
            s2b_mark = "✓ S2B" if ran_s2b else "— S2B"
            print(f"  [{done}/{len(PICKS)}] {mark} [{gt_vec}/{gt_beh}] {n[:38]:38s} verdict={v} score={score:.1f} ({s2b_mark})")

    dur = time.time() - t0
    print(f"\n总耗时 {dur:.0f}s")
    # 准确率
    ok = sum(1 for r in results if r.get("verdict") in ("MALICIOUS", "SUSPICIOUS"))
    print(f"准确率: {ok}/{len(results)} = {ok/len(results)*100:.0f}%")
    out = REPO / "analysis_results" / "unified_5_more" / "results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"→ {out}")


if __name__ == "__main__":
    main()
