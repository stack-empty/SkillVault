"""跑 15 个 MalSkillBench 样本（10 malware + 5 benign）过完整流水线。

每个 skill 都走 5 阶段 + 6 路融合 + 0-100 风险分。
2 路并行（VM 资源限制 + 每个 skill 内部还会启 2 并行升级，所以外层不能太多）。
"""
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

OUT = REPO / "analysis_results" / "unified_15"
OUT.mkdir(parents=True, exist_ok=True)


def parse_label(name: str) -> tuple[str, str]:
    m = re.search(r"__(CI|PI|MIXED)_(B\d+)$", name)
    return (m.group(1), m.group(2)) if m else ("BENIGN", "B0")


def pick_15() -> list[tuple[str, str, str, str]]:
    """10 malware（覆盖 CI/PI/MIXED 多 behavior）+ 5 benign。"""
    mal_dir = DATASET_ROOT / "malware"
    benign_dir = DATASET_ROOT / "benign"
    all_mal = sorted([p.name for p in mal_dir.iterdir() if p.is_dir()])
    all_benign = sorted([p.name for p in benign_dir.iterdir() if p.is_dir()])

    by_cell: dict[tuple[str, str], list[str]] = {}
    for n in all_mal:
        v, b = parse_label(n)
        if v == "BENIGN":
            continue
        by_cell.setdefault((v, b), []).append(n)

    picks: list[tuple[str, str, str, str]] = []
    # 优先取每个 (vec,beh) cell 第一个
    for (v, b), names in sorted(by_cell.items()):
        if len(picks) >= 10:
            break
        picks.append((names[0], "malware", v, b))
    # 5 benign
    for n in all_benign[:5]:
        picks.append((n, "benign", "BENIGN", "B0"))

    return picks[:15]


def stage_to_adhoc(name: str, category: str) -> str:
    """复制 DATASET_ROOT/<cat>/<name> 到 DATASET_ROOT/adhoc/<safe_name>，返回 safe_name。"""
    src = DATASET_ROOT / category / name
    # 防止 name 里有空格 / 中文导致 process_one 路径处理出问题，用 safe_name
    safe = re.sub(r"[^A-Za-z0-9_\-]", "_", name)[:60]
    dst = DATASET_ROOT / "adhoc" / safe
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    return safe


def one(name: str, category: str, gt_vec: str, gt_beh: str) -> dict:
    print(f"  [{category}/{gt_vec}/{gt_beh}] {name[:50]} ...")
    try:
        safe_name = stage_to_adhoc(name, category)
    except Exception as e:
        return {
            "original_name": name, "category": category,
            "ground_truth": {"vector": gt_vec, "behavior": gt_beh},
            "error": f"stage failed: {e}",
        }
    try:
        # 单样本不触发 Stage 3
        r = run_unified(safe_name, enable_stage3=False)
        r["original_name"] = name
        r["ground_truth"] = {"vector": gt_vec, "behavior": gt_beh}
        # 持久化每样本结果到 UNIFIED_ROOT（流水线自带）+ 复制一份到 OUT
        save_individual = UNIFIED_ROOT / safe_name / "result.json"
        save_individual.parent.mkdir(parents=True, exist_ok=True)
        save_individual.write_text(
            json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        return r
    except Exception as e:
        return {
            "original_name": name, "category": category,
            "ground_truth": {"vector": gt_vec, "behavior": gt_beh},
            "error": f"run_unified failed: {e}",
        }


def main():
    picks = pick_15()
    print("=" * 75)
    print(f"完整流水线扫描 15 个样本 "
          f"({sum(1 for p in picks if p[1]=='malware')} mal + "
          f"{sum(1 for p in picks if p[1]=='benign')} benign)")
    print("=" * 75)
    for n, cat, v, b in picks:
        print(f"  - [{cat:7s}/{v:6s}/{b:3s}] {n}")
    print()

    t0 = time.time()
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = {ex.submit(one, n, c, v, b): (n, c, v, b) for n, c, v, b in picks}
        done = 0
        for f in as_completed(futs):
            n, c, v, b = futs[f]
            done += 1
            r = f.result()
            results.append(r)
            if "error" in r:
                print(f"  [{done:2d}/15] ✗ EXC [{v:6s}/{b:3s}] {n[:46]:46s} {r['error'][:60]}")
                continue
            verdict = r.get("verdict", "?")
            score = r.get("fusion", {}).get("risk_score", 0)
            if v == "BENIGN":
                ok = verdict == "SAFE"
            else:
                ok = verdict in ("MALICIOUS", "SUSPICIOUS")
            mark = "✓" if ok else "✗"
            print(f"  [{done:2d}/15] {mark} [{v:6s}/{b:3s}] {n[:46]:46s} "
                  f"verdict={verdict} score={score:.1f}")

    dur = time.time() - t0
    print(f"\n总耗时 {dur:.0f}s = {dur/60:.1f} 分钟\n")

    # 准确率统计
    by_vec: dict[str, list[int]] = {"CI": [0, 0], "PI": [0, 0],
                                     "MIXED": [0, 0], "BENIGN": [0, 0]}
    for r in results:
        v = r["ground_truth"]["vector"]
        if "error" in r:
            by_vec[v][1] += 1
            continue
        verdict = r.get("verdict", "?")
        if v == "BENIGN":
            ok = verdict == "SAFE"
        else:
            ok = verdict in ("MALICIOUS", "SUSPICIOUS")
        by_vec[v][1] += 1
        if ok:
            by_vec[v][0] += 1

    print("=== 准确率分类 ===")
    total_ok = total = 0
    for v, (ok, tot) in by_vec.items():
        if tot == 0:
            continue
        print(f"  {v:8s}: {ok}/{tot} = {ok/tot*100:.0f}%")
        total_ok += ok; total += tot
    print(f"  ----------")
    print(f"  总体    : {total_ok}/{total} = {total_ok/max(1,total)*100:.0f}%")

    out_path = OUT / "results.json"
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"\n→ {out_path}")


if __name__ == "__main__":
    main()
