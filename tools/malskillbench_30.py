"""扫 30 个 MalSkillBench 样本（20 malware + 10 benign）。"""
from __future__ import annotations

import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

from malskillbench_runner import process_one, DATASET_ROOT

WORK = REPO / "analysis_results" / "malskillbench"
WORK.mkdir(exist_ok=True, parents=True)


def parse_label(name: str) -> tuple[str, str]:
    """从样本名抽 vector + behavior。如 'foo__CI_B4' → ('CI', 'B4')"""
    m = re.search(r"__(CI|PI|MIXED)_(B\d+)$", name)
    if m:
        return m.group(1), m.group(2)
    return "BENIGN", "B0"


def pick_30_samples() -> list[tuple[str, str, str, str]]:
    """挑 30 个 sample = 20 malware (CI/PI/MIXED 各种 B) + 10 benign。"""
    mal_dir = DATASET_ROOT / "malware"
    benign_dir = DATASET_ROOT / "benign"
    all_mal = sorted([p.name for p in mal_dir.iterdir() if p.is_dir()])
    all_benign = sorted([p.name for p in benign_dir.iterdir() if p.is_dir()])

    # 按 (vector, behavior) 分类
    by_label = {}
    for n in all_mal:
        v, b = parse_label(n)
        if v == "BENIGN": continue
        by_label.setdefault((v, b), []).append(n)

    # 优先覆盖 — 每个 (vector, behavior) 拿 1-2 个
    picks = []
    # 之前已跑过的 10 个先放进来，避免浪费
    PREVIOUS = [
        ("Art__CI_B1", "CI", "B1"),
        ("1k-cross-platform__CI_B4", "CI", "B4"),
        ("Branch Orchestration__CI_B6", "CI", "B6"),
        ("3d-games__PI_B10", "PI", "B10"),
        ("3d-web-experience__PI_B11", "PI", "B11"),
        ("Council__PI_B12", "PI", "B12"),
        ("1k-cross-platform__MIXED_B5", "MIXED", "B5"),
        ("3d-web-experience__MIXED_B7", "MIXED", "B7"),
    ]
    seen = set()
    for n, v, b in PREVIOUS:
        if (DATASET_ROOT / "malware" / n).exists():
            picks.append((n, "malware", v, b))
            seen.add(n)

    # 再补 12 个新 malware，每个 (vector, behavior) cell 优先未覆盖的
    seen_cells = {(p[2], p[3]) for p in picks}
    for (v, b), names in sorted(by_label.items()):
        if len(picks) >= 20: break
        if (v, b) in seen_cells: continue
        for n in names:
            if n in seen: continue
            picks.append((n, "malware", v, b))
            seen.add(n)
            seen_cells.add((v, b))
            break

    # 不够 20 就随便补到 20
    if len(picks) < 20:
        for (v, b), names in sorted(by_label.items()):
            if len(picks) >= 20: break
            for n in names:
                if n in seen: continue
                picks.append((n, "malware", v, b))
                seen.add(n)
                if len(picks) >= 20: break

    # 10 个 benign（之前已跑过 1password / 12306 + 8 个新）
    benign_picks = ["1password", "12306"]
    for n in all_benign:
        if len(benign_picks) >= 10: break
        if n in benign_picks: continue
        benign_picks.append(n)
    for n in benign_picks:
        picks.append((n, "benign", "BENIGN", "B0"))

    return picks[:30]


def main():
    samples = pick_30_samples()
    print("=" * 70)
    print(f"MalSkillBench 30 样本扫描 ({sum(1 for s in samples if s[1] == 'malware')} malware + {sum(1 for s in samples if s[1] == 'benign')} benign)")
    print("=" * 70)
    for n, cat, v, b in samples:
        print(f"  - [{cat}/{v}/{b}] {n}")
    print()

    results = {}
    t0 = time.time()
    # 3 路并行 — VM 资源限制下 docker 都能跑通
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = {
            ex.submit(process_one, n, cat, v, b): (n, cat, v, b)
            for n, cat, v, b in samples
        }
        done = 0
        for f in as_completed(futs):
            n, cat, v, b = futs[f]
            done += 1
            try:
                r = f.result()
                results[n] = r
                verdict = r["judge"].get("verdict")
                if v == "BENIGN":
                    ok = "✓" if verdict == "SAFE" else "✗"
                else:
                    ok = "✓" if verdict in ("MALICIOUS", "SUSPICIOUS") else "✗"
                print(f"  [{done:2d}/30] {ok} [{v:6s}/{b:3s}] {n[:40]:40s} verdict={verdict}")
            except Exception as e:
                print(f"  [{done:2d}/30] ✗ EXC [{v:6s}/{b:3s}] {n[:40]:40s} {type(e).__name__}: {str(e)[:60]}")
                results[n] = {"error": str(e), "ground_truth": {"vector": v, "behavior": b}}

    dur = time.time() - t0
    print(f"\n总耗时 {dur:.0f}s = {dur/60:.1f} 分钟")

    # 准确率统计
    by_vec = {"CI": [0, 0], "PI": [0, 0], "MIXED": [0, 0], "BENIGN": [0, 0]}
    for n, r in results.items():
        if "error" in r:
            v = r["ground_truth"]["vector"]
            by_vec[v][1] += 1
            continue
        v = r["ground_truth"]["vector"]
        verdict = r["judge"].get("verdict")
        if v == "BENIGN":
            ok = verdict == "SAFE"
        else:
            ok = verdict in ("MALICIOUS", "SUSPICIOUS")
        by_vec[v][1] += 1
        if ok: by_vec[v][0] += 1

    print("\n=== 准确率分类 ===")
    total_ok = 0
    total = 0
    for v, (ok, tot) in by_vec.items():
        if tot == 0: continue
        pct = ok / tot * 100
        print(f"  {v:8s}: {ok}/{tot} = {pct:.0f}%")
        total_ok += ok
        total += tot
    print(f"  ----------")
    print(f"  总体    : {total_ok}/{total} = {total_ok/max(1,total)*100:.0f}%")

    out = WORK / "malskillbench_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n→ {out}")


if __name__ == "__main__":
    main()
