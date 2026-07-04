"""Evaluate scanner against a labeled benchmark.

Ground truth in tools/eval_ground_truth.json maps skill_name -> 0 (benign) / 1 (malicious).

Reads each labeled skill's analysis_results/asg/<skill>/asg_report.json,
treats verdict in {SUSPICIOUS, MALICIOUS} as positive prediction.

Outputs:
  - Precision / Recall / F1 / FPR / F2
  - Confusion matrix
  - List of FP and FN by name (for debugging which rules misfired / missed)
  - Optional --by-source group results
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GT_PATH = ROOT / "tools" / "eval_ground_truth.json"
ASG_DIR = ROOT / "analysis_results" / "asg"


def load_verdict(name: str) -> tuple[str, float] | None:
    p = ASG_DIR / name / "asg_report.json"
    if not p.exists():
        return None
    try:
        r = json.loads(p.read_text(encoding="utf-8"))
        v = r["composite_risk"]["verdict"]
        s = r["composite_risk"]["composite_score"]
        return (v, s)
    except (json.JSONDecodeError, KeyError):
        return None


def main() -> int:
    if not GT_PATH.exists():
        print(f"ground truth not found: {GT_PATH}", file=sys.stderr)
        return 2
    labels: dict[str, int] = json.loads(GT_PATH.read_text(encoding="utf-8"))

    tp, fp, tn, fn = 0, 0, 0, 0
    fp_names: list[tuple[str, float]] = []
    fn_names: list[tuple[str, float]] = []
    missing: list[str] = []
    for name, label in labels.items():
        v = load_verdict(name)
        if v is None:
            missing.append(name)
            continue
        verdict, score = v
        # 二分类：SUSPICIOUS / MALICIOUS -> 1, SAFE -> 0
        pred = 1 if verdict in {"SUSPICIOUS", "MALICIOUS",
                                "CRITICAL_MALICIOUS"} else 0
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
            fp_names.append((name, score))
        elif pred == 0 and label == 0:
            tn += 1
        else:  # pred==0, label==1
            fn += 1
            fn_names.append((name, score))

    total = tp + fp + tn + fn
    if total == 0:
        print("no scored samples (missing all?)", file=sys.stderr)
        return 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    f2 = 5 * precision * recall / (4 * precision + recall) if (4 * precision + recall) else 0.0

    print("=" * 60)
    print(f"Confusion Matrix (over {total} labeled samples, {len(missing)} missing reports)")
    print("=" * 60)
    print(f"  TP = {tp:>3}   FP = {fp:>3}")
    print(f"  FN = {fn:>3}   TN = {tn:>3}")
    print()
    print(f"Precision  = {precision:.3f}")
    print(f"Recall     = {recall:.3f}  (miss-rate = {1-recall:.1%})")
    print(f"F1         = {f1:.3f}")
    print(f"F2         = {f2:.3f}  (recall-weighted)")
    print(f"FPR        = {fpr:.3f}  ({fp} benign judged not-safe)")
    print()
    if fp_names:
        print(f"--- False Positives ({len(fp_names)}, benign judged not-safe) ---")
        for n, s in sorted(fp_names, key=lambda x: -x[1]):
            print(f"  {n:<40} score={s:>5.1f}")
        print()
    if fn_names:
        print(f"--- False Negatives ({len(fn_names)}, malicious missed) ---")
        for n, s in sorted(fn_names, key=lambda x: -x[1])[:30]:
            print(f"  {n:<40} score={s:>5.1f}")
        if len(fn_names) > 30:
            print(f"  ... ({len(fn_names)-30} more)")
        print()
    if missing:
        print(f"--- Missing reports ({len(missing)}, skipped from metrics) ---")
        for n in missing[:10]:
            print(f"  {n}")
        if len(missing) > 10:
            print(f"  ... ({len(missing)-10} more)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
