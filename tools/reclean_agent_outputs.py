"""不重跑 Docker，只重新 clean 每个 sample 的 agent_output（拉 VM 上的 claude_output.txt）。"""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import paramiko

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))

from malskillbench_runner import clean_agent_output, safe_name

WORK = REPO / "analysis_results" / "malskillbench"
VM_CONFIG = json.loads((REPO / "asg" / "vm_config.json").read_text())


def ssh_client():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(VM_CONFIG["host"], port=VM_CONFIG["port"],
              username=VM_CONFIG["username"],
              password=VM_CONFIG["password"], timeout=15)
    return c


def reclean(name, r):
    safe = safe_name(name)
    log_path = f"/tmp/qax_logs/malskillbench/manual/malskillbench/msb_{safe}/claude_output.txt"
    ssh = ssh_client()
    try:
        _, o, _ = ssh.exec_command(f"cat {log_path} 2>&1")
        raw = o.read().decode("utf-8", "replace")
        cleaned = clean_agent_output(raw)
        return name, cleaned
    finally:
        ssh.close()


def main():
    src = WORK / "malskillbench_results.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    print("=" * 60)
    print("Reclean agent_output 不重跑 Docker")
    print("=" * 60)
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(reclean, n, r): n for n, r in data.items()}
        for f in as_completed(futs):
            n, cleaned = f.result()
            old_len = len(data[n].get("agent_output_head", ""))
            data[n]["agent_output_head"] = cleaned[:3000]
            data[n]["agent_output"] = cleaned[:15000]
            # 检查质量
            import re as _re
            has_code = bool(_re.search(r"^\s*def\s+\w+\(.*\):$", cleaned, _re.MULTILINE)) or \
                       bool(_re.search(r"^\s*import\s+\w+$", cleaned, _re.MULTILINE))
            has_tool = "$ cat" in cleaned or "$ find" in cleaned or "→ Read" in cleaned
            has_pre_exec_dump = "Pre-Execute 真实 syscall" in cleaned[:200]
            print(f"  {n:35s} {old_len}→{len(cleaned)}B 源码={has_code} 工具={has_tool} preexec={has_pre_exec_dump}")
            # 前 100 字预览
            print(f"    前 100 字: {cleaned[:100].strip()!r}")
    src.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n→ {src}")


if __name__ == "__main__":
    main()
