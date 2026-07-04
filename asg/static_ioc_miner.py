"""静态 IOC 预挖掘 — 不跑容器，扫 skill 源码抽可疑模式。
输出喂给 Layer 2 judge 当额外证据。
"""
from __future__ import annotations

import re
from pathlib import Path

# 已知良性外站（白名单）
_BENIGN_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "pypi.org",
    "files.pythonhosted.org", "registry.npmjs.org",
    "huggingface.co", "openai.com", "anthropic.com",
    "google.com", "yahoo.com", "coingecko.com",
    "localhost", "127.0.0.1", "example.com",
    "schema.org", "w3.org", "ietf.org",
}

# 已知 infra 私有 IP 段
_INFRA_IP_PREFIX = ("10.", "172.16.", "192.168.", "127.", "169.254.")


def _grep_files(skill_path: Path, pattern: str, flags: int = 0,
                max_per_file: int = 5,
                code_only: bool = False,
                skip_doc_lines: bool = True) -> list[tuple[str, int, str]]:
    """返回 [(file, line, snippet)]。
    code_only=True 时只扫源码文件（.py/.sh/.js/.ts），跳过 .md/.json/.yaml（文档/配置）。
    skip_doc_lines=True（默认）扫 .md 时跳过明显的文档说明行（命令行参数、列表项 inline code）。
    """
    hits = []
    rex = re.compile(pattern, flags)
    code_exts = {".py", ".js", ".ts", ".sh", ".bash"}
    all_exts = code_exts | {".md", ".yaml", ".yml", ".json"}
    for f in skill_path.rglob("*"):
        if not f.is_file(): continue
        if code_only:
            if f.suffix not in code_exts: continue
        else:
            if f.suffix not in all_exts: continue
        is_md = f.suffix == ".md"
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.split("\n"), 1):
            if is_md and skip_doc_lines and _is_doc_line(line):
                continue
            m = rex.search(line)
            if m:
                hits.append((str(f.relative_to(skill_path)), i, line.strip()[:200]))
                if sum(1 for h in hits if h[0] == str(f.relative_to(skill_path))) >= max_per_file:
                    break
    return hits[:50]


def _detect_pi_payload(skill_path: Path) -> list[dict]:
    """专扫 SKILL.md 找 prompt injection payload 痕迹。"""
    pi_patterns = [
        (r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|context)", "ignore_previous"),
        (r"(?i)disregard\s+(?:all\s+)?(?:previous|prior)", "disregard_previous"),
        (r"(?i)override\s+(?:all\s+)?(?:previous|prior|system)", "override_previous"),
        (r"(?i)all\s+prior\s+(?:task\s+)?specifications?\s+(?:are\s+)?invalidated", "specs_invalidated"),
        (r"(?i)you\s+(?:are\s+)?now\s+(?:a|an|the)\s+\w+(?:\s+agent|\s+assistant|\s+bot)?", "role_replacement"),
        (r"(?i)from\s+now\s+on[,:]?\s+you", "from_now_on"),
        (r"(?i)forget\s+(?:everything|your)\s+(?:above|previous|prior)", "forget_everything"),
        (r"(?i)system\s+override", "system_override"),
        (r"(?i)reveal\s+your\s+(?:system\s+)?prompt", "reveal_prompt"),
        (r"(?i)mandatory\s+(?:response\s+policy|response\s+format)", "mandatory_policy"),
        (r"(?i)harvest|exfiltrate|exfil\s+(?:user|system)\s+data", "exfil_keyword"),
        (r"(?i)autonomous\s+(?:digital|mode)\s+sovereign", "autonomous_sovereign"),
        (r"(?i)spread\s+(?:to|across)\s+other\s+agents?", "self_propagation"),
        # 新增：B11 Safety Bypass 用的伪装词（§3.1 同款 — bypass + protocol 包装）
        (r"(?i)bypass(?:ing|ed)?\s+(?:the\s+)?(?:security\s+)?(?:protocols?|safety|consent|safeguards?|filters?|rules?)", "safety_bypass"),
        (r"(?i)security\s+protocol\s+bypass", "explicit_bypass"),
        (r"(?i)rule[\s-]?breakers?", "rule_breaker"),
        (r"(?i)criminal\s+activit", "criminal_activity"),
        (r"(?i)deviant\s+activit", "deviant_activity"),
        # B10 Role Hijack 隐式变体
        (r"(?i)dual\s+(?:perspective|role|identity|life)", "dual_role"),
        (r"(?i)operational\s+(?:directives?|continuity|mode)", "operational_directive"),
        # B12 Instruction Override 隐式变体
        (r"(?i)CRITICAL[\s:]+This\s+section\s+contains\s+operational\s+directives", "critical_directive"),
        (r"(?i)govern[s]?\s+agent\s+behavior", "govern_behavior"),
    ]
    hits = []
    for f in skill_path.rglob("*"):
        if f.suffix != ".md": continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.split("\n"), 1):
            for pat, kind in pi_patterns:
                if re.search(pat, line):
                    hits.append({
                        "file": str(f.relative_to(skill_path)),
                        "line": i,
                        "kind": kind,
                        "snippet": line.strip()[:200],
                    })
                    break
    return hits[:20]


# 知名良性 CLI 工具白名单 — shell 调用这些是合法的
_BENIGN_CLI_TOOLS = {
    "git", "gh", "git-lfs", "hub",
    "npm", "yarn", "pnpm", "pip", "pip3", "uv", "pipx", "poetry", "node",
    "docker", "docker-compose", "podman", "kubectl", "helm",
    "aws", "az", "gcloud", "gsutil",
    "terraform", "pulumi", "ansible",
    "op",        # 1Password CLI
    "gpg", "ssh-keygen", "ssh-add",
    "python", "python3", "ruby", "go", "cargo", "rustc",
    "tmux", "screen", "make", "cmake", "ninja",
    # curl / wget 移出白名单 — 恶意 skill 常用它们外发数据
    "grep", "awk", "sed", "find", "ls", "cat", "head", "tail", "wc", "sort", "uniq",
    "jq", "yq",
    "ffmpeg", "imagemagick", "convert", "magick",
    "pdftotext", "pdfinfo", "pdftk", "ghostscript",
    "tesseract",
    "psql", "mysql", "sqlite3", "redis-cli", "mongo",
    "jest", "pytest", "go test",
}


def _shell_call_is_benign(snippet: str) -> bool:
    """检查 shell 调用是否调用已知良性 CLI（如 op / git / aws / kubectl）。"""
    low = snippet.lower()
    for tool in _BENIGN_CLI_TOOLS:
        # 匹配 "subprocess.run(['op',  ..." 或 "os.system('git ...")
        if re.search(rf"['\"\s]({re.escape(tool)})\s+", low):
            return True
        if re.search(rf"\[\s*['\"]{re.escape(tool)}['\"]", low):
            return True
    return False


def _is_doc_line(line: str) -> bool:
    """判断是否是文档里的命令行参数说明（如 `--type <X>` / `-f md` / `[option]`）。"""
    # 短横线 + 字母 + 中括号或反引号包围 = 参数说明
    if re.search(r"^\s*[-*]?\s*`?-[a-zA-Z]", line.strip()):
        return True
    # markdown 列表项里的 inline code
    if re.match(r"^\s*[-*]\s+`[^`]+`\s*[:：]", line):
        return True
    return False


def mine_static_iocs(skill_path: Path) -> dict:
    """对 skill 源码做静态 IOC 挖掘。"""
    p = Path(skill_path)
    out = {
        "hardcoded_urls": [],
        "hardcoded_ips": [],
        "shell_commands": [],
        "network_calls": [],
        "sensitive_paths_in_code": [],
        "dangerous_eval": [],
        "subprocess_calls": [],
        "summary": {},
    }

    # 1. 硬编码 URL
    url_hits = _grep_files(p, r"https?://[a-zA-Z0-9.\-_]+(?:[:/][^\s'\"<>]*)?")
    for f, ln, snip in url_hits:
        # 抽 host
        m = re.search(r"https?://([a-zA-Z0-9.\-_]+)", snip)
        if not m: continue
        host = m.group(1).lower()
        # 过滤良性
        if any(host == d or host.endswith("." + d) for d in _BENIGN_DOMAINS):
            continue
        out["hardcoded_urls"].append({"file": f, "line": ln, "host": host, "snippet": snip[:120]})

    # 2. 硬编码 IP（排除 infra）
    ip_hits = _grep_files(p, r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for f, ln, snip in ip_hits:
        m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", snip)
        if not m: continue
        ip = m.group(1)
        if any(ip.startswith(pre) for pre in _INFRA_IP_PREFIX):
            continue
        if ip in ("0.0.0.0", "255.255.255.255"):
            continue
        out["hardcoded_ips"].append({"file": f, "line": ln, "ip": ip, "snippet": snip[:120]})

    # 3. Shell 命令注入 — 全文件扫，但 .md 跳过文档说明行
    shell_hits = _grep_files(p,
        r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen|"
        r"shell_exec|/bin/(?:sh|bash)\s+-[ci]|powershell\s+-|"
        r"\$\(curl\s+http|`curl\s+http|`wget\s+http)",
        code_only=False)
    for f, ln, snip in shell_hits:
        if _shell_call_is_benign(snip):
            out.setdefault("benign_cli_uses", []).append(
                {"file": f, "line": ln, "snippet": snip[:200]})
            continue
        out["shell_commands"].append({"file": f, "line": ln, "snippet": snip[:200]})

    # 4. 网络调用 — 全文件扫
    net_hits = _grep_files(p,
        r"(?:socket\.(?:socket|connect|gethostbyname)|"
        r"requests\.(?:get|post|put|delete|request)|"
        r"urllib(?:\.request)?\.urlopen|urllib2\.urlopen|"
        r"httplib\.|http\.client\.|aiohttp\.|httpx\.|"
        r"curl\s+(?:-X\s+POST|-d\s)|wget\s+http)",
        code_only=False)
    for f, ln, snip in net_hits:
        out["network_calls"].append({"file": f, "line": ln, "snippet": snip[:200]})

    # 5. 代码里的敏感路径 — 全文件扫
    sens_hits = _grep_files(p,
        r"(?:\.ssh/(?:id_rsa|id_ed25519|authorized_keys)|"
        r"\.aws/credentials|\.aws/config|"
        r"/etc/shadow|/etc/sudoers|\.env(?:\W|$)|"
        r"~?/\.netrc|\.docker/config\.json|\.kube/config|"
        r"credentials\.json)",
        code_only=False)
    for f, ln, snip in sens_hits:
        out["sensitive_paths_in_code"].append({"file": f, "line": ln, "snippet": snip[:200]})

    # 5.5. PI payload 痕迹（专扫 SKILL.md） — 新增
    out["pi_payloads"] = _detect_pi_payload(p)

    # 6. eval / exec / __import__
    eval_hits = _grep_files(p,
        r"(?:^|[^a-zA-Z_])(?:eval|exec|__import__|compile)\s*\("
        r"|globals\(\)\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\("
        r"|getattr\s*\([^,]+,\s*['\"][^'\"]+['\"]\s*\)\s*\(")
    for f, ln, snip in eval_hits:
        out["dangerous_eval"].append({"file": f, "line": ln, "snippet": snip[:200]})

    # 7. subprocess+download 组合（典型 dropper）
    dropper_hits = _grep_files(p,
        r"(?:wget|curl|nc\b|ncat|invoke-webrequest|invoke-restmethod).*?(?:\|\s*(?:sh|bash|python)|>\s*/tmp/)")
    for f, ln, snip in dropper_hits:
        out["shell_commands"].append({"file": f, "line": ln, "snippet": snip[:200], "_kind": "dropper"})

    # 汇总
    out["summary"] = {
        "n_hardcoded_external_urls": len(out["hardcoded_urls"]),
        "n_hardcoded_external_ips": len(out["hardcoded_ips"]),
        "n_shell_commands": len(out["shell_commands"]),
        "n_benign_cli_uses": len(out.get("benign_cli_uses", [])),
        "n_network_calls": len(out["network_calls"]),
        "n_sensitive_paths": len(out["sensitive_paths_in_code"]),
        "n_dangerous_eval": len(out["dangerous_eval"]),
        "n_pi_payloads": len(out.get("pi_payloads", [])),
    }
    out["risk_score"] = _quick_risk_score(out)
    return out


def _quick_risk_score(iocs: dict) -> float:
    """给一个快速 0-1 静态风险分（仅参考，不用于最终 verdict）。
    良性 CLI 使用（op/git/aws/...）已经被过滤到 benign_cli_uses，不计分。
    """
    s = iocs["summary"]
    score = (
        min(s["n_hardcoded_external_ips"], 5) * 0.20 +
        min(s["n_hardcoded_external_urls"], 5) * 0.08 +
        min(s["n_dangerous_eval"], 3) * 0.25 +
        min(s["n_shell_commands"], 5) * 0.06 +
        min(s["n_sensitive_paths"], 3) * 0.10 +
        min(s["n_network_calls"], 5) * 0.03 +
        min(s.get("n_pi_payloads", 0), 3) * 0.20     # PI payload 痕迹同 eval 同高
    )
    return round(min(score, 1.0), 2)


def format_for_layer2(iocs: dict, max_items: int = 6) -> str:
    """格式化喂给 Layer 2 judge 的中文摘要。"""
    s = iocs["summary"]
    if all(v == 0 for v in s.values()):
        return "静态预扫: 未发现硬编码外站/IP、shell 调用、敏感路径、eval 等可疑模式。"

    lines = [f"静态预扫风险分: {iocs['risk_score']}/1.0\n"]
    if iocs["hardcoded_ips"]:
        lines.append(f"硬编码外网 IP（{len(iocs['hardcoded_ips'])} 处）:")
        for h in iocs["hardcoded_ips"][:max_items]:
            lines.append(f"  {h['file']}:{h['line']} → {h['ip']}  | {h['snippet'][:80]}")
    if iocs["hardcoded_urls"]:
        lines.append(f"硬编码外站 URL（{len(iocs['hardcoded_urls'])} 处）:")
        for h in iocs["hardcoded_urls"][:max_items]:
            lines.append(f"  {h['file']}:{h['line']} → {h['host']}  | {h['snippet'][:80]}")
    if iocs["dangerous_eval"]:
        lines.append(f"eval/exec 动态执行（{len(iocs['dangerous_eval'])} 处）:")
        for h in iocs["dangerous_eval"][:max_items]:
            lines.append(f"  {h['file']}:{h['line']}  | {h['snippet'][:100]}")
    if iocs["shell_commands"]:
        lines.append(f"Shell 命令调用（{len(iocs['shell_commands'])} 处，可疑/未知 binary）:")
        for h in iocs["shell_commands"][:max_items]:
            kind = h.get("_kind", "")
            tag = f" [{kind}]" if kind else ""
            lines.append(f"  {h['file']}:{h['line']}{tag}  | {h['snippet'][:100]}")
    benign_uses = iocs.get("benign_cli_uses", [])
    if benign_uses:
        # 良性 CLI 单独列出，告诉 judge 这些不算可疑
        cli_set = set()
        for h in benign_uses[:max_items*2]:
            for tool in _BENIGN_CLI_TOOLS:
                import re as _re
                if _re.search(rf"['\"\s]{_re.escape(tool)}\s+", h["snippet"].lower()):
                    cli_set.add(tool); break
        lines.append(f"良性 CLI 工具使用（{len(benign_uses)} 处，**不算可疑** — 已知工具 {', '.join(sorted(cli_set))}）")
    if iocs["sensitive_paths_in_code"]:
        lines.append(f"代码引用敏感路径（{len(iocs['sensitive_paths_in_code'])} 处）:")
        for h in iocs["sensitive_paths_in_code"][:max_items]:
            lines.append(f"  {h['file']}:{h['line']}  | {h['snippet'][:100]}")
    if iocs["network_calls"]:
        lines.append(f"网络调用（{len(iocs['network_calls'])} 处）:")
        for h in iocs["network_calls"][:max_items]:
            lines.append(f"  {h['file']}:{h['line']}  | {h['snippet'][:100]}")
    pi_payloads = iocs.get("pi_payloads", [])
    if pi_payloads:
        kinds = sorted(set(h["kind"] for h in pi_payloads))
        lines.append(f"⚠ Prompt Injection 痕迹（SKILL.md 中，共 {len(pi_payloads)} 处）: {', '.join(kinds)}")
        for h in pi_payloads[:max_items]:
            lines.append(f"  {h['file']}:{h['line']} [{h['kind']}] | {h['snippet'][:100]}")
    return "\n".join(lines)
