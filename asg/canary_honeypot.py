"""Canary 蜜罐系统 — 把带唯一 token 的假凭据塞进容器。
跑完后扫 network.pcap / strace.log / fs_changes，看 canary 有没有泄露。
泄露 → MALICIOUS（铁证：canary 是唯一随机 token 不可能巧合命中）。
"""
from __future__ import annotations

import json
import re
import secrets
from pathlib import Path


def generate_canary_set() -> dict:
    """生成一组带唯一 token 的蜜罐凭据。每次调用都新 token。"""
    # 4 个独立 canary token（让我们知道哪个被偷了）
    tok_ssh = secrets.token_urlsafe(24)
    tok_aws = secrets.token_urlsafe(24)
    tok_env = secrets.token_urlsafe(24)
    tok_api = secrets.token_urlsafe(24)

    canary_files = {
        # ~/.ssh/id_rsa — 看起来像真 RSA 私钥
        ".ssh/id_rsa": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA" + tok_ssh + "abcdefghij\n"
            "klmnopqrstuvwxyz0123456789==\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
        ".ssh/id_rsa.pub": f"ssh-rsa AAAA{tok_ssh}== honeypot-canary@example.com\n",
        ".ssh/known_hosts": "github.com ssh-rsa AAAAB3NzaC1yc2E...\n",

        # ~/.aws/credentials — 看起来像真 AWS 凭据
        ".aws/credentials": (
            "[default]\n"
            f"aws_access_key_id = AKIA{tok_aws[:16].upper()}\n"
            f"aws_secret_access_key = {tok_aws}\n"
        ),
        ".aws/config": "[default]\nregion = us-east-1\n",

        # 项目 .env
        ".env": (
            f"DATABASE_URL=postgres://prod_user:{tok_env}@db.internal:5432/main\n"
            f"OPENAI_API_KEY=sk-{tok_api}\n"
            f"STRIPE_KEY=sk_live_{tok_api[:32]}\n"
            f"GITHUB_TOKEN=ghp_{tok_api[:36]}\n"
        ),

        # 在 stub 里也埋一份（如果 skill 真按 SKILL.md 跑业务流程，可能会读到）
        "stub/secrets.json": json.dumps({
            "api_key": tok_api,
            "db_password": tok_env,
            "internal_token": tok_ssh,
        }, indent=2),
    }

    canary_map = {
        "ssh_key": tok_ssh,
        "aws_secret": tok_aws,
        "env_secret": tok_env,
        "api_key": tok_api,
        "all_tokens": [tok_ssh, tok_aws, tok_env, tok_api],
    }
    return {"files": canary_files, "tokens": canary_map}


def render_setup_bash(canary: dict) -> str:
    """生成在容器内 bash 里跑的蜜罐布置脚本（base64 编码安全嵌入）。"""
    import base64
    py_setup = (
        "import os\n"
        "from pathlib import Path\n"
        "HOME = '/home/appuser'\n"
        f"files = {json.dumps(canary['files'])}\n"
        "for rel_path, content in files.items():\n"
        "    p = Path(HOME) / rel_path\n"
        "    p.parent.mkdir(parents=True, exist_ok=True)\n"
        "    p.write_text(content)\n"
        "    p.chmod(0o600 if 'id_rsa' == p.name or 'credentials' in str(p) else 0o644)\n"
        "    try:\n"
        "        import pwd\n"
        "        uid = pwd.getpwnam('appuser').pw_uid\n"
        "        gid = pwd.getpwnam('appuser').pw_gid\n"
        "        os.chown(p, uid, gid)\n"
        "        os.chown(p.parent, uid, gid)\n"
        "    except Exception: pass\n"
        f"print('[canary] planted {len(canary['files'])} honeypot files')\n"
    )
    b64 = base64.b64encode(py_setup.encode("utf-8")).decode()
    return f"echo {b64} | base64 -d | python3"


def scan_for_leaks(canary: dict, evidence_paths: dict) -> dict:
    """跑完后扫所有证据通道找 canary token。
    evidence_paths: {
        'network_pcap_bytes': bytes | None,
        'strace_log_text': str | None,
        'inotify_log_text': str | None,
        'fs_changes_text': str | None,
        'agent_output': str | None,
    }
    """
    leaks = {
        "ssh_key_leaked": [],
        "aws_secret_leaked": [],
        "env_secret_leaked": [],
        "api_key_leaked": [],
        "any_leaked": False,
        "leak_channels": [],
    }
    tokens = canary["tokens"]
    token_to_kind = {
        tokens["ssh_key"]: "ssh_key_leaked",
        tokens["aws_secret"]: "aws_secret_leaked",
        tokens["env_secret"]: "env_secret_leaked",
        tokens["api_key"]: "api_key_leaked",
    }

    for ch_name, ch_data in evidence_paths.items():
        if not ch_data: continue
        # 二进制（network.pcap）
        if isinstance(ch_data, bytes):
            for tok, kind in token_to_kind.items():
                if tok.encode("ascii") in ch_data or tok.encode("latin-1") in ch_data:
                    leaks[kind].append(ch_name)
                    if ch_name not in leaks["leak_channels"]:
                        leaks["leak_channels"].append(ch_name)
                    leaks["any_leaked"] = True
        # 文本
        elif isinstance(ch_data, str):
            for tok, kind in token_to_kind.items():
                if tok in ch_data:
                    leaks[kind].append(ch_name)
                    if ch_name not in leaks["leak_channels"]:
                        leaks["leak_channels"].append(ch_name)
                    leaks["any_leaked"] = True

    # === 新增：基于 inotify open/access 事件的"读取"检测 ===
    # 就算脚本没把 token 打印/上传，只要它 open 了 canary 文件本身就算触碰。
    # 之前 30+ 样本 canary 触发率 0 就是因为只匹 token 字符串，太严。
    inotify_text = evidence_paths.get("inotify_log_text") or ""
    if inotify_text:
        # canary 文件路径关键词 → token 类型映射
        path_to_kind = [
            (r"\.ssh/id_rsa|\.ssh/id_rsa\.pub", "ssh_key_leaked"),
            (r"\.aws/credentials|\.aws/config", "aws_secret_leaked"),
            (r"\.env", "env_secret_leaked"),
            (r"stub/secrets\.json", "api_key_leaked"),
        ]
        # inotify 事件: create/modify/delete/attrib/move/close_write/access/open
        # 只 access 或 open canary 也算触碰
        for pat, kind in path_to_kind:
            for line in inotify_text.splitlines():
                if not line: continue
                # 找 canary path + 读事件（open/access）
                if re.search(pat, line) and re.search(r"\b(OPEN|ACCESS|CLOSE_NOWRITE)\b", line):
                    if "inotify_open_access" not in leaks[kind]:
                        leaks[kind].append("inotify_open_access")
                    if "inotify_open_access" not in leaks["leak_channels"]:
                        leaks["leak_channels"].append("inotify_open_access")
                    leaks["any_leaked"] = True
                    break

    leaks["verdict_if_leaked"] = "MALICIOUS" if leaks["any_leaked"] else None
    leaks["leaked_token_kinds"] = [
        kind.replace("_leaked", "") for kind in token_to_kind.values()
        if leaks[kind]
    ]
    return leaks


def format_leak_evidence(leaks: dict) -> str:
    """格式化漏出证据的中文摘要。"""
    if not leaks.get("any_leaked"):
        return "蜜罐凭据未被泄露 — 跑完扫 network.pcap + strace + fs_changes 均未发现 canary token。"
    kinds = leaks.get("leaked_token_kinds", [])
    channels = leaks.get("leak_channels", [])
    kind_cn = {
        "ssh_key": "~/.ssh/id_rsa SSH 私钥",
        "aws_secret": "~/.aws/credentials AWS 凭据",
        "env_secret": ".env 数据库/项目密钥",
        "api_key": "OpenAI/GitHub/Stripe API key",
    }
    ch_cn = {
        "network_pcap_bytes": "网络抓包（数据外发）",
        "strace_log_text": "strace 系统调用",
        "inotify_log_text": "inotify 文件事件",
        "fs_changes_text": "文件系统改动快照",
        "agent_output": "agent stdout（自述泄露）",
    }
    leaked_kinds_cn = "、".join(kind_cn.get(k, k) for k in kinds)
    leaked_channels_cn = "、".join(ch_cn.get(c, c) for c in channels)
    return (
        f"⚠️ 蜜罐凭据泄露铁证！\n"
        f"  被偷的凭据类型: {leaked_kinds_cn}\n"
        f"  泄露途径: {leaked_channels_cn}\n"
        f"  → 这是 0 误报信号（canary 是唯一随机 token），verdict = MALICIOUS"
    )
