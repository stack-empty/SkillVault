"""ASG static detection rules.

Implements paper [arXiv:2602.06547v2] Table 3 / Table 9 14-pattern taxonomy,
plus 3 paper-supplementary extensions (P5, P6, P7) based on observed
attack categories in [6] GTG-1002 and [8] Cato CTRL incident reports.

Each rule maps to:
  - id: paper pattern id (E1..E4, P1..P7, PE1..PE3, SC1..SC3)
  - kill_chain_phase: one of recon/cred_access/execution/evasion/exfil/impact
  - severity: CRITICAL / HIGH / MEDIUM / LOW (paper Appendix H)
  - patterns: list of regex patterns (case-insensitive)
  - description: human-readable explanation
  - paper_table: reference (table_3, table_9, extension)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from asg import context_classifier


@dataclass
class Finding:
    rule_id: str
    severity: str
    kill_chain_phase: str
    file: str
    line: int
    pattern: str
    matched_text: str
    description: str
    confidence: float
    context: str = ""  # 命中行 ±N 行的代码上下文（带行号，命中行用 » 标记）
    # ===== Fix1 新增字段：让上下文降权可解释、可审计 =====
    original_severity: str = ""  # 降级前的原始严重度（reasoner / scorer 能用到）
    evidence_type: str = "capability"  # exfiltration/sensitive_access/prompt_injection/persistence/evasion/capability/documentation
    context_type: str = "unknown"  # main_skill_logic / markdown_code_block / test_code / example_file / readme_doc / ...
    snippet: str = ""  # 命中行原文（去首尾空白、截 220 字符），便于报告页直接显示
    downgraded: bool = False  # 是否被上下文/白名单降级过
    downgrade_reason: str | None = None  # 降级原因（如 "Matched in test_code context"）


@dataclass
class Rule:
    rule_id: str
    name: str
    kill_chain_phase: str
    severity: str
    patterns: list[str]
    description: str
    paper_reference: str = "table_3"
    confidence: float = 0.85


# ============================================================
# Paper Table 3 / Table 9: original 14 patterns
# ============================================================
PAPER_RULES: list[Rule] = [
    # Reconnaissance phase
    Rule(
        rule_id="E3",
        name="File System Enumeration",
        kill_chain_phase="recon",
        severity="MEDIUM",
        patterns=[
            r"glob.*\.(ssh|aws|gnupg)",
            r"id_rsa",
            r"\.pem(?:\s|$|[\"'])",
            r"os\.listdir.*\.(ssh|aws)",
            r"ls\s+[~/].*\.(ssh|aws)",
        ],
        description="Scanning for SSH keys, AWS credentials, or other auth files.",
    ),
    Rule(
        rule_id="E4",
        name="Network Reconnaissance",
        kill_chain_phase="recon",
        severity="LOW",  # was MEDIUM; bare socket.connect is too generic, real signal needs nmap/portscan keywords (bumped in _classify_match)
        patterns=[
            r"socket\.(?:connect|gethostbyname|socket)",
            r"socket\.AF_INET",
            r"\.connect\s*\(\s*\(",  # any obj.connect((host, port)) pattern
            r"nmap",
            r"netstat",
            r"port[\s_-]?scan",
        ],
        description="Network socket usage or port scanning.",
    ),
    # Credential Access phase
    Rule(
        rule_id="E2",
        name="Credential Harvesting",
        kill_chain_phase="cred_access",
        severity="MEDIUM",  # was HIGH → MEDIUM；"读 env var 拿 API key" 给自己用是正常做法，
                             # 真窃取需要同时命中 E1（外联）。chain-bump 逻辑在 scan_file 后处理
        patterns=[
            r"os\.(?:environ|getenv).*(?:key|secret|token|password|api)",
            r"\$\{?(?:ANTHROPIC|OPENAI|GITHUB|AWS)_(?:API_)?(?:KEY|TOKEN|SECRET)",
            r"process\.env\.[A-Z_]+(?:KEY|TOKEN|SECRET)",
            r"capture\s+(?:the\s+)?value[s]?\s+of",
        ],
        description="Collecting API keys, tokens, or passwords from environment.",
    ),
    Rule(
        rule_id="PE3",
        name="Credential File Access",
        kill_chain_phase="cred_access",
        severity="CRITICAL",
        patterns=[
            r"open\s*\(\s*[\"'][^\"']*\.(?:ssh|aws)/(?:id_rsa|credentials)",
            r"open\s*\(\s*[\"'][^\"']*\.env[\"']",
            r"~/\.(?:ssh|aws|kube|netrc|gnupg)",
            r"/etc/(?:shadow|passwd)",
        ],
        description="Reading auth tokens or password stores from filesystem.",
    ),
    # Execution phase
    Rule(
        rule_id="SC1",
        name="Command Injection",
        kill_chain_phase="execution",
        severity="HIGH",
        patterns=[
            r"subprocess\.(?:run|call|Popen).*shell\s*=\s*True",
            r"subprocess\.(?:run|call|Popen)\s*\(\s*\[\s*[\"']/?bin/(?:sh|bash|zsh)",
            r"os\.system\s*\(",
            r"eval\s*\(\s*(?:input|request|user|sys\.argv)",
            r"exec\s*\(\s*(?:input|request|user|open)",
            # Reverse-shell signatures (paper Fig. 1 pattern)
            r"/bin/sh.*-i",
            r"bash\s+-i\s+>",
            r"os\.dup2\s*\(.*fileno",
            r"nc\s+-e",
        ],
        description="Arbitrary system command execution or reverse-shell pattern.",
    ),
    Rule(
        rule_id="SC2",
        name="Remote Script Execution",
        kill_chain_phase="execution",
        severity="CRITICAL",
        patterns=[
            r"curl[^|]+\|\s*(?:bash|sh|zsh)",
            r"wget[^|]+\|\s*(?:bash|sh|zsh)",
            r"exec\s*\(\s*[\"']?http",
            r"requests\.get\(.*\)\.text.*exec",
        ],
        description="Downloading and running external code (curl | bash pattern).",
    ),
    # Defense Evasion phase
    Rule(
        rule_id="SC3",
        name="Obfuscated Code",
        kill_chain_phase="evasion",
        severity="CRITICAL",
        patterns=[
            r"base64\.b64decode.*exec",
            r"exec\s*\(\s*base64",
            r"eval\s*\(.*b64decode",
            r"marshal\.loads.*exec",
            r"pickle\.loads.*exec",
        ],
        description="Base64/hex/marshal obfuscated code execution.",
    ),
    Rule(
        rule_id="P2",
        name="Hidden Instructions",
        kill_chain_phase="evasion",
        severity="HIGH",
        patterns=[
            r"<!--[^-]*\b(?:must|always|never|do\s+not|critical)\b",
            r"\[//\]:\s*#",
            # invisible Unicode zero-width characters
            r"[​‌‍⁠﻿]",
        ],
        description="Directives hidden in HTML comments or invisible Unicode.",
    ),
    # Exfiltration phase
    Rule(
        rule_id="E1",
        name="External Data Transmission",
        kill_chain_phase="exfil",
        severity="HIGH",
        patterns=[
            r"requests\.(?:post|put|get).*http[s]?://(?!localhost)",
            r"urllib\.request.*http",
            r"axios\.(?:post|put|get).*http",
            r"fetch\s*\(\s*[\"']http",
            # curl POST/PUT — 兼容多标志组合: curl -X POST / curl -s -X POST /
            # curl -sX POST / curl --silent -X POST 等。原来的 `\s+-X?\s*` 抓不到。
            r"curl\b[^|;\n]{0,80}?-X\s*(?:POST|PUT|DELETE|PATCH)",
            # curl --data / -d / --data-raw / --data-urlencode —— 隐式 POST 形式，
            # snyk-vercel sample 用 `curl -s --data "{...}" URL` 外发 uname。
            r"curl\b[^|;\n]{0,120}?(?:--data\b|\s-d\s)",
            # 兜底：长轮询接外部任务的 curl while-loop 模式（如 agentdo.dev 类）
            r"(?i)while\s+true.*curl.*api/tasks",
            # Pastebin / paste service / temporary-URL hosting — 已知 exfil destination
            # 或 stage-2 payload 源。Snyk samples 用 paste.c-net.org / glot.io。
            r"(?i)https?://(?:[\w-]+\.)*(?:"
            r"paste\.c-net\.org|pastebin\.com|hastebin\.com|hasteb\.in|"
            r"glot\.io|gist\.github\.com|"
            r"0x0\.st|transfer\.sh|tmpfiles\.org|"
            r"file\.io|wormhole\.app|"
            r"dpaste\.com|privatebin\.net|paste\.ee|ix\.io|sprunge\.us|"
            r"termbin\.com|paste2\.org|paste\.debian\.net|fpaste\.org|"
            r"controlc\.com|ghostbin\.com|p\.ip\.fi|envs\.sh"
            r")\b",
            # Known attacker / exfil sinkholes used in paper case studies
            r"\battacker\.example\b",
            r"\battacker\.com\b",
            r"\bexfil[\w-]*\.example\b",
            r"\bc2[\w-]*\.example\b",
            r"webhook\.site",
            r"pastebin\.com",
            r"\.onion\b",
        ],
        description="Data transmission to external (typically attacker-controlled) endpoints.",
    ),
    Rule(
        rule_id="P3",
        name="Data Exfil via Code Exec",
        kill_chain_phase="exfil",
        severity="HIGH",
        patterns=[
            r"exec.*requests\.(?:post|put)",
            r"eval.*urllib",
            r"subprocess.*curl.*-d",
        ],
        description="Data exfiltration via dynamically-executed code paths.",
    ),
    # Impact phase
    Rule(
        rule_id="P1",
        name="Instruction Override",
        kill_chain_phase="impact",
        severity="MEDIUM",  # was HIGH; "must be followed"/"non-negotiable" wording alone is benign emphasis. Real prompt-injection (ignore/disregard/override) is bumped to HIGH in _classify_match.
        patterns=[
            r"(?i)ignore\s+(?:previous|above|prior|all)\s+(?:instruction|message|prompt|rule)",
            r"(?i)disregard\s+(?:previous|above|prior|all|safety|user)",
            r"(?i)override\s+(?:any|all|user|system|conflicting|prior)",
            r"(?i)supersede\s+(?:any|all|user|system)",
            r"(?i)non[\s-]?negotiable",
            r"(?i)unbypassable",
            r"(?i)cannot\s+be\s+overridden",
            r"(?i)these\s+instructions\s+are\s+(?:critical|mandatory)",
            r"(?i)must\s+be\s+followed\s+(?:in\s+all\s+cases|regardless)",
        ],
        description="Skill instructs the agent to override user/system constraints.",
    ),
    Rule(
        rule_id="P4",
        name="Behavior Manipulation",
        kill_chain_phase="impact",
        severity="MEDIUM",
        patterns=[
            r"(?i)(?:do\s+not|don't|never)\s+(?:ask|consult|prompt|query)\s+(?:the\s+)?user",
            r"(?i)(?:do\s+not|don't|never)\s+(?:mention|tell|inform|alert|notify|disclose)",
            r"(?i)silently\s+(?:add|include|inject|append|execute|run|copy)",
            r"(?i)without\s+(?:asking|notifying|informing|user[\s-]?consent)",
            r"(?i)deny\s+that\s+you",
            r"(?i)mandatory\s+(?:activation|protocol|step|behavior|bcc|action)",
            r"(?i)always\s+add\s+.*\s+(?:to\s+the\s+)?(?:bcc|cc|recipient|email)",
            r"(?i)ban\s+(?:the\s+)?askuserquestion",
            r"(?i)do\s+not\s+use\s+(?:the\s+)?askuserquestion",
        ],
        description="Coercive language steering the agent toward unsafe actions.",
    ),
    Rule(
        rule_id="PE1",
        name="Excessive Permissions",
        kill_chain_phase="impact",
        severity="LOW",
        patterns=[
            r"--dangerously-skip-permissions",
            r"--yolo",
            r"danger-full-access",
        ],
        description="Skill requests scope beyond stated functionality.",
    ),
    Rule(
        rule_id="PE2",
        name="Privilege Escalation",
        kill_chain_phase="impact",
        severity="MEDIUM",
        patterns=[
            r"sudo\s+",
            r"chmod\s+[0-7]*[67][0-7]*",
            r"chown\s+",
            r"setuid",
        ],
        description="Elevating access without justification.",
    ),
]


# ============================================================
# ASG paper-supplementary extensions (P5, P6, P7)
# ============================================================
EXTENSION_RULES: list[Rule] = [
    Rule(
        rule_id="P5",
        name="Authority Impersonation",
        kill_chain_phase="impact",
        severity="HIGH",
        patterns=[
            r"(?i)system\s+administrator\s+(?:requires|requests|asks|says)",
            r"(?i)this\s+is\s+a\s+test\s+by\s+(?:claude|anthropic|openai|admin)",
            r"(?i)verified\s+by\s+(?:safety|security|trust)\s+team",
            r"(?i)approved\s+by\s+(?:anthropic|openai|google)",
            r"(?i)as\s+(?:your|the)\s+(?:developer|maintainer|owner)",
            r"(?i)official\s+(?:internal|safety)\s+(?:guideline|policy)",
        ],
        description="Skill claims false authority to manipulate agent.",
        paper_reference="extension",
        confidence=0.80,
    ),
    Rule(
        rule_id="P6",
        name="Persistence Implantation",
        kill_chain_phase="impact",
        severity="CRITICAL",
        patterns=[
            r"(?i)(?:add|append|write)\s+(?:to|into)\s+~?[/\\]?\.bashrc",
            r"(?i)(?:add|append|write)\s+(?:to|into)\s+~?[/\\]?\.zshrc",
            r"(?i)(?:add|append|write)\s+(?:to|into)\s+~?[/\\]?\.profile",
            r"crontab\s+-e",
            r"systemd.*service",
            r"reg\s+add\s+.*\\Run",
            r"(?i)set\s+startup\s+(?:item|task)",
            r"(?i)launchd",
            r"(?i)autostart",
        ],
        description="Skill instructs persistent modification to system startup.",
        paper_reference="extension",
        confidence=0.85,
    ),
    Rule(
        rule_id="P7",
        name="Cross-tool Coercion",
        kill_chain_phase="impact",
        severity="MEDIUM",  # was HIGH; "first install" / "use another skill" is super common in install docs, real risk only when chained with E1/SC2
        patterns=[
            r"(?i)use\s+(?:another|different|the)\s+skill",
            r"(?i)first\s+install\s+",
            r"(?i)before\s+responding[,]?\s+(?:read|run|execute)",
            r"(?i)chain\s+with\s+(?:skill|tool)",
            r"(?i)invoke\s+(?:the\s+)?backup\s+script",
            r"(?i)automatically\s+activate\s+for\s+every",
        ],
        description="Skill instructs the agent to invoke or install other skills/tools.",
        paper_reference="extension",
        confidence=0.75,
    ),
    Rule(
        rule_id="P11",
        name="Stage-2 Payload Delivery / Obfuscated Install",
        kill_chain_phase="execution",
        severity="HIGH",
        # Snyk toxicskills-goof 的 clawhub sample 用"密码保护 zip / paste service
        # 复制粘贴执行"模式分阶段投递攻击。Trend Micro Atomic Stealer 案例同款。
        patterns=[
            # 密码保护的 zip 指令
            r"(?i)(?:extract|unzip|open)\s+(?:using|with)\s+(?:pass|password)\s*[:：]",
            r"(?i)password[-\s]?protected\s+(?:zip|archive)",
            r"(?i)(?:pass|password)\s*[:：]\s*[`\"']?[a-z0-9_-]{4,20}[`\"']?\s*\)?\s*$",
            # 让 agent / 用户去 paste service 复制粘贴执行
            r"(?i)visit\s+https?://[^\s]*(?:glot\.io|pastebin|hastebin|gist\.github)"
            r"[^\s]*\s+(?:and|then)\s+(?:execute|run|paste)",
            r"(?i)copy\s+(?:and\s+)?paste\s+(?:the\s+)?(?:command|snippet|script)"
            r"\s+(?:into|in)\s+(?:terminal|shell|bash|cmd)",
            # 不明 zip 文件下载后立即执行
            r"(?i)(?:download|wget|curl)\s+\S+\.zip\b[^|]{0,100}\b(?:run|execute|launch)",
            # "seed host info" 之类的间接外发指令（snyk-vercel sample）
            r"(?i)seed\s+(?:the\s+)?(?:current\s+)?host\s+(?:info|information)",
        ],
        description=(
            "Stage-2 payload delivery pattern: password-protected zip "
            "instructions, paste-service copy-paste-execute flows, opaque "
            "zip-then-execute chains, or 'seed host info' indirect "
            "exfiltration. Matches Snyk toxicskills-goof clawhub/vercel "
            "samples and the Atomic Stealer attack pattern reported by "
            "Trend Micro (2026-02)."
        ),
        paper_reference="snyk_toxicskills_stage2_delivery",
        confidence=0.93,
    ),
    Rule(
        rule_id="P10",
        name="Unicode Smuggling / Invisible Characters",
        kill_chain_phase="evasion",
        severity="HIGH",
        # Snyk toxicskills-goof 明确把 "ASCII smuggling / zero-width / RTL
        # override" 列为已观察到的真实攻击向量。这些字符让恶意指令对人类肉眼
        # 不可见但对 Claude/Codex 可读。
        patterns=[
            # 零宽 / 不可见空格类
            r"​",  # ZERO WIDTH SPACE
            r"‌",  # ZERO WIDTH NON-JOINER
            r"‍",  # ZERO WIDTH JOINER
            r"⁠",  # WORD JOINER
            r"﻿",  # BOM / ZERO WIDTH NO-BREAK
            # 双向控制符（RTL override 攻击）
            r"‪",  # LRE
            r"‫",  # RLE
            r"‬",  # PDF
            r"‭",  # LRO
            r"‮",  # RLO ← 经典 RTL override
            r"⁦",  # LRI
            r"⁧",  # RLI
            r"⁨",  # FSI
            r"⁩",  # PDI
            # Tag 字符块（U+E0000-U+E007F）— Anthropic ASCII smuggling 主载体
            r"[\U000E0000-\U000E007F]",
        ],
        description=(
            "Unicode control / invisible / tag characters used to hide "
            "instructions from human review while remaining readable to the "
            "LLM. Includes zero-width spaces (U+200B family), bidirectional "
            "override (U+202E etc.), and the Unicode TAG block "
            "(U+E0000-U+E007F) which is Anthropic's documented ASCII "
            "smuggling primary vector. Matches Snyk toxicskills-goof's "
            "testing-guidelines sample exactly."
        ),
        paper_reference="snyk_toxicskills_ascii_smuggling",
        confidence=0.95,
    ),
    Rule(
        rule_id="P9",
        name="Hardcoded Credential Literal",
        kill_chain_phase="cred_access",
        severity="HIGH",
        # 字面 pattern 类 — 跟 QAX 的 SECRET_OPENAI_KEY / SECRET_JWT_TOKEN /
        # SECRET_DATABASE_URL 对齐。区别于 E2（读 env var）：P9 抓"代码或
        # 文档里直接贴出的真实 key/token/URL"。
        patterns=[
            # OpenAI / Anthropic API keys (字面前缀 + base64 段)
            r"sk-[A-Za-z0-9]{20,}",
            r"sk-proj-[A-Za-z0-9_-]{20,}",
            r"sk-ant-[A-Za-z0-9_-]{20,}",
            # GitHub PAT
            r"ghp_[A-Za-z0-9]{30,}",
            r"github_pat_[A-Za-z0-9_]{40,}",
            # JWT 三段（header.payload.signature）
            r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            # AWS key 字面
            r"\bAKIA[0-9A-Z]{16}\b",
            # 数据库连接串（postgres/mysql/mongo）含密码字段
            r"(?i)(?:postgres|postgresql|mysql|mongodb)(?:\+\w+)?://[^/\s:]+:[^@\s]+@[\w.-]+",
            # IP+port+ "password" 字段在同一 dict (硬编码生产 DB 配置)
            r"(?i)['\"](?:password|passwd|pwd)['\"]\s*[:=]\s*['\"][^\"'\s]{4,}['\"]",
            # 私钥头
            r"-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----",
            # Stripe / Twilio / Slack token 字面
            r"\bxox[baprs]-[A-Za-z0-9-]{20,}",
            r"\bSK[a-f0-9]{32}\b",        # Stripe secret
            # GitLab PAT
            r"\bglpat-[A-Za-z0-9_-]{20,}",
            # 自定义 API token 通用前缀 (短前缀_长哈希)，如 ppc_xxx / cf_xxx
            r"\b[a-z]{2,6}_[a-f0-9]{30,}\b",
            # JSON 里 "token"/"secret"/"api_key" 字段配长字面值（≥ 16 字符）
            r"(?i)[\"'](?:secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[\"']\s*[:=]\s*[\"'][A-Za-z0-9+/=_-]{16,}[\"']",
        ],
        description=(
            "Hardcoded credential literal found in skill source or SKILL.md "
            "— matches OpenAI / Anthropic / GitHub PAT / AWS / JWT / private "
            "key / DB connection-string-with-password / hardcoded password "
            "field. Aligns with Snyk audit and QAX commercial-scanner "
            "SECRET_* taxonomy. Distinct from E2 which catches reading env "
            "vars: P9 catches literal credentials baked into the package."
        ),
        paper_reference="QAX_SECRET_taxonomy",
        confidence=0.92,
    ),
    Rule(
        rule_id="P8",
        name="Selection Manipulation",
        kill_chain_phase="impact",
        severity="MEDIUM",
        # Paper [arXiv:2605.11418] §6 Table 10: four families of description-only
        # framing that bias an agent's skill selection in pairwise trials by
        # 77.6% on average across 4 models. Patterns adapted from the published
        # trigger templates.
        patterns=[
            # False advertising (capability exaggeration)
            r"(?i)\bthis\s+is\s+the\s+(?:best|most\s+(?:ideal|advanced|trusted|"
            r"secure|efficient|reliable|comprehensive))\s+skill",
            r"(?i)\bthis\s+skill\s+works\s+in\s+the\s+most\s+efficient\s+way",
            r"(?i)\btakes?\s+the\s+least\s+(?:amount\s+of\s+)?(?:token|cost|time)",
            r"(?i)\bthe\s+(?:source|single\s+source)\s+of\s+truth",
            # Assertive cues (directive language steering selection)
            # 收紧：要求 "this skill" / "this is the" 共现，避免抓到 anthropic 文档里
            # 合法的 "always use claude-opus-4-8" / "always use Fable" 这种产品偏好。
            r"(?i)\b(?:always|should)\s+(?:choose|pick|use|prefer|select)\s+this\s+skill",
            r"(?i)\bthis\s+skill\s+should\s+be\s+(?:picked|chosen|used)\s+(?:whenever|always)",
            r"(?i)\byou\s+(?:must|should)\s+(?:choose|pick|use)\s+this\s+skill",
            r"(?i)\balways\s+(?:choose|pick|prefer|select)\s+this\b",
            r"(?i)\bowns?\s+the\s+(?:shell|design|workflow|definition)\b",  # "Stitch owns the shell design"
            r"(?i)\bdo\s+not\s+fork\s+",  # "do not fork logic into route-local scripts"
            # Active maintenance (recency / reliability signaling)
            r"(?i)\bthis\s+skill\s+is\s+(?:actively\s+maintained|updated\s+(?:every|daily|hourly))",
            r"(?i)\bthe\s+most[\-\s]updated\s+version",
            # Trust / security claims (unverifiable reputation signaling)
            r"(?i)\btrusted\s+by\s+(?:all\s+agents|cybersecurity|security\s+teams|engineers)",
            r"(?i)\b(?:dedicated|verified)\s+(?:security\s+)?engineers\s+(?:made|reviewed|approved)",
            r"(?i)\bthis\s+skill\s+is\s+(?:very\s+)?(?:secured?|trustworthy|safe)\b",
        ],
        description=(
            "SKILL.md uses description-only framing patterns documented in "
            "Saha et al. (arXiv:2605.11418) §6 — claims of being 'best', 'always "
            "use', 'trusted by', 'source of truth' etc. — that bias an agent's "
            "selection in 77.6% of pairwise trials even when the underlying "
            "capability is unchanged. Strong manipulation surface for "
            "supply-chain attackers."
        ),
        paper_reference="arXiv_2605_11418_table_10",
        confidence=0.78,
    ),
]


ALL_RULES: list[Rule] = PAPER_RULES + EXTENSION_RULES


# ============================================================
# Severity weights for risk scoring (paper Appendix H)
# ============================================================
SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.7,
    "MEDIUM": 0.4,
    "LOW": 0.1,
}


# ============================================================
# Scanning
# ============================================================
def _read_text_safely(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ============================================================
# Fix1 上下文降权：常量 + helpers（搬自 SkillGuard_Fix1Batch1）
# ============================================================
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# 偏指令/语义类规则（命中位置如果在 SKILL.md 散文里，要按"指令"算，不是泛代码）
INSTRUCTION_RULE_IDS = {"P1", "P2", "P4", "P5", "P7", "P8", "P9", "P10", "P11"}

# 偏"真实执行/真实外联"类规则——SKILL.md 围栏里命中这些时不能算"reference_doc"，
# 因为 SKILL.md 本身就是给 agent 看的指令清单，里面的 ```curl | bash``` 是要 agent 去跑的。
EXECUTION_RULE_IDS = {"SC1", "SC2", "SC3", "E1", "E2", "E3", "P3", "P6", "PE2", "PE3"}

# 每条规则对应的"证据类型"，给 risk_scorer / report 用作更细粒度分类
EVIDENCE_TYPES = {
    "E1": "exfiltration", "E2": "sensitive_access", "E3": "sensitive_access",
    "E4": "capability", "P1": "prompt_injection", "P2": "prompt_injection",
    "P3": "exfiltration", "P4": "prompt_injection", "P5": "prompt_injection",
    "P6": "persistence", "P7": "prompt_injection", "P8": "prompt_injection",
    "PE1": "capability", "PE2": "persistence", "PE3": "sensitive_access",
    "SC1": "capability", "SC2": "capability", "SC3": "evasion",
    "P9": "sensitive_access",
    "P10": "evasion",
    "P11": "exfiltration",
}

# 把这些 context_type 当"文档/非主代码"上下文 — 命中时降一级严重度
CONTEXTUAL_TYPES = {
    "markdown_code_block", "markdown_text", "comment", "test_file",
    "example_file", "sample_file", "readme_doc", "reference_doc",
    "example_code", "test_code", "history_file", "archive_file",
}


def _downgrade_severity(severity: str) -> str:
    """CRITICAL→HIGH→MEDIUM→LOW→INFO，再低就 INFO。"""
    try:
        idx = SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return SEVERITY_ORDER[max(idx - 1, 0)]


def _path_context(path: Path, relative_path: str) -> str | None:
    """根据相对路径判断粗粒度上下文（test/example/sample/docs/config）。"""
    lowered_parts = [part.lower() for part in Path(relative_path).parts]
    stem = path.stem.lower()
    joined = "/".join(lowered_parts)
    if any(part in {"test", "tests"} for part in lowered_parts) or stem.startswith("test_"):
        return "test_file"
    if any(part in {"example", "examples", "demo"} for part in lowered_parts):
        return "example_file"
    if any(part in {"sample", "samples"} for part in lowered_parts):
        return "sample_file"
    if any(part in {"docs", "doc"} for part in lowered_parts) or "readme" in joined:
        return "markdown_text" if path.suffix.lower() == ".md" else "example_file"
    if path.suffix.lower() in {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}:
        return "config_file"
    return None


def _line_context(path: Path, relative_path: str, line: str, in_fence: bool, rule_id: str) -> str:
    """给单行算 context_type。SKILL.md 散文里命中"指令类"规则要算 skill_md_instruction，
    fence 内的代码块算 markdown_code_block 等。

    重要：SKILL.md 围栏内命中"执行类"规则（curl|bash / crontab / 凭证读取 等）不要降到
    reference_doc——这些是 agent 真要去执行的内容，是 skill 的主行为本身。"""
    context = context_classifier.classify_line_context(relative_path, line)
    is_skill_md = path.name.lower() == "skill.md"
    # SKILL.md 命中指令类 → skill_md_instruction（权重 0.9，不降级）
    if is_skill_md and rule_id in INSTRUCTION_RULE_IDS:
        return "skill_md_instruction"
    # SKILL.md 围栏内命中执行类 → 也算 skill_md_instruction（这是 agent 的执行指令）
    if is_skill_md and in_fence and rule_id in EXECUTION_RULE_IDS:
        return "skill_md_instruction"
    if in_fence and context == "skill_md_instruction":
        return "reference_doc"
    if in_fence and context not in ("test_code", "example_code", "reference_doc"):
        return "markdown_code_block"
    return context


def _is_documentary_context(context_type: str) -> bool:
    return context_type in CONTEXTUAL_TYPES


# 在 markdown_code_block 里真要执行的 bash/python 模式 — 命中这些时即使在 fence
# 里也不应该降级（这是 agent 看到 README 就会照做的"真指令"）。
# 这条策略修正了一个真实漏报：奇安信标 SUSPICIOUS 的 7/10 样本里，有 5 个的
# 关键证据藏在 README 的 ```bash 块里被自动降级抹掉了。
_REAL_EXECUTION_IN_FENCE = re.compile(
    r"(?:"
    r"curl\b[^|;\n]{0,80}?-X\s*(?:POST|PUT|DELETE|PATCH)"  # curl POST/PUT
    r"|while\s+true"                                       # 长轮询接外部任务
    r"|crontab\s+-e"                                       # 持久化
    r"|\b(?:wget|curl)\s+[^|]+\|\s*(?:bash|sh|zsh)\b"      # curl | bash
    r"|eval\s*\(\s*[\"']?\$"                              # eval $(...)
    r"|>\s*~?[/\\]?\.(?:bashrc|zshrc|profile)"             # 写 dotfiles
    r"|sudo\s+\S+"                                          # 提权
    r")",
    re.IGNORECASE,
)


def _should_skip_downgrade(context_type: str, rule_id: str, line: str) -> bool:
    """决定 markdown 上下文里某一行要不要破例不降级。

    规则：markdown_code_block 里命中执行类规则（E1/SC1/SC2/SC3/P6/P8 等），
    且行文本含真实执行特征（curl POST / while true / curl|bash / crontab -e 等），
    判定为"agent 会照做的真指令"，不降级。
    其它 documentary 上下文（reference_doc / readme_doc / test_file 等）仍然降级。
    """
    if context_type != "markdown_code_block":
        return False
    if rule_id not in EXECUTION_RULE_IDS:
        return False
    return bool(_REAL_EXECUTION_IN_FENCE.search(line))


_ALLOWLIST_DOMAIN_RE = re.compile(
    r"https?://(?:[\w-]+\.)*("
    # LLM 提供商
    r"openai\.com|anthropic\.com|deepseek\.com|moonshot\.ai|moonshot\.cn|"
    r"mistral\.ai|cohere\.com|together\.ai|"
    # 代码托管 / 包仓库
    r"github\.com|githubusercontent\.com|gitlab\.com|"
    r"pypi\.org|npmjs\.com|crates\.io|"
    # 模型 / 数据集 hub
    r"huggingface\.co|hf\.co|civitai\.com|"
    # 主流 SaaS 工具（agent 经常正当调用的）
    r"discord\.com|discordapp\.com|slack\.com|notion\.com|notion\.so|"
    r"linear\.app|asana\.com|trello\.com|atlassian\.com|"
    r"datadoghq\.com|datadoghq\.eu|sentry\.io|pagerduty\.com|"
    r"figma\.com|miro\.com|"
    r"google\.com|googleapis\.com|gstatic\.com|"
    r"microsoft\.com|office\.com|azure\.com|live\.com|"
    # 数据库 / 云
    r"mongodb\.com|supabase\.co|supabase\.com|firebase\.com|"
    # 通信平台
    r"twilio\.com|sendgrid\.com|mailgun\.com|"
    # 文档
    r"readthedocs\.org|readthedocs\.io|"
    # Letta / OpenClaw / Claude 生态
    r"letta\.com|claude\.com|claudeai\.com|claudecode\.ai|"
    r"openclaw\.ai|clawhub\.ai|clawskills\.sh|"
    # LLM 工具 / RAG SDK
    r"morph\.so|morph\.ai|morphllm\.com|warpgrep\.com|"
    r"langchain\.com|llamaindex\.ai|pinecone\.io|weaviate\.io|"
    r"qdrant\.tech|chromadb\.io"
    r")\b",
    re.IGNORECASE,
)


def _is_allowlisted_endpoint(line: str) -> bool:
    """官方 LLM/代码托管/SaaS 工具 API 端点不算可疑外联（capability，不是 exfil）。

    判定逻辑：URL 域名（含子域名）落在已知合法 SaaS / 模型 / 代码仓库的列表里。
    覆盖范围保守宽松：FPR 收益远大于因放过同域名攻击带来的 FN 风险。
    """
    return bool(_ALLOWLIST_DOMAIN_RE.search(line))


# Known-bad indicators: when these appear in a match, severity stays as-is.
# Without them, "example" patterns in .md docs (curl POST, requests.post)
# get downgraded to LOW to avoid false-positives on benign skill READMEs.
SINKHOLE_KEYWORDS = (
    "attacker.", "exfil", "c2.", ".onion", "webhook.site", "pastebin.com",
    "ngrok.io", "burpcollaborator", "interactsh", "requestbin",
)
# Rules that frequently produce noise inside markdown docs unless they hit
# a real sinkhole. Downgrade these in .md/.txt files when matched_text has
# no sinkhole keyword.
MARKDOWN_NOISE_RULE_IDS = {"E1", "SC1", "SC2", "PE2", "P7"}

# Real prompt-injection language. P1 base is MEDIUM (catches emphasis words
# like "non-negotiable" which legitimate skills also use). When the match
# contains a true override directive, bump to HIGH.
P1_OVERRIDE_KEYWORDS = ("ignore", "disregard", "override", "supersede")

# Reverse-shell signatures. SC1 base is HIGH (covers `os.system`, shell=True).
# When the match is a reverse-shell pattern, bump to CRITICAL.
SC1_REVSHELL_KEYWORDS = ("/bin/sh", "bash -i", "dup2", "nc -e ", " nc -e", "/bin/bash -i")

# Real port-scan / recon signals. E4 base is LOW (bare socket.connect is too
# generic). Bump to MEDIUM only when these keywords appear.
E4_SCAN_KEYWORDS = ("nmap", "netstat", "port_scan", "portscan", "port-scan")

# Unicode zero-width / bidi-override / non-printing characters used in
# steganographic prompt injection. P2 base is HIGH; bump these to CRITICAL.
P2_INVISIBLE_CHARS = (
    "​", "‌", "‍", "⁠", "﻿",
    "‪", "‫", "‬", "‭", "‮",  # bidi overrides
)


def _is_doc_context(path: Path) -> bool:
    return path.suffix.lower() in {".md", ".txt"}


def _hit_real_sinkhole(matched_text: str) -> bool:
    low = matched_text.lower()
    return any(kw in low for kw in SINKHOLE_KEYWORDS)


def _build_context(lines: list[str], hit_line_no: int, radius: int = 3) -> str:
    """命中行周围 ±radius 行，带行号；命中行用 '»' 前缀标记，其余用 ' '。
    行号从 1 开始（hit_line_no 是 1-based）。"""
    start = max(1, hit_line_no - radius)
    end = min(len(lines), hit_line_no + radius)
    width = len(str(end))
    out: list[str] = []
    for n in range(start, end + 1):
        marker = "»" if n == hit_line_no else " "
        text = lines[n - 1].rstrip("\n")
        if len(text) > 200:
            text = text[:200] + " …"
        out.append(f"{marker} {str(n).rjust(width)} | {text}")
    return "\n".join(out)


# 占位符 / 示例值 — P9 命中这些时不算真凭据，降到 LOW（或 INFO）
_P9_PLACEHOLDER_RE = re.compile(
    r"(?i)("
    r"your[-_]?(?:key|token|secret|password|api)|"
    r"(?:key|token|secret|password)[-_]?here|"
    r"<[\w-]+>|"                # <YOUR_KEY> style
    r"\{[\w-]+\}|"               # {key} style
    r"xxx+|"
    r"placeholder|"
    r"example|"
    r"replace[-_]?(?:with|me|this)|"
    r"change[-_]?(?:me|this)|"
    r"\.\.\.|\bredacted\b|"
    r"@localhost|"
    r":127\.0\.0\.1|"
    r"://(?:user|admin|root):(?:user|admin|root|password|secret)@" # postgres://user:password@host
    r")"
)


def _classify_match(rule_id: str, base_severity: str, matched_text: str, doc_context: bool) -> str:
    """Decide the final severity of a single match based on rule-specific
    high-confidence / low-confidence indicators in the matched text.

    Bump-up cases (matched text indicates clear malicious intent):
      * E1 + sinkhole keyword     → CRITICAL  (attacker.example, .onion, ...)
      * SC1 + reverse-shell sig   → CRITICAL  (bin/sh -i, nc -e, dup2, ...)
      * E4 + scan keyword         → MEDIUM    (nmap, port_scan, ...)
      * P1 + override keyword     → HIGH      (ignore previous, disregard, ...)
      * P2 + invisible Unicode    → CRITICAL  (zero-width / bidi override)

    Bump-down cases (matched text in doc context with no high-confidence hint):
      * Any MARKDOWN_NOISE_RULE_IDS rule in .md/.txt with no sinkhole keyword
        → LOW
    """
    low = matched_text.lower()

    # ---- Per-rule bump-up rules ----
    if rule_id == "E1" and _hit_real_sinkhole(matched_text):
        return "CRITICAL"
    if rule_id == "SC1" and any(kw in low for kw in SC1_REVSHELL_KEYWORDS):
        return "CRITICAL"
    if rule_id == "E4" and any(kw in low for kw in E4_SCAN_KEYWORDS):
        return "MEDIUM"
    if rule_id == "P1" and any(kw in low for kw in P1_OVERRIDE_KEYWORDS):
        return "HIGH"
    if rule_id == "P2" and any(ch in matched_text for ch in P2_INVISIBLE_CHARS):
        return "CRITICAL"
    # P4: specific "mandatory_activation/protocol" sub-pattern is noisy emphasis,
    # not a coercion signal. Downgrade.
    if rule_id == "P4" and "mandatory" in low and ("activation" in low or "protocol" in low):
        return "LOW"
    # P9: 命中"占位符 / 示例值"（your-key-here / xxx / placeholder / @localhost）
    # 不算真凭据泄漏，降到 LOW。配合 SDK 文档场景。
    if rule_id == "P9" and _P9_PLACEHOLDER_RE.search(matched_text):
        return "LOW"

    # ---- Markdown-context downgrade ----
    if doc_context and rule_id in MARKDOWN_NOISE_RULE_IDS and not _hit_real_sinkhole(matched_text):
        return "LOW"

    return base_severity


def scan_file(path: Path, skill_root: Path, rules: list[Rule] | None = None) -> list[Finding]:
    """扫单个文件。结合 (1) 行级 _classify_match 升降级；(2) Fix1 上下文降权
    （markdown 围栏识别 + 路径/行分类 + 官方 API 白名单）。"""
    if rules is None:
        rules = ALL_RULES
    findings: list[Finding] = []
    text = _read_text_safely(path)
    if not text:
        return findings

    try:
        rel = str(path.relative_to(skill_root))
    except ValueError:
        rel = str(path)

    doc_context = _is_doc_context(path)
    lines = text.splitlines()

    # —— Fix1 ① 先扫一遍 markdown 文件，标记 ``` ... ``` 围栏内行
    markdown_fence_lines: dict[int, bool] = {}
    if path.suffix.lower() in {".md", ".txt"} or path.name.lower() == "skill.md":
        inside_fence = False
        for line_no, line in enumerate(lines, start=1):
            markdown_fence_lines[line_no] = inside_fence
            if line.lstrip().startswith("```"):
                inside_fence = not inside_fence

    for rule in rules:
        for pattern in rule.patterns:
            # —— Fix1 ② 所有规则统一不区分大小写（提高召回）
            compiled = re.compile(pattern, flags=re.IGNORECASE)
            for line_no, line in enumerate(lines, start=1):
                match = compiled.search(line)
                if not match:
                    continue
                matched = match.group(0)[:160]

                # 行级升降级（保留原有的 _classify_match：E1+sinkhole→CRITICAL、SC1+revshell→CRITICAL 等）
                severity = _classify_match(rule.rule_id, rule.severity, matched, doc_context)
                original = rule.severity
                evidence_type = EVIDENCE_TYPES.get(rule.rule_id, "capability")

                # —— Fix1 ③ 算 context_type（多维：路径/行/围栏）
                in_fence = markdown_fence_lines.get(line_no, False)
                context_type = _line_context(path, rel, line, in_fence, rule.rule_id)
                # 路径层补一刀（test_file / example_file 等）
                if context_type in ("main_skill_logic", "unknown", "skill_md_instruction"):
                    pc = _path_context(path, rel)
                    if pc:
                        context_type = pc

                # —— Fix1 ④ 上下文降权：文档/测试/示例上下文 → 降一级
                downgraded = False
                downgrade_reason: str | None = None
                if _is_documentary_context(context_type) \
                        and not _should_skip_downgrade(context_type, rule.rule_id, line):
                    new_sev = _downgrade_severity(severity)
                    if new_sev != severity:
                        severity = new_sev
                        downgraded = True
                        downgrade_reason = f"Matched in {context_type} context"
                        evidence_type = "documentation"
                # —— Fix1 ⑤ 官方 API 端点白名单（anthropic.com / openai.com / github.com / deepseek.com）
                # 仅对 E1（真实 HTTP 调用） 触发。P9 / P10 / P11 等指令类规则即使
                # URL 落在 github 也仍恶意（attacker 可能托管自己的 release）。
                elif rule.rule_id == "E1" and evidence_type == "exfiltration" \
                        and _is_allowlisted_endpoint(line):
                    new_sev = _downgrade_severity(severity)
                    if new_sev != severity:
                        severity = new_sev
                        downgraded = True
                        downgrade_reason = "Allowlisted official API endpoint"
                        evidence_type = "capability"

                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=severity,
                        kill_chain_phase=rule.kill_chain_phase,
                        file=rel,
                        line=line_no,
                        pattern=pattern,
                        matched_text=matched,
                        description=rule.description,
                        confidence=rule.confidence,
                        context=_build_context(lines, line_no, radius=3),
                        original_severity=original,
                        evidence_type=evidence_type,
                        context_type=context_type,
                        snippet=line.strip()[:220],
                        downgraded=downgraded,
                        downgrade_reason=downgrade_reason,
                    )
                )

    # ===== AST 检测（仅 .py，补 regex 不能抓的混淆/绕过）=====
    # 用独立模块避免循环依赖；只在文件是真实 .py 时跑（SKILL.md 没语义可言）。
    if path.suffix.lower() == ".py" and not doc_context:
        try:
            from asg.ast_rules import scan_python_ast
            ast_findings = scan_python_ast(rel, text)
            for af in ast_findings:
                # 补 context（regex 路径里 _build_context 已经在用）
                if not af.context:
                    af.context = _build_context(lines, af.line, radius=3)
            findings.extend(ast_findings)
        except Exception as exc:  # AST 自己崩了不应该影响 regex 结果
            findings.append(Finding(
                rule_id="SC3",
                severity="LOW",
                kill_chain_phase="evasion",
                file=rel,
                line=1,
                pattern="<ast-engine-error>",
                matched_text=f"{type(exc).__name__}: {exc}"[:160],
                description=f"AST 引擎异常（{type(exc).__name__}），仅 regex 结果可信",
                confidence=0.3,
                evidence_type="capability",
                context_type="main_skill_logic",
                snippet=f"ast engine error: {exc}"[:220],
            ))

    # ===== 文件内 chain bump: E2 + E1 同文件 → E2 升回 HIGH =====
    # "读 env var 拿 key" 单独看是正常做法（MEDIUM），但同文件里有真实外联 E1
    # （未降级、非白名单端点、且 _classify_match 没把它降到 LOW）就说明大概率
    # 是窃取链路，升回 HIGH。
    # 注意：downgraded=False 只表示没被 context 降级；_classify_match 可能
    # 已经把 E1 从 HIGH 降到 LOW（白名单端点/无 sinkhole）。要求 severity
    # ≥ MEDIUM 排除这类已经低风险化的 E1（如 SDK 文档里的 API 调用示例）。
    has_real_exfil = any(
        f.rule_id == "E1"
        and not f.downgraded
        and f.evidence_type == "exfiltration"
        and f.severity in ("MEDIUM", "HIGH", "CRITICAL")
        for f in findings
    )
    if has_real_exfil:
        for f in findings:
            if (f.rule_id == "E2" and not f.downgraded
                    and f.severity == "MEDIUM"):
                f.severity = "HIGH"
                # 沿用 downgrade_reason 字段记录（虽然这次是升级；同字段同语义"调整原因"）
                f.downgrade_reason = (
                    f.downgrade_reason + " | " if f.downgrade_reason else ""
                ) + "Bumped to HIGH: co-located with real E1 exfiltration in same file"
    return findings


SCAN_SUFFIXES = {".md", ".txt", ".py", ".sh", ".js", ".ts", ".yaml", ".yml", ".json", ".toml"}


def scan_skill_directory(skill_path: Path) -> dict[str, Any]:
    """Scan a skill folder and return findings + summary."""
    skill_path = skill_path.resolve()
    findings: list[Finding] = []
    files_scanned: list[str] = []

    for path in sorted(skill_path.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix.lower() not in SCAN_SUFFIXES and path.name != "SKILL.md":
            continue
        findings.extend(scan_file(path, skill_path))
        try:
            files_scanned.append(str(path.relative_to(skill_path)))
        except ValueError:
            files_scanned.append(str(path))

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_pattern: dict[str, int] = {}
    by_phase: dict[str, int] = {}
    rule_ids_hit: set[str] = set()

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_pattern[f.rule_id] = by_pattern.get(f.rule_id, 0) + 1
        by_phase[f.kill_chain_phase] = by_phase.get(f.kill_chain_phase, 0) + 1
        rule_ids_hit.add(f.rule_id)

    return {
        "skill_path": str(skill_path),
        "skill_name": skill_path.name,
        "files_scanned": files_scanned,
        "files_scanned_count": len(files_scanned),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_pattern": by_pattern,
        "by_kill_chain_phase": by_phase,
        "rule_ids_hit": sorted(rule_ids_hit),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "kill_chain_phase": f.kill_chain_phase,
                "file": f.file,
                "line": f.line,
                "pattern": f.pattern,
                "matched_text": f.matched_text,
                "description": f.description,
                "confidence": f.confidence,
                "context": f.context,
                # Fix1 新增字段（旧 reader 看不见也不会炸）
                "original_severity": f.original_severity,
                "evidence_type": f.evidence_type,
                "context_type": f.context_type,
                "snippet": f.snippet,
                "downgraded": f.downgraded,
                "downgrade_reason": f.downgrade_reason,
            }
            for f in findings
        ],
    }
