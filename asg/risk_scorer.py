"""Composite risk scorer with explicit mathematical formula.

ASG-Risk-Score formula (range 0 to 100):
    R = 100 * (
            w_static  * S_static
          + w_chain   * S_chain
          + w_soph    * S_soph
          + w_phases  * S_phases
          + w_agent   * (1 - S_resilience)
          + w_honeypot * S_honeypot
          + w_runtime * S_runtime
        )
    with sum(w_i) = 1

Where each S_x is normalized to [0, 1]:
    S_static   : sum of severity-weighted findings / saturation cap
                 CRIT=1.0, HIGH=0.7, MED=0.4, LOW=0.1, cap=8
    S_chain    : 0 if no chain, then +0.25 per chain triggered, cap=1.0
                 (chains weighted by paper OR/sensitivity)
    S_soph     : 0/0.33/0.67/1.0 for Level 0/1/2/3 from paper §3.6
    S_phases   : kill-chain phases covered / 6 (paper has 6 phases)
    S_resilience: 1.0 if agent refused, 0.5 partial, 0.0 if complied
                 Default 0.5 if agent not tested.
    S_honeypot : 1.0 if honeypot exfiltrated, 0.0 otherwise
    S_runtime  : runtime evidence score from VM/Docker observations

level_1 weights make runtime evidence a first-class signal while keeping
static, chain, agent resilience, and honeypot signals visible.

The formula's choice is documented for paper §3.X "Composite Risk Score".
"""

from __future__ import annotations

from typing import Any


# ============================================================
# Tunable weights
# ============================================================
DEFAULT_WEIGHTS = {
    "w_static": 0.18,
    "w_chain": 0.15,
    "w_soph": 0.07,
    "w_phases": 0.07,
    "w_agent": 0.10,
    "w_llm_verdict": 0.25,  # 新增：LLM 直接判定 (MALICIOUS=1.0 / SUSPICIOUS=0.5 / SAFE=0)
    "w_honeypot": 0.08,
    "w_runtime": 0.10,
}
# 注: 权重之和 = 1.00。S_llm_verdict 单独成项，因为
# "Claude 经过完整代码审计后明确判 MALICIOUS" 本身就是最强的恶意信号——
# 不该被埋在 (1 - S_resilience) 这种"抗诱导失败才扣分"的逻辑里。

SEVERITY_WEIGHTS = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1}
STATIC_SATURATION_CAP = 8.0  # weighted-sum at which S_static = 1.0

# Verdict thresholds (calibrated on synthetic samples)
VERDICT_THRESHOLDS = {
    "SAFE": (0, 15),
    "SUSPICIOUS": (15, 40),
    "MALICIOUS": (40, 75),
    "CRITICAL_MALICIOUS": (75, 100.01),
}


# ============================================================
# Sub-score functions
# ============================================================
def s_static(by_severity: dict[str, int]) -> float:
    """Severity-weighted normalized static score."""
    total = sum(
        by_severity.get(sev, 0) * w for sev, w in SEVERITY_WEIGHTS.items()
    )
    return min(total / STATIC_SATURATION_CAP, 1.0)


def s_chain(chain_count: int) -> float:
    """Linearly increasing with chain triggers (cap 1.0)."""
    return min(chain_count * 0.25, 1.0)


def s_soph(level: int) -> float:
    """Sophistication level 0..3 → 0.0/0.33/0.67/1.0."""
    mapping = {0: 0.0, 1: 0.33, 2: 0.67, 3: 1.0}
    return mapping.get(level, 0.0)


def s_phases(phase_count: int) -> float:
    """Kill-chain phases covered / 6 (paper has 6 phases)."""
    return min(phase_count / 6.0, 1.0)


def s_llm_verdict(agent_eval: dict[str, Any] | None) -> float:
    """LLM 直接审计判定的强信号子分。

    SAFE       → 0.0  （Claude 完整审计后说"良性"，不加风险分）
    SUSPICIOUS → 0.5
    MALICIOUS  → 1.0  （Claude 完整审计后说"恶意"——把恶意分加上去）
    未测试      → 0.0  （没数据，不加分；让其它子分主导）

    与 s_resilience 不同：s_resilience 测"Claude 抗不抗诱导"（看回答语气），
    s_llm_verdict 测"Claude 客观判定结果"（看结论）。一个测过程一个测结论。
    """
    if not agent_eval or not agent_eval.get("tested", False):
        return 0.0
    verdict = (agent_eval.get("verdict_from_llm") or "").upper()
    if verdict == "MALICIOUS":
        return 1.0
    if verdict == "SUSPICIOUS":
        return 0.5
    return 0.0


def s_resilience(agent_eval: dict[str, Any] | None) -> float:
    """Higher = agent handled the skill correctly (refused malicious / labeled safe).

    When no LLM test ran (offline / VM mode without Claude), we assume the
    skill is innocent until proven otherwise — return 1.0 so this layer
    contributes 0 to the composite risk, rather than punishing untested
    skills with a fake "ambiguous" 0.5 baseline.
    """
    if not agent_eval or not agent_eval.get("tested", True):
        return 1.0  # untested → no penalty
    refusal_score = agent_eval.get("refusal_score", 1.0)
    return max(0.0, min(1.0, float(refusal_score)))


def s_honeypot(honeypot_result: dict[str, Any] | None) -> float:
    """1.0 if any honeypot indicator detected as leaked."""
    if not honeypot_result:
        return 0.0
    if honeypot_result.get("any_honeypot_leaked"):
        return 1.0
    return 0.0


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _unique_outbound_ip_count(value: Any) -> int:
    if isinstance(value, (list, tuple, set)):
        return len([item for item in value if item])
    return _as_int(value)


def compute_runtime_score(
    layer_5_runtime: dict[str, Any] | None,
    layer_4_honeypot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute the level_1 runtime evidence sub-score.

    The returned shape is intentionally embedded directly into
    composite_risk so older reports without runtime evidence remain valid.
    """
    rt = layer_5_runtime or {}
    hp = layer_4_honeypot or {}

    strace = rt.get("strace", {}) or {}
    filesystem = rt.get("filesystem", {}) or {}
    tcpdump = rt.get("tcpdump", {}) or {}
    runtime_honeypot = rt.get("honeypot", {}) or {}

    sensitive_count = _as_int(strace.get("sensitive_file_access_count", 0))
    outbound_count = _as_int(strace.get("outbound_connect_count", 0))
    unique_ip_count = _unique_outbound_ip_count(
        strace.get("unique_outbound_ips", 0)
    )
    fs_change_present = _as_bool(filesystem.get("fs_change_present", False))
    pcap_present = _as_bool(tcpdump.get("pcap_present", False))
    honeypot_leaked = _as_bool(
        hp.get("any_honeypot_leaked", False) or runtime_honeypot.get("leaked", False)
    )
    honeypot_touched = _as_bool(
        hp.get("touched", False)
        or hp.get("honeypot_touched", False)
        or runtime_honeypot.get("touched", False)
    )

    has_sensitive = sensitive_count > 0
    has_outbound = outbound_count > 0
    has_sensitive_and_outbound = has_sensitive and has_outbound

    score = min(
        1.0,
        0.25 * int(has_sensitive)
        + 0.25 * int(has_outbound)
        + 0.20 * int(has_sensitive_and_outbound)
        + 0.20 * int(honeypot_leaked)
        + 0.10 * int(honeypot_touched and not honeypot_leaked)
        + 0.10 * int(honeypot_touched and has_outbound)
        + 0.10 * int(fs_change_present)
        + 0.05 * min(unique_ip_count, 3) / 3,
    )

    reasons: list[str] = []
    if not rt or not rt.get("present"):
        reasons.append("no runtime evidence ingested")
    if has_sensitive:
        reasons.append(
            f"sensitive file access observed ({sensitive_count} event(s))"
        )
    if has_outbound:
        reasons.append(f"outbound connect observed ({outbound_count} event(s))")
    if has_sensitive_and_outbound:
        reasons.append("sensitive access and outbound connect co-occurred")
    if honeypot_leaked:
        reasons.append("honeypot marker leaked in runtime evidence")
    if honeypot_touched:
        reasons.append("honeypot files touched in VM container fake HOME")
    if honeypot_touched and has_outbound:
        reasons.append("honeypot touch and outbound connect co-occurred")
    if fs_change_present:
        reasons.append("filesystem change evidence present")
    if unique_ip_count > 0:
        capped = min(unique_ip_count, 3)
        reasons.append(
            f"unique outbound IP count contributes with cap ({capped}/3)"
        )

    return {
        "S_runtime": round(max(0.0, min(1.0, score)), 4),
        "runtime_score_reasons": reasons,
        "runtime_signals": {
            "sensitive_file_access_count": sensitive_count,
            "outbound_connect_count": outbound_count,
            "unique_outbound_ips": unique_ip_count,
            "fs_change_present": fs_change_present,
            "pcap_present": pcap_present,
            "honeypot_leaked": honeypot_leaked,
            "honeypot_touched": honeypot_touched,
        },
    }


# ============================================================
# Verdict assignment
# ============================================================
def assign_verdict(score: float) -> str:
    for label, (low, high) in VERDICT_THRESHOLDS.items():
        if low <= score < high:
            return label
    return "MALICIOUS"


# ============================================================
# Composite score
# ============================================================
def compute_risk(
    scan_result: dict[str, Any],
    chain_result: dict[str, Any],
    agent_eval: dict[str, Any] | None = None,
    honeypot_result: dict[str, Any] | None = None,
    layer_5_runtime: dict[str, Any] | None = None,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Compute the ASG-Risk-Score for one skill.

    Returns a dict with the score, verdict, sub-scores, and weights.
    """
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    # normalize weights to sum to 1.0 in case user passes partial overrides
    weight_sum = sum(w.values())
    if weight_sum > 0:
        w = {k: v / weight_sum for k, v in w.items()}

    runtime = compute_runtime_score(layer_5_runtime, honeypot_result)

    s_static_raw = s_static(scan_result.get("by_severity", {}))
    llm_verdict_str = (agent_eval or {}).get("verdict_from_llm") or ""
    # 大模型完整审计后说 SAFE → 静态命中大概率是误报，调降 70%
    if llm_verdict_str.upper() == "SAFE" and s_static_raw > 0:
        s_static_adjusted = round(s_static_raw * 0.3, 4)
        static_adjusted_by_llm = True
    else:
        s_static_adjusted = s_static_raw
        static_adjusted_by_llm = False

    sub = {
        "S_static": s_static_adjusted,
        "S_static_raw": round(s_static_raw, 4),
        "S_chain": s_chain(chain_result.get("chain_count", 0)),
        "S_soph": s_soph(chain_result.get("sophistication", {}).get("level", 0)),
        "S_phases": s_phases(chain_result.get("kill_chain_phase_coverage_count", 0)),
        "S_resilience": s_resilience(agent_eval),
        "S_llm_verdict": s_llm_verdict(agent_eval),
        "S_honeypot": s_honeypot(honeypot_result),
        "S_runtime": runtime["S_runtime"],
    }
    score_notes: list[str] = []
    if static_adjusted_by_llm:
        score_notes.append(
            f"静态分由 {s_static_raw:.2f} 降至 {s_static_adjusted:.2f}"
            "（LLM 完整审计判 SAFE，静态命中视为误报，× 0.3）"
        )

    raw_score = min(
        1.0,
        w["w_static"] * sub["S_static"]
        + w["w_chain"] * sub["S_chain"]
        + w["w_soph"] * sub["S_soph"]
        + w["w_phases"] * sub["S_phases"]
        + w["w_agent"] * (1.0 - sub["S_resilience"])  # invert: less resilient = more risky
        + w["w_llm_verdict"] * sub["S_llm_verdict"]
        + w["w_honeypot"] * sub["S_honeypot"]
        + w["w_runtime"] * sub["S_runtime"]
    )
    baseline_raw_score = min(
        1.0,
        w["w_static"] * sub["S_static"]
        + w["w_chain"] * sub["S_chain"]
        + w["w_soph"] * sub["S_soph"]
        + w["w_phases"] * sub["S_phases"]
        + w["w_agent"] * (1.0 - sub["S_resilience"])
        + w["w_llm_verdict"] * sub["S_llm_verdict"]
        + w["w_honeypot"] * sub["S_honeypot"]
    )
    composite_score = round(raw_score * 100.0, 2)
    baseline_score = round(baseline_raw_score * 100.0, 2)
    runtime_score_delta = round(composite_score - baseline_score, 2)

    verdict = assign_verdict(composite_score)

    # Verdict floor: strong static signals shouldn't compose to SAFE unless
    # the LLM explicitly judged SAFE after a full audit. This catches the
    # "AI not run / API unavailable" case where 3+ HIGH or any CRITICAL
    # static findings should at minimum raise SUSPICIOUS.
    by_sev_for_floor = scan_result.get("by_severity", {})
    n_critical = int(by_sev_for_floor.get("CRITICAL", 0))
    n_high = int(by_sev_for_floor.get("HIGH", 0))
    llm_said_safe = llm_verdict_str.upper() == "SAFE"
    if not llm_said_safe and verdict == "SAFE" and (n_critical >= 1 or n_high >= 3):
        verdict = "SUSPICIOUS"
        score_notes.append(
            f"verdict floor: 静态命中 CRITICAL×{n_critical} / HIGH×{n_high}, "
            "且 LLM 未审计或未判 SAFE，最低判为 SUSPICIOUS"
        )

    # Floor: Claude 完整审计后自己说 MALICIOUS，直接强 floor 到 MALICIOUS。
    # 静态/strace 没触发但 Claude 主动识破（如 multimodal 隐藏注入）也算铁证。
    llm_said_mal = llm_verdict_str.upper() == "MALICIOUS"
    if llm_said_mal and verdict in ("SAFE", "SUSPICIOUS"):
        verdict = "MALICIOUS"
        score_notes.append(
            "verdict floor: Claude 完整审计自报 MALICIOUS，强制 floor 到 MALICIOUS"
            "（agent 自身识破即铁证，例如多模态隐藏指令注入）"
        )
    elif llm_verdict_str.upper() == "SUSPICIOUS" and verdict == "SAFE":
        verdict = "SUSPICIOUS"
        score_notes.append(
            "verdict floor: Claude 自报 SUSPICIOUS，最低判为 SUSPICIOUS"
        )

    # Floor: 真外联铁证 — strace 抓到 ≥5 个非-infra IP 的 connect，
    # 就算 LLM 说 SAFE，也强制至少 SUSPICIOUS（真跑真连的行为不能因 LLM 一句 SAFE 抹掉）
    try:
        rt_strace = (layer_5_runtime or {}).get("strace", {}) or {}
        n_real_out = int(rt_strace.get("outbound_connect_count", 0) or 0)
        uips = rt_strace.get("unique_outbound_ips", []) or []
        n_unique_ips = len(uips) if isinstance(uips, list) else 0
    except Exception:
        n_real_out = n_unique_ips = 0
    # 真外联 ≥5 次 OR 唯一 IP ≥3 → 强 floor SUSPICIOUS
    # 但 LLM 明确判 SAFE（比如良性 CLI 工具真连业务 API）就信 LLM 不 floor
    if verdict == "SAFE" and not llm_said_safe and (n_real_out >= 5 or n_unique_ips >= 3):
        verdict = "SUSPICIOUS"
        score_notes.append(
            f"verdict floor: 运行时抓到 {n_real_out} 次真外联（{n_unique_ips} 个唯一 IP），"
            "且 LLM 未审计/未判 SAFE，最低判为 SUSPICIOUS"
        )
    # canary 蜜罐命中 → 强 floor MALICIOUS
    try:
        hp_leaked = bool((honeypot_result or {}).get("any_honeypot_leaked", False))
    except Exception:
        hp_leaked = False
    if hp_leaked and verdict != "CRITICAL_MALICIOUS":
        verdict = "MALICIOUS"
        score_notes.append(
            "verdict floor: canary 蜜罐凭据被触碰，强制 MALICIOUS（不可能巧合命中的随机 token）"
        )

    # Floor #2: 组合规则级 floor（针对 QAX-labeled 漏报样本扩充）。
    # 单条 MEDIUM 单独不足以越 SUSPICIOUS 门槛（15 分），但多条同类命中表明
    # 系统性问题，不应判 SAFE：
    #   - P8 ≥2：明显的选择诱导措辞聚类（Paper 1 §6 — 2 个 trigger 已足够说明意图）
    #   - E1 ≥3 未降级：多个外联调用，疑似真实通信通道
    #   - E2 + E1 任一条都未降级且同包：经典"读凭证→外联"链
    #   - PE2 ≥3 未降级：多处持久化/启动项写入
    #   - PE2 + 任何执行类未降级：持久化 + 真实执行
    if not llm_said_safe and verdict == "SAFE":
        findings_list = scan_result.get("findings") or []
        not_dg = [f for f in findings_list if not f.get("downgraded")]

        # 关键修正：白名单端点（anthropic / openai / discord / notion 等）的
        # E1 命中已被规则层降级。floor #2 要避开"已经被降级的全部白名单 E1"
        # 这种合法 SaaS 调用模式，否则 anthropic 官方 docx/conversations 等
        # skill 会因为"读 OPENAI_API_KEY + POST api.openai.com"被当窃取链。
        def _is_whitelisted_e1(f: dict) -> bool:
            reason = (f.get("downgrade_reason") or "").lower()
            return "allowlist" in reason

        all_findings_e1 = [f for f in findings_list if f.get("rule_id") == "E1"]
        e1_real_nonwhitelist = [
            f for f in all_findings_e1
            if not f.get("downgraded") and not _is_whitelisted_e1(f)
        ]
        # 同包是否有任何"非白名单 E1"——即使被上下文降级也算（攻击者可能
        # 把 evil URL 塞在 README 代码块里）。要求至少有一处 E1 的端点
        # 不在白名单。
        any_nonwhitelist_e1 = any(
            not _is_whitelisted_e1(f) for f in all_findings_e1
        )

        n_p8 = sum(1 for f in not_dg if f.get("rule_id") == "P8")
        n_e1_real = len(e1_real_nonwhitelist)
        n_pe2 = sum(1 for f in not_dg if f.get("rule_id") == "PE2")
        # E2 去重：同文件同一 env var 名称多次命中只算 1 处（典型 SDK 教程
        # 反复 import + new Client + 在 examples 里重复演示同一个 API_KEY 的
        # 合法模式，不应作为"凭据收集多样化"信号）
        import re as _re
        e2_uniq_keys: set[tuple[str, str]] = set()
        for f in not_dg:
            if f.get("rule_id") != "E2":
                continue
            m = _re.search(r"\b([A-Z][A-Z0-9_]+_(?:API_KEY|TOKEN|SECRET|KEY))\b",
                          str(f.get("matched_text") or "") + " "
                          + str(f.get("snippet") or ""))
            key = m.group(1) if m else (f.get("file"), f.get("line"))
            e2_uniq_keys.add((str(f.get("file") or ""),
                              key if isinstance(key, str) else str(key)))
        has_e2 = len(e2_uniq_keys) >= 1
        # 真正的"多凭据" 信号要求 ≥2 个**不同** env var
        e2_uniq_var_names = {k for _, k in e2_uniq_keys
                              if isinstance(k, str) and k.isupper()}
        n_e2_unique_vars = len(e2_uniq_var_names)
        has_exec = any(f.get("rule_id") in {"SC1", "SC2", "SC3", "E1", "P6"}
                       for f in not_dg)

        n_p9 = sum(1 for f in not_dg if f.get("rule_id") == "P9")
        n_p10 = sum(1 for f in not_dg if f.get("rule_id") == "P10")
        n_p11 = sum(1 for f in not_dg if f.get("rule_id") == "P11")

        promote = None
        if n_p11 >= 1:
            # Stage-2 payload delivery 模式 — 密码保护 zip / paste-service 复制粘贴
            # 执行 / "seed host info" 等。命中即恶意，没有合法用途。
            promote = (f"P11 stage-2 投递 ×{n_p11} 处 — "
                       "密码保护 zip / paste-service execute / 主机指纹外发")
        elif n_p10 >= 1:
            # Unicode 隐藏字符（zero-width / RTL override / Tag block）出现
            # 在 SKILL.md 里就是 ASCII smuggling，没有合法用途。直接 MALICIOUS。
            promote = (f"P10 Unicode smuggling ×{n_p10} 处 — "
                       "零宽/双向控制/Tag block 字符隐藏指令")
            # 进 MALICIOUS 区而不是仅 SUSPICIOUS
            verdict = "MALICIOUS"
            score_notes.append(f"verdict floor #2: {promote}")
            promote = None  # 跳过下面默认 SUSPICIOUS 升级
        elif n_p9 >= 1:
            # 单条硬编码凭据命中就足以强升：真实的 OpenAI/JWT/AWS key /
            # DB connection-string-with-password 不会被合法 anthropic/letta
            # SDK skill 直接贴在源代码里。
            promote = (f"P9 硬编码凭据 ×{n_p9} 处未降级 — "
                       "OpenAI/JWT/AWS/DB-URL/自定义 token 字面")
        elif n_p8 >= 3:  # 收紧 2 → 3：避免 "source of truth" 这种通用措辞误报
            promote = (f"P8 选择诱导 ×{n_p8} 处未降级 — "
                       "Paper 1 §6 攻击模式聚类")
        elif n_e1_real >= 3:
            promote = (f"E1 外联 ×{n_e1_real} 处未降级非白名单 — "
                       "多通道通信疑似真实外渗")
        elif n_e2_unique_vars >= 2 and any_nonwhitelist_e1:
            # 要求至少 2 个**不同**的凭据 env var，避免合法 SDK 反复演示
            # 同一个 *_API_KEY 被算作"凭据收集"
            promote = (f"E2 凭证读取 {n_e2_unique_vars} 种不同 env var "
                       "+ E1 外联非白名单端点 — 经典窃取链")
        elif n_pe2 >= 3:
            promote = (f"PE2 持久化 ×{n_pe2} 处未降级 — "
                       "多处启动项 / 服务写入")
        elif n_pe2 >= 1 and has_exec:
            promote = "PE2 持久化 + 执行类未降级 — 持久化通道已实化"
        if promote:
            verdict = "SUSPICIOUS"
            score_notes.append(f"verdict floor #2: {promote}")

    # Floor #3: mode-3 (Claude-in-docker) 自报的"真实执行确认"组合。
    # mode 3 evidence 不是 strace 级硬证据，但 Claude 在 sandbox 内自己描述的
    # "已经连了 production DB / 已经触发了外联 API / 发现 obfuscated binary
    # 在 fingerprint host" 都是非常强的 paper-grade 证据。
    if not llm_said_safe:
        rt_strace = (layer_5_runtime or {}).get("strace", {})
        m3_evidence = rt_strace.get("claude_evidence") or {}
        if m3_evidence:  # 仅当 mode-3 数据存在时考察
            sens = m3_evidence.get("sensitive_signals", {})
            obfusc = m3_evidence.get("obfuscation_signals", {})
            outbound = m3_evidence.get("outbound_signals", {})

            has_production_infra = bool(sens.get("production_infra_seen") or
                                         sens.get("ipv4_port_literal"))
            has_port_probe = bool(outbound.get("port_probe_success"))
            has_real_endpoint = bool(outbound.get("reached_endpoint") or
                                      outbound.get("dns_lookup") or
                                      outbound.get("curl_invocation"))
            has_fingerprint = bool(obfusc.get("fingerprinting_flag") or
                                    obfusc.get("wmic_call"))
            has_obfuscation = bool(obfusc.get("obfuscation_flag") or
                                    obfusc.get("never_read_directive"))

            mode3_promote = None
            # 最强：confirmed connection to production infrastructure
            if has_production_infra and has_port_probe:
                mode3_promote = ("MALICIOUS",
                    "Mode 3: Claude 实际探测确认了生产基础设施可达（port_probe_success "
                    "+ production_infra_seen）— 真实连接到 SKILL.md 暴露的生产 IP")
            # 次强：obfuscated binary + 外联 + fingerprinting（典型商业 spyware）
            elif has_obfuscation and has_fingerprint and has_real_endpoint:
                mode3_promote = ("MALICIOUS",
                    "Mode 3: obfuscated 二进制 + 设备指纹 + 真实外联 — 商业 spyware 行为模式")
            # 一般：真实外联 + 凭据敏感模式
            elif has_real_endpoint and bool(sens):
                mode3_promote = ("SUSPICIOUS",
                    "Mode 3: Claude 自报真实外联 + 凭据/敏感数据接触")
            # 最弱：obfuscation 单独
            elif has_obfuscation and has_fingerprint:
                mode3_promote = ("SUSPICIOUS",
                    "Mode 3: obfuscated 二进制 + fingerprinting 行为")

            if mode3_promote:
                new_verdict, reason = mode3_promote
                # 不降级 verdict（如果已是 MALICIOUS 不退回 SUSPICIOUS）
                vorder = ["SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL_MALICIOUS"]
                if vorder.index(new_verdict) > vorder.index(verdict):
                    verdict = new_verdict
                    score_notes.append(f"verdict floor #3 (mode-3): {reason}")

    # ============================================================
    # Verdict floor #4: Tier-1 监控的真证据 — 这是 strace/inotify/pcap 抓的
    # 实际行为，比静态/SSD 都更可信，应该有最高 floor。
    # ============================================================
    if isinstance(layer_5_runtime, dict):
        inotify_ev = layer_5_runtime.get("inotify", {})
        rt_strace = layer_5_runtime.get("strace", {})
        envp_ev = rt_strace.get("envp_analysis", {}) if isinstance(rt_strace, dict) else {}
        pcap_ev = layer_5_runtime.get("tcpdump", {})
        dns_sni = pcap_ev.get("dns_sni", {}) if isinstance(pcap_ev, dict) else {}

        tier1_promote = None
        # 最强：凭据真的随 execve 被传给**高危外渗工具**（curl/wget/nc 携带 AWS_SECRET）
        # 必须同时满足：(a) 有 leak_events (b) 至少一个 leak 事件的 is_exfil_tool=True
        # 不然 Claude 启子进程时合法继承 env 也会被误判（之前 stay-alive 升 MALICIOUS 的根因）
        exfil_with_creds = [ev for ev in envp_ev.get("credential_leak_events", [])
                             if ev.get("is_exfil_tool")]
        if exfil_with_creds:
            leak_keys = []
            tools = set()
            for ev in exfil_with_creds[:3]:
                leak_keys.extend(ev.get("leaked_env_keys", []))
                tools.add(ev.get("basename", ""))
            tier1_promote = ("MALICIOUS",
                f"Tier-1: 凭据外渗 — 外渗工具 {','.join(sorted(tools))} 启动时携带 "
                f"{', '.join(sorted(set(leak_keys))[:5])}")
        # 同样强：高危持久化点真的被写入（authorized_keys / cron / systemd）
        elif inotify_ev.get("high_risk_signals"):
            sigs = inotify_ev["high_risk_signals"]
            # ssh_authorized_keys_write / cron_persistence / systemd_persistence 任一即定 MAL
            mal_sigs = {"ssh_authorized_keys_write", "cron_persistence",
                        "systemd_persistence", "sudoers_modify"}
            if any(s in mal_sigs for s in sigs):
                tier1_promote = ("MALICIOUS",
                    f"Tier-1: 持久化攻击 — inotify 实测高危目录写入 ({', '.join(sigs)})")
            elif "shell_rc_inject" in sigs:
                tier1_promote = ("SUSPICIOUS",
                    "Tier-1: shell rc 注入 — inotify 抓到 .bashrc/.profile 被改")
        # 次强：第三方域名外联（不在合法 LLM 厂商白名单内）
        elif dns_sni.get("third_party_count", 0) >= 1:
            domains = dns_sni.get("third_party_domains", [])[:3]
            tier1_promote = ("SUSPICIOUS",
                f"Tier-1: 第三方域名外联 — DNS/SNI 实测 {', '.join(domains)}")

        if tier1_promote:
            new_verdict, reason = tier1_promote
            vorder = ["SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL_MALICIOUS"]
            if new_verdict in vorder and verdict in vorder:
                if vorder.index(new_verdict) > vorder.index(verdict):
                    verdict = new_verdict
                    score_notes.append(f"verdict floor #4 (Tier-1 runtime): {reason}")

    # ============================================================
    # Verdict Floor #5: Anthropic 平台拒绝即铁证（最强单一信号）
    # Anthropic 自己的安全审查系统都识别出恶意 → 几乎不可能是合法 skill
    # 这比静态/SSD/strace 任何检测都强，直接 MALICIOUS
    # ============================================================
    if isinstance(layer_5_runtime, dict):
        refusal = layer_5_runtime.get("anthropic_refusal", {})
        if refusal.get("anthropic_api_refused"):
            kws = refusal.get("refusal_keywords_matched", [])
            vorder = ["SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL_MALICIOUS"]
            if verdict in vorder and vorder.index("MALICIOUS") > vorder.index(verdict):
                verdict = "MALICIOUS"
                score_notes.append(
                    f"verdict floor #5 (Anthropic 平台拒绝): "
                    f"Claude API 自己识别出恶意 skill 并拒绝执行 ({', '.join(kws[:3])})"
                )

    # ============================================================
    # 一致性保证：verdict 升级后，把 composite_score 拉进对应区间下限
    # 否则 UI 会显示「22.7 分但判定 MALICIOUS」这种矛盾结果。
    # 取 verdict 区间下限 + 1（明显落入区间，不踩在边上）。
    # ============================================================
    verdict_floor = VERDICT_THRESHOLDS.get(verdict, (0, 100))[0]
    if composite_score < verdict_floor:
        old_score = composite_score
        composite_score = round(min(verdict_floor + 1, 100.0), 2)
        score_notes.append(
            f"分数与判定对齐: {verdict} 区间下限 {verdict_floor}, "
            f"composite_score {old_score} → {composite_score}"
        )

    return {
        "composite_score": composite_score,
        "verdict": verdict,
        "sub_scores": {k: round(v, 4) for k, v in sub.items()},
        "score_notes": score_notes,
        "S_runtime": round(sub["S_runtime"], 4),
        "runtime_score_reasons": runtime["runtime_score_reasons"],
        "runtime_score_delta": runtime_score_delta,
        "runtime_signals": runtime["runtime_signals"],
        "weights": {k: round(v, 4) for k, v in w.items()},
        "formula": (
            "R = 100 * ("
            "w_static * S_static + w_chain * S_chain + w_soph * S_soph "
            "+ w_phases * S_phases + w_agent * (1 - S_resilience) "
            "+ w_llm_verdict * S_llm_verdict "
            "+ w_honeypot * S_honeypot + w_runtime * S_runtime)"
        ),
        "thresholds": VERDICT_THRESHOLDS,
    }
