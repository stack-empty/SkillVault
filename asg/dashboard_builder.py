"""Build a self-contained HTML dashboard from ASG batch results.

Writes a single static HTML file (no JS framework, no external CSS) that
visualizes:
  - Composite risk score per skill (color-coded gauge)
  - Archetype distribution
  - Attack-chain hits (paper Table 11)
  - Score formula breakdown (transparent reproducibility)
  - Layer-by-layer evidence per skill (static / chain / agent / honeypot)

Designed to be opened by double-clicking the resulting HTML.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


VERDICT_COLOR = {
    "SAFE": "#22c55e",
    "SUSPICIOUS": "#f59e0b",
    "MALICIOUS": "#ef4444",
    "CRITICAL_MALICIOUS": "#7c1d1d",
}

VERDICT_CN = {
    "SAFE": "安全",
    "SUSPICIOUS": "留意",
    "MALICIOUS": "危险",
    "CRITICAL_MALICIOUS": "严重",
}

VERDICT_ACTION_CN = {
    "SAFE": "允许使用",
    "SUSPICIOUS": "建议人工审核",
    "MALICIOUS": "拒绝安装",
    "CRITICAL_MALICIOUS": "立即隔离",
}

ARCHETYPE_COLOR = {
    "Benign": "#22c55e",
    "Partial-Risk": "#f59e0b",
    "Data Thief": "#ef4444",
    "Agent Hijacker": "#8b5cf6",
    "Hybrid": "#ec4899",
    "Platform-Native": "#06b6d4",
}

ARCHETYPE_CN = {
    "Benign": "良性",
    "Partial-Risk": "部分风险",
    "Data Thief": "数据窃取",
    "Agent Hijacker": "智能体劫持",
    "Hybrid": "混合型",
    "Platform-Native": "平台原生",
}

PHASE_CN = {
    "recon": "侦察",
    "cred_access": "凭证窃取",
    "execution": "代码执行",
    "evasion": "逃避检测",
    "exfil": "数据外传",
    "impact": "行为操控",
}

# 17 静态检测规则的中文名（rule_id 取自 asg/rules.py）
RULE_CN = {
    "E1": ("数据外传",   "exfil",       "向外部 URL（含已知 sinkhole）POST/上传数据"),
    "E2": ("凭证窃取",   "cred_access", "读环境变量中的 API_KEY / TOKEN / SECRET"),
    "E3": ("文件系统侦察", "recon",     "枚举 ~/.ssh / ~/.aws / .pem 等敏感目录"),
    "E4": ("网络侦察",   "recon",       "调用 socket / nmap / 端口扫描"),
    "P1": ("指令覆盖",   "impact",      "命令 Agent 忽略上层 / 用户指令"),
    "P2": ("隐藏指令",   "evasion",     "HTML 注释 / 零宽 Unicode 藏命令"),
    "P3": ("代码执行外传", "exfil",     "通过 exec/eval 动态执行后发数据"),
    "P4": ("行为操控",   "impact",      "命令 Agent 不告诉用户 / 静默执行"),
    "P5": ("社工话术",   "impact",      "权威/紧急/胁迫话术诱导"),
    "P6": ("条件触发",   "evasion",     "环境判断后才触发恶意分支"),
    "P7": ("供应链信号", "impact",      "提示安装不知名的第三方依赖"),
    "PE1": ("Root/特权请求", "execution", "要求 root / Administrator / sudo 提权"),
    "PE2": ("独占资源占用", "impact",   "独占网络/文件锁 / 阻断其他工具"),
    "PE3": ("凭证文件访问", "cred_access", "open(~/.ssh/id_rsa, ~/.aws/credentials, /etc/shadow)"),
    "SC1": ("命令注入/反弹shell", "execution", "subprocess shell=True / /bin/sh -i / nc -e"),
    "SC2": ("远程脚本执行", "execution", "curl | bash / wget | sh / 下载即执行"),
    "SC3": ("代码混淆",   "evasion",    "base64.b64decode + exec / pickle.loads + exec"),
}

CATEGORY_GROUPS_CN = [
    ("权限提升",   ["PE1", "PE2"]),
    ("代码执行",   ["SC1", "SC2"]),
    ("代码混淆",   ["SC3", "P2"]),
    ("凭证窃取",   ["E2", "PE3"]),
    ("数据外传",   ["E1", "P3"]),
    ("文件/网络侦察", ["E3", "E4"]),
    ("社会工程/行为操控", ["P1", "P4", "P5", "P7"]),
    ("条件触发逃避", ["P6"]),
]


def _escape(value: Any) -> str:
    return html.escape(str(value))


def _gauge_html(score: float, verdict: str) -> str:
    color = VERDICT_COLOR.get(verdict, "#888")
    pct = max(0.0, min(100.0, score))
    return f"""
    <div class="gauge">
      <div class="gauge-track">
        <div class="gauge-fill" style="width: {pct}%; background: {color};"></div>
      </div>
      <div class="gauge-label" style="color: {color};">
        {pct:.1f} <span class="verdict-tag">{_escape(verdict)}</span>
      </div>
    </div>
    """


def _bar_chart(counts: dict[str, int], color_map: dict[str, str]) -> str:
    if not counts:
        return '<div class="empty">No data</div>'
    max_v = max(counts.values()) or 1
    rows = []
    for label, value in counts.items():
        color = color_map.get(label, "#666")
        pct = (value / max_v) * 100.0
        rows.append(
            f'<div class="bar-row">'
            f'<div class="bar-label">{_escape(label)}</div>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" style="width: {pct}%; background: {color};">{value}</div>'
            f'</div></div>'
        )
    return "\n".join(rows)


def _sub_score_table(report: dict[str, Any]) -> str:
    risk = report["composite_risk"]
    sub = risk["sub_scores"]
    weights = risk["weights"]
    rows = []
    components = [
        ("S_static", "Static rule severity", weights.get("w_static", 0.25)),
        ("S_chain", "Attack chain hit", weights.get("w_chain", 0.20)),
        ("S_soph", "Sophistication level", weights.get("w_soph", 0.10)),
        ("S_phases", "Kill-chain phase coverage", weights.get("w_phases", 0.10)),
        ("S_resilience", "Agent resilience (1 - this = risk)", weights.get("w_agent", 0.25)),
        ("S_honeypot", "Honeypot exfiltrated", weights.get("w_honeypot", 0.10)),
        ("S_runtime", "Runtime evidence", weights.get("w_runtime", 0.0)),
    ]
    for key, label, weight in components:
        val = sub.get(key, 0.0)
        contribution = (1.0 - val) * weight * 100 if key == "S_resilience" else val * weight * 100
        rows.append(
            f"<tr><td>{_escape(label)}</td>"
            f"<td><code>{key}</code></td>"
            f"<td>{val:.3f}</td>"
            f"<td>{weight:.2f}</td>"
            f"<td><strong>{contribution:.2f}</strong></td></tr>"
        )
    return f"""
    <table class="formula">
      <thead><tr><th>组件</th><th>符号</th><th>子分值</th><th>权重</th><th>贡献</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _findings_table(report: dict[str, Any], limit: int = 12) -> str:
    findings = report.get("findings", [])[:limit]
    if not findings:
        return '<div class="empty">No static findings.</div>'
    rows = []
    for f in findings:
        severity_class = f.get("severity", "LOW").lower()
        rows.append(
            f"<tr>"
            f'<td><span class="sev-pill sev-{severity_class}">{_escape(f.get("severity",""))}</span></td>'
            f"<td><code>{_escape(f.get('rule_id',''))}</code></td>"
            f"<td>{_escape(f.get('kill_chain_phase',''))}</td>"
            f"<td><code>{_escape(f.get('file',''))}:{_escape(f.get('line',''))}</code></td>"
            f"<td><code class=\"snippet\">{_escape(f.get('matched_text','')[:80])}</code></td>"
            f"</tr>"
        )
    extra = ""
    if len(report.get("findings", [])) > limit:
        extra = f'<tr><td colspan="5" class="muted">... ({len(report["findings"]) - limit} more findings)</td></tr>'
    return f"""
    <table class="findings">
      <thead><tr><th>严重度</th><th>规则</th><th>阶段</th><th>位置</th><th>匹配片段</th></tr></thead>
      <tbody>{''.join(rows)}{extra}</tbody>
    </table>
    """


def _chain_pills(report: dict[str, Any]) -> str:
    chains = report["layer_2_attack_chain"]["chains_triggered"]
    if not chains:
        return '<div class="empty">未触发任何攻击链。</div>'
    pills = []
    for c in chains:
        pills.append(
            f'<div class="chain-pill">'
            f'<div class="chain-id">{_escape(c["chain_id"])}</div>'
            f'<div class="chain-name">{_escape(c["name"])}</div>'
            f'<div class="chain-evidence">{_escape(c["paper_evidence"])}</div>'
            f'</div>'
        )
    return f'<div class="chain-pills">{"".join(pills)}</div>'


def _agent_eval_panel(report: dict[str, Any]) -> str:
    ae = report["layer_3_agent_eval"]
    if not ae.get("tested"):
        reason = _escape(ae.get("skipped_reason", "未测试"))
        return f'<div class="agent-not-tested">AI 智能体层未测试 — <em>{reason}</em></div>'
    refusal = ae.get("refusal_score", 0)
    disclosure = ae.get("disclosure_score", 0)
    compliance = ae.get("compliance_signal", 0)
    return f"""
    <div class="agent-scores">
      <div class="agent-score"><span>拒绝度</span><strong>{refusal:.2f}</strong></div>
      <div class="agent-score"><span>主动揭露</span><strong>{disclosure:.2f}</strong></div>
      <div class="agent-score"><span>顺从信号</span><strong>{compliance:.2f}</strong></div>
    </div>
    <details>
      <summary>展开 Claude 完整回复</summary>
      <pre class="claude-preview">{_escape(ae.get("raw_response_preview", ""))}</pre>
    </details>
    """


def _runtime_panel(report: dict[str, Any]) -> str:
    rt = report.get("layer_5_runtime", {}) or {}
    risk = report.get("composite_risk", {}) or {}
    sub = risk.get("sub_scores", {}) or {}
    s_runtime = float(sub.get("S_runtime", risk.get("S_runtime", 0.0)) or 0.0)
    runtime_delta = float(risk.get("runtime_score_delta", 0.0) or 0.0)
    reasons = risk.get("runtime_score_reasons", []) or []
    signals = risk.get("runtime_signals", {}) or {}

    reason_html = (
        "<ul class=\"runtime-reasons\">"
        + "".join(f"<li>{_escape(reason)}</li>" for reason in reasons)
        + "</ul>"
        if reasons
        else '<div class="empty">No runtime score reasons recorded.</div>'
    )
    score_html = f"""
    <div class="runtime-score">
      <div><span>运行时风险分</span><strong>{s_runtime:.3f}</strong></div>
      <div><span>对综合分加成</span><strong class="runtime-delta">{runtime_delta:+.2f}</strong></div>
    </div>
    <div class="runtime-reason-block">
      <strong>评分原因</strong>
      {reason_html}
    </div>
    """

    if not rt.get("present"):
        return score_html + '<div class="empty">未导入 VM Docker 运行时证据。</div>'

    mode = rt.get("mode", "unknown")
    mode_color = "#22c55e" if mode == "agent_in_the_loop" else "#f59e0b"
    mode_label = (
        "B 模式: 容器内 Claude CLI 执行"
        if mode == "agent_in_the_loop"
        else "C 模式: 纯 Docker 直跑（无 LLM）"
    )

    strace = rt.get("strace", {}) or {}
    tcpdump = rt.get("tcpdump", {}) or {}
    fs = rt.get("filesystem", {}) or {}

    rows = []
    rows.append(
        f'<tr><td>strace.log 是否存在</td>'
        f'<td><strong>{"是" if strace.get("log_present") else "否"}</strong></td>'
        f'<td>{strace.get("log_size_bytes", 0):,} 字节</td></tr>'
    )
    rows.append(
        f'<tr><td>敏感文件读取次数</td>'
        f'<td><strong>{signals.get("sensitive_file_access_count", strace.get("sensitive_file_access_count", 0))}</strong></td>'
        f'<td>open(~/.ssh, .aws, .env) 等</td></tr>'
    )
    rows.append(
        f'<tr><td>对外连接尝试次数</td>'
        f'<td><strong>{signals.get("outbound_connect_count", strace.get("outbound_connect_count", 0))}</strong></td>'
        f'<td>connect() 到非本地</td></tr>'
    )
    unique_ips = strace.get("unique_outbound_ips", [])
    unique_ip_count = signals.get(
        "unique_outbound_ips",
        len(unique_ips) if isinstance(unique_ips, list) else unique_ips,
    )
    if unique_ips:
        rows.append(
            f'<tr><td>独立出站 IP 数</td>'
            f'<td><strong>{unique_ip_count}</strong></td>'
            f'<td><code>{", ".join(unique_ips[:6])}</code></td></tr>'
        )
    else:
        rows.append(
            f'<tr><td>独立出站 IP 数</td>'
            f'<td><strong>{unique_ip_count}</strong></td>'
            f'<td>评分截断到 3 个</td></tr>'
        )
    rows.append(
        f'<tr><td>tcpdump pcap 是否存在</td>'
        f'<td><strong>{"是" if signals.get("pcap_present", tcpdump.get("pcap_present")) else "否"}</strong></td>'
        f'<td>{tcpdump.get("pcap_size_bytes", 0):,} 字节</td></tr>'
    )
    rows.append(
        f'<tr><td>文件系统变更</td>'
        f'<td><strong>{"是" if signals.get("fs_change_present", fs.get("fs_change_present")) else "否"}</strong></td>'
        f'<td>fs diff 已捕获</td></tr>'
    )
    rows.append(
        f'<tr><td>蜜罐 marker 泄露</td>'
        f'<td><strong>{"是" if signals.get("honeypot_leaked", False) else "否"}</strong></td>'
        f'<td>来自 layer 4 蜜罐证据</td></tr>'
    )

    table = f"""
    <table class="findings">
      <thead><tr><th>信号</th><th>值</th><th>说明</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """

    preview = ""
    if rt.get("claude_output_present"):
        preview = (
            "<details><summary>展开 VM 容器中 Claude 完整回复</summary>"
            f"<pre class=\"claude-preview\">{_escape(rt.get('claude_output_preview', ''))}</pre>"
            "</details>"
        )

    return f"""
    {score_html}
    <div class="honeypot-status">
      运行时模式:
      <span style="background:{mode_color};color:#0f172a;padding:2px 10px;border-radius:4px;font-weight:600;">
        {mode_label}
      </span>
      &nbsp; 证据目录: <code>{_escape(rt.get('evidence_dir', ''))}</code>
    </div>
    {table}
    {preview}
    """


def _honeypot_panel(report: dict[str, Any]) -> str:
    hp = report["layer_4_honeypot"]
    if not hp.get("enabled"):
        return '<div class="empty">蜜罐未启用。</div>'
    leaked = hp.get("any_honeypot_leaked", False)
    touched = hp.get("touched", False)
    deployed = hp.get("deployed", False)
    badge = (
        '<span class="hp-leaked">已泄露</span>'
        if leaked
        else '<span class="hp-clean">未泄露</span>'
    )
    touch_badge = (
        '<span class="hp-touch">已触碰</span>'
        if touched
        else '<span class="hp-clean">未触碰</span>'
    )
    deploy_badge = (
        '<span class="hp-touch">已部署</span>'
        if deployed
        else '<span class="hp-clean">未部署</span>'
    )
    bundle = hp.get("bundle", {}) or {}
    bundle_id = hp.get("bundle_id") or bundle.get("bundle_id", "?")
    files_created = hp.get("files_created") or bundle.get("files", [])
    redacted_preview = hp.get("redacted_preview") or bundle.get("redacted_preview", {})
    leak_sources = hp.get("leak_sources", [])
    touched_files = hp.get("touched_files", [])
    preview_rows = "".join(
        f"<tr><td>{_escape(k)}</td><td><code>{_escape(v)}</code></td></tr>"
        for k, v in sorted(redacted_preview.items())
    )
    if not preview_rows:
        preview_rows = '<tr><td colspan="2" class="muted">No redacted preview.</td></tr>'
    source_html = (
        "<ul class=\"runtime-reasons\">"
        + "".join(f"<li><code>{_escape(src)}</code></li>" for src in leak_sources)
        + "</ul>"
        if leak_sources
        else '<div class="empty">No leak sources.</div>'
    )
    touched_html = (
        "<ul class=\"runtime-reasons\">"
        + "".join(f"<li><code>{_escape(src)}</code></li>" for src in touched_files)
        + "</ul>"
        if touched_files
        else '<div class="empty">No touched honeypot files.</div>'
    )
    risk_note = (
        '<div class="runtime-risk-note">Runtime score increased because honeypot marker leaked from VM evidence.</div>'
        if leaked
        else ""
    )
    return f"""
    <div class="honeypot-status">部署: {deploy_badge} · 触碰: {touch_badge} · 泄露: {badge}</div>
    <table class="findings">
      <tbody>
        <tr><td>部署方式</td><td><code>{_escape(hp.get("deployment_mode", "未知"))}</code></td></tr>
        <tr><td>蜜罐 bundle ID</td><td><code>{_escape(bundle_id)}</code></td></tr>
        <tr><td>生成假凭证文件数</td><td>{len(files_created)}</td></tr>
        <tr><td>canary marker 数</td><td>{_escape(hp.get("marker_count", 0))}</td></tr>
      </tbody>
    </table>
    <details>
      <summary>展开假凭证 marker（已脱敏）</summary>
      <table class="findings"><tbody>{preview_rows}</tbody></table>
    </details>
    <details>
      <summary>展开被触碰的蜜罐文件</summary>
      {touched_html}
    </details>
    <details>
      <summary>展开泄露源头</summary>
      {source_html}
    </details>
    {risk_note}
    """


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _contents_panel(report: dict[str, Any]) -> str:
    contents = report.get("skill_contents") or {}
    files = contents.get("files") or []
    if not files:
        return ""
    file_blocks = []
    for f in files:
        path = f.get("path", "")
        size = f.get("size_bytes", 0)
        kind = f.get("kind", "")
        preview = f.get("content_preview", "")
        trunc = f.get("content_truncated", False)
        header = (
            f'<code>{_escape(path)}</code> '
            f'<span class="muted">({_human_bytes(size)}, {_escape(kind)})</span>'
        )
        if kind == "text" and preview:
            body = f'<pre class="claude-preview file-preview">{_escape(preview)}</pre>'
            if trunc:
                body += '<div class="muted">…(content truncated)</div>'
            block = (
                f'<details open><summary>{header}</summary>{body}</details>'
                if path == "SKILL.md"
                else f'<details><summary>{header}</summary>{body}</details>'
            )
        else:
            block = f'<div class="file-row">{header} <span class="muted">— binary, no preview</span></div>'
        file_blocks.append(block)
    if contents.get("files_truncated"):
        file_blocks.append('<div class="muted">… (file list truncated at limit)</div>')
    total = _human_bytes(contents.get("total_bytes", 0))
    count = contents.get("file_count", 0)
    return f"""
    <section>
      <h4>Skill Contents — what was scanned ({count} file{'s' if count != 1 else ''}, {total})</h4>
      <div class="file-list">{''.join(file_blocks)}</div>
    </section>
    """


def _risk_category_cards(report: dict[str, Any]) -> str:
    """SAFESKILL-style 风险类别统计大卡片（按大类聚合命中规则数）。"""
    findings = report.get("findings", []) or []
    rule_hits: dict[str, int] = {}
    for f in findings:
        rid = f.get("rule_id", "")
        rule_hits[rid] = rule_hits.get(rid, 0) + 1
    cards = []
    for group_name, rule_ids in CATEGORY_GROUPS_CN:
        hits = sum(rule_hits.get(rid, 0) for rid in rule_ids)
        severity_cls = "card-critical" if hits else "card-clean"
        badge = f'<span class="card-badge bad">严重</span>' if hits else '<span class="card-badge ok">未检出</span>'
        cards.append(
            f'<article class="risk-cat-card {severity_cls}">'
            f'  <div class="card-title">{_escape(group_name)}</div>'
            f'  <div class="card-count">{hits}<span class="card-unit"> 项</span></div>'
            f'  {badge}'
            f'</article>'
        )
    return f'<div class="risk-cat-grid">{"".join(cards)}</div>'


def _detection_grid(report: dict[str, Any]) -> str:
    """SAFESKILL-style 17 项细分检测网格。"""
    findings = report.get("findings", []) or []
    rule_hits: dict[str, int] = {}
    for f in findings:
        rid = f.get("rule_id", "")
        rule_hits[rid] = rule_hits.get(rid, 0) + 1
    cells = []
    for rid, (cn_name, phase, _desc) in RULE_CN.items():
        n = rule_hits.get(rid, 0)
        if n > 0:
            cls = "det-hit"
            badge = f'<span class="det-badge bad">严重 · {n}</span>'
        else:
            cls = "det-miss"
            badge = '<span class="det-badge ok">未检出</span>'
        cells.append(
            f'<div class="det-cell {cls}" title="{_escape(_desc)}">'
            f'  <div class="det-name">{_escape(cn_name)}</div>'
            f'  <div class="det-meta"><code>{rid}</code> · {_escape(PHASE_CN.get(phase, phase))}</div>'
            f'  {badge}'
            f'</div>'
        )
    return f'<div class="det-grid">{"".join(cells)}</div>'


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_CN = {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危"}
SEVERITY_BADGE_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#64748b",
}


def _ai_summary_block(report: dict[str, Any]) -> str:
    """AI 中文研判简介 + 分级风险列表（SAFESKILL 风格）。"""
    ae = report.get("layer_3_agent_eval", {}) or {}
    if not ae.get("tested"):
        return (
            '<div class="ai-summary skipped">'
            '<div class="ai-summary-title">AI 研判描述</div>'
            '<div class="ai-summary-body">未调用 LLM 进行研判（'
            f'{_escape(ae.get("skipped_reason", "未触发"))}）。'
            '</div></div>'
        )
    model = ae.get("model", "claude")
    verdict_llm = ae.get("verdict_from_llm") or "?"
    refusal = ae.get("refusal_score", 0)
    da = ae.get("detailed_audit") or {}
    summary_cn = da.get("summary_cn", "")
    risks = da.get("risks", []) or []
    if not summary_cn:
        # 退化：用 raw response 前 500 字
        preview = ae.get("raw_response_preview", "") or ""
        summary_cn = preview[:500] + ("…" if len(preview) > 500 else "")

    # 头部摘要
    out = [
        '<div class="ai-summary">',
        '<div class="ai-summary-title">AI 研判描述 ',
        f'<span class="ai-meta">模型 {_escape(model)} · LLM判 {_escape(verdict_llm)} · 拒绝度 {refusal:.2f}</span>',
        '</div>',
        f'<div class="ai-summary-body">{_escape(summary_cn)}</div>',
        '</div>',
    ]

    if not risks:
        return "".join(out)

    # 风险评估区（按 severity 排序）
    risks_sorted = sorted(risks, key=lambda r: (SEVERITY_ORDER.get(r.get("severity", "LOW"), 99), r.get("file", "")))

    # 按 category 分组
    from collections import defaultdict
    by_category: dict[str, list[dict]] = defaultdict(list)
    for r in risks_sorted:
        by_category[r.get("category", "其他")].append(r)

    out.append('<div class="llm-risk-section">')
    out.append('<div class="llm-risk-header">')
    out.append('<div><span class="llm-risk-title">风险评估</span> '
               '<span class="llm-risk-subtitle">RISK ASSESSMENT</span></div>')
    out.append(f'<div class="llm-risk-count">{len(risks_sorted)} ISSUES</div>')
    out.append('</div>')

    for cat_name, items in by_category.items():
        # 组级 severity 取最高
        max_sev = min(SEVERITY_ORDER.get(r.get("severity", "LOW"), 99) for r in items)
        sev_label = next((k for k, v in SEVERITY_ORDER.items() if v == max_sev), "LOW")
        sev_cn = SEVERITY_CN.get(sev_label, sev_label)
        sev_color = SEVERITY_BADGE_COLOR.get(sev_label, "#666")
        out.append(f'<details open class="llm-risk-cat" style="border-left:3px solid {sev_color};">')
        out.append(f'<summary><span class="llm-cat-name">{_escape(cat_name)}</span>'
                   f'<span class="llm-cat-badge" style="background:{sev_color};">{sev_cn}</span>'
                   f'<span class="llm-cat-count">{len(items)} 项</span></summary>')
        for i, r in enumerate(items, 1):
            sev = r.get("severity", "LOW")
            sev_c = SEVERITY_BADGE_COLOR.get(sev, "#666")
            sev_label_cn = SEVERITY_CN.get(sev, sev)
            file_loc = r.get("file", "")
            line = r.get("line", 0)
            loc_str = f"{file_loc}:{line}" if line else file_loc
            out.append('<div class="llm-risk-item">')
            out.append('<div class="llm-risk-item-head">')
            out.append(f'<span class="llm-risk-num">#{i}</span>')
            out.append(f'<span class="llm-risk-sev" style="background:{sev_c};">{sev_label_cn}</span>')
            out.append(f'<span class="llm-risk-title-text">{_escape(r.get("title", ""))}</span>')
            out.append('<span class="llm-risk-flag">大模型检出</span>')
            out.append('</div>')
            if loc_str:
                out.append(f'<div class="llm-risk-loc"><code>{_escape(loc_str)}</code></div>')
            if r.get("code_snippet"):
                out.append(f'<pre class="llm-risk-code">{_escape(r["code_snippet"])}</pre>')
            if r.get("description"):
                out.append(f'<div class="llm-risk-desc">{_escape(r["description"])}</div>')
            if r.get("recommendation"):
                out.append('<div class="llm-risk-fix">')
                out.append('<span class="llm-risk-fix-label">修复建议:</span> ')
                out.append(_escape(r["recommendation"]))
                out.append('</div>')
            out.append('</div>')
        out.append('</details>')

    out.append('</div>')
    return "".join(out)


def _meta_chips(report: dict[str, Any]) -> str:
    """skill metadata chips（分类、复杂度、扫描时间）。"""
    archetype = report["layer_2_attack_chain"]["archetype"]["archetype"]
    archetype_cn = ARCHETYPE_CN.get(archetype, archetype)
    archetype_color = ARCHETYPE_COLOR.get(archetype, "#666")
    soph = report["layer_2_attack_chain"]["sophistication"]
    gen = report.get("generated_at_utc", "")[:19].replace("T", " ")
    contents = report.get("skill_contents", {}) or {}
    fc = contents.get("file_count", 0)
    tb = _human_bytes(contents.get("total_bytes", 0))
    return (
        '<div class="meta-chips">'
        f'  <span class="chip chip-archetype" style="background:{archetype_color};">分类: {_escape(archetype_cn)}</span>'
        f'  <span class="chip">复杂度: L{soph["level"]} · {_escape(soph["label"])}</span>'
        f'  <span class="chip">文件: {fc} · {tb}</span>'
        f'  <span class="chip">扫描: {_escape(gen)}</span>'
        '</div>'
    )


def _skill_card(report: dict[str, Any]) -> str:
    name = report["skill_name"]
    risk = report["composite_risk"]
    verdict = risk["verdict"]
    verdict_cn = VERDICT_CN.get(verdict, verdict)
    verdict_color = VERDICT_COLOR.get(verdict, "#888")
    action_cn = VERDICT_ACTION_CN.get(verdict, "审核")
    static_count = report["layer_1_static_scan"]["total_findings"]
    return f"""
    <article class="skill-card" id="skill-{_escape(name)}">
      <header class="card-hero">
        <div class="hero-left">
          <h2 class="skill-title">{_escape(name)}</h2>
          {_meta_chips(report)}
        </div>
        <div class="hero-right">
          <div class="verdict-big" style="border-color:{verdict_color};color:{verdict_color};">
            <span class="verdict-label">{_escape(verdict_cn)}</span>
            <span class="verdict-en">{_escape(verdict)}</span>
          </div>
          <div class="action-hint">处置建议: <strong style="color:{verdict_color};">{_escape(action_cn)}</strong></div>
        </div>
      </header>

      <div class="score-strip">
        <div class="score-num" style="color:{verdict_color};">{risk["composite_score"]:.1f}<span class="score-max">/100</span></div>
        <div class="score-bar"><div class="score-fill" style="width:{max(0,min(100,risk['composite_score']))}%;background:{verdict_color};"></div></div>
        <div class="score-cap">综合风险评分</div>
      </div>

      {_ai_summary_block(report)}

      <section class="card-section">
        <h3 class="cn-title">风险类别统计 <span class="cn-sub">按参考文献 kill-chain 阶段聚合</span></h3>
        {_risk_category_cards(report)}
      </section>

      <section class="card-section">
        <h3 class="cn-title">细分检测项 <span class="cn-sub">共 17 条静态规则</span></h3>
        {_detection_grid(report)}
      </section>

      <section class="card-section">
        <h3 class="cn-title">命中详情 <span class="cn-sub">共 {static_count} 条</span></h3>
        {_findings_table(report)}
      </section>

      <section class="card-section">
        <h3 class="cn-title">攻击链分析 <span class="cn-sub">Table 11</span></h3>
        {_chain_pills(report)}
      </section>

      <section class="card-section">
        <h3 class="cn-title">蜜罐检测</h3>
        {_honeypot_panel(report)}
      </section>

      <section class="card-section">
        <h3 class="cn-title">动态运行时证据 <span class="cn-sub">VM Docker · strace · tcpdump</span></h3>
        {_runtime_panel(report)}
      </section>

      <section class="card-section">
        <h3 class="cn-title">目录结构 <span class="cn-sub">展开查看每个文件内容</span></h3>
        {_contents_panel(report)}
      </section>

      <details class="formula-details">
        <summary>综合评分公式明细（点开查看 7 个子分的加权计算）</summary>
        {_sub_score_table(report)}
      </details>
    </article>
    """


CSS = """
* { box-sizing: border-box; }
body {
  font-family: "PingFang SC", "Microsoft YaHei", -apple-system, "Segoe UI", system-ui, sans-serif;
  margin: 0;
  background: #07101f;
  color: #e2e8f0;
  line-height: 1.6;
}
header.topbar {
  background: linear-gradient(135deg, #0b1729 0%, #122544 50%, #0b1729 100%);
  padding: 32px 48px;
  border-bottom: 1px solid #1e3354;
  position: relative;
}
header.topbar::after {
  content: ""; position: absolute; bottom: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, #38bdf8, transparent);
}
header.topbar h1 {
  margin: 0;
  font-size: 32px;
  color: #f8fafc;
  letter-spacing: 1px;
}
header.topbar .subtitle {
  color: #64748b;
  margin-top: 10px;
  font-size: 13px;
}
.eyebrow {
  color: #38bdf8;
  letter-spacing: 2px;
  font-size: 11px;
  margin-bottom: 4px;
}
main { padding: 32px 48px; max-width: 1480px; margin: 0 auto; }
.section-title {
  font-size: 22px; margin: 32px 0 16px; color: #f8fafc;
  padding-left: 14px; border-left: 4px solid #38bdf8;
  display: flex; align-items: center; gap: 12px;
}
.section-title .section-sub { color: #64748b; font-size: 13px; font-weight: 400; }
.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.summary-card {
  background: #0e1a2f;
  padding: 20px 24px;
  border-radius: 12px;
  border: 1px solid #1e3354;
  transition: transform 0.15s;
}
.summary-card:hover { transform: translateY(-2px); border-color: #38bdf8; }
.summary-card span { display: block; color: #64748b; font-size: 12px; margin-bottom: 6px; }
.summary-card strong { font-size: 32px; color: #f8fafc; font-weight: 700; }
.summary-card.v-safe strong { color: #22c55e; }
.summary-card.v-susp strong { color: #f59e0b; }
.summary-card.v-mal strong { color: #ef4444; }
.panel {
  background: #0e1a2f;
  padding: 24px;
  border-radius: 12px;
  border: 1px solid #1e3354;
  margin-bottom: 20px;
}
.panel h2 { margin-top: 0; color: #f1f5f9; font-size: 16px; }
.bar-row { display: flex; align-items: center; margin-bottom: 8px; }
.bar-label { width: 160px; font-size: 13px; color: #cbd5e1; }
.bar-track { flex: 1; background: #07101f; height: 24px; border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; color: white; text-align: right; padding-right: 8px; font-size: 12px; line-height: 24px; min-width: 32px; font-weight: 600; }
.skills-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 24px;
}
.skill-card {
  background: linear-gradient(180deg, #0e1a2f 0%, #0a1424 100%);
  padding: 0;
  border-radius: 14px;
  border: 1px solid #1e3354;
  overflow: hidden;
}
.card-hero {
  padding: 28px 32px;
  background: linear-gradient(135deg, #0e1a2f, #122846);
  border-bottom: 1px solid #1e3354;
  display: flex; gap: 24px; align-items: flex-start; flex-wrap: wrap;
}
.hero-left { flex: 1; min-width: 320px; }
.hero-right { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; }
.skill-title { margin: 0 0 12px 0; font-size: 24px; color: #f8fafc; font-weight: 600; word-break: break-all; }
.meta-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { padding: 4px 10px; border-radius: 4px; font-size: 12px; background: #1a2944; color: #cbd5e1; border: 1px solid #1e3354; }
.chip-archetype { color: white; font-weight: 600; border: none; }
.verdict-big {
  border: 2px solid; border-radius: 8px;
  padding: 10px 24px; text-align: center; min-width: 140px;
}
.verdict-label { display: block; font-size: 24px; font-weight: 700; letter-spacing: 2px; }
.verdict-en { display: block; font-size: 11px; opacity: 0.7; letter-spacing: 1px; margin-top: 2px; }
.action-hint { font-size: 13px; color: #94a3b8; }
.score-strip {
  padding: 16px 32px; background: #07101f;
  display: flex; align-items: center; gap: 20px; border-bottom: 1px solid #1e3354;
}
.score-num { font-size: 36px; font-weight: 700; min-width: 130px; }
.score-max { font-size: 14px; color: #64748b; font-weight: 400; }
.score-bar { flex: 1; height: 8px; background: #1a2944; border-radius: 4px; overflow: hidden; }
.score-fill { height: 100%; transition: width 0.4s; }
.score-cap { font-size: 13px; color: #94a3b8; min-width: 110px; text-align: right; }
.card-section { padding: 20px 32px; border-bottom: 1px solid #142342; }
.card-section:last-of-type { border-bottom: none; }
.cn-title { font-size: 17px; color: #f1f5f9; margin: 0 0 14px 0; font-weight: 600; }
.cn-sub { color: #64748b; font-size: 12px; font-weight: 400; margin-left: 8px; }
.formula-details { padding: 16px 32px 24px; }
.formula-details summary { color: #64748b; font-size: 13px; }
.ai-summary {
  margin: 16px 32px; padding: 18px 22px;
  background: rgba(56, 189, 248, 0.06); border-left: 3px solid #38bdf8; border-radius: 6px;
}
.ai-summary.skipped { background: rgba(100,116,139,0.08); border-left-color: #64748b; }
.ai-summary-title { color: #38bdf8; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
.ai-summary.skipped .ai-summary-title { color: #94a3b8; }
.ai-summary-body { color: #cbd5e1; font-size: 13px; line-height: 1.7; white-space: pre-wrap; }
.ai-meta { color: #64748b; font-weight: 400; font-size: 12px; margin-left: 8px; }
.risk-cat-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px;
}
.risk-cat-card {
  background: #07101f; padding: 16px; border-radius: 8px; border: 1px solid #1e3354; position: relative;
}
.risk-cat-card.card-critical { border-color: #ef4444; background: rgba(239,68,68,0.08); }
.risk-cat-card.card-clean { border-color: #1e3354; }
.card-title { color: #cbd5e1; font-size: 13px; margin-bottom: 8px; }
.card-count { font-size: 28px; font-weight: 700; color: #f8fafc; }
.card-critical .card-count { color: #ef4444; }
.card-unit { font-size: 12px; color: #64748b; margin-left: 4px; font-weight: 400; }
.card-badge {
  position: absolute; top: 12px; right: 12px;
  padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 600;
}
.card-badge.bad { background: #ef4444; color: white; }
.card-badge.ok { background: rgba(34,197,94,0.15); color: #22c55e; }
.det-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px;
}
.det-cell {
  background: #07101f; padding: 12px; border-radius: 6px; border: 1px solid #1e3354;
  display: flex; flex-direction: column; gap: 6px;
}
.det-cell.det-hit { border-color: #ef4444; background: rgba(239,68,68,0.08); }
.det-name { color: #f1f5f9; font-size: 13px; font-weight: 600; }
.det-hit .det-name { color: #fca5a5; }
.det-meta { color: #64748b; font-size: 11px; }
.det-meta code { background: transparent; color: #94a3b8; padding: 0; }
.det-badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; align-self: flex-start; font-weight: 600; }
.det-badge.bad { background: #ef4444; color: white; }
.det-badge.ok { background: rgba(34,197,94,0.15); color: #22c55e; }
.gauge { margin: 8px 0 16px; }
.gauge-track { height: 12px; background: #0f172a; border-radius: 6px; overflow: hidden; }
.gauge-fill { height: 100%; transition: width 0.4s; }
.gauge-label { margin-top: 4px; font-size: 22px; font-weight: 700; }
.verdict-tag { font-size: 12px; padding: 2px 8px; border-radius: 4px; background: rgba(255,255,255,0.08); margin-left: 6px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; color: #94a3b8; font-weight: 500; padding: 6px 8px; border-bottom: 1px solid #334155; }
td { padding: 6px 8px; border-bottom: 1px solid #1e293b; vertical-align: top; }
.sev-pill { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; color: white; }
.sev-critical { background: #ef4444; }
.sev-high     { background: #f97316; }
.sev-medium   { background: #f59e0b; }
.sev-low      { background: #64748b; }
.snippet { font-size: 11px; color: #94a3b8; }
.chain-pills { display: flex; flex-direction: column; gap: 8px; }
.chain-pill { background: #0f172a; padding: 10px; border-radius: 6px; border-left: 3px solid #38bdf8; }
.chain-id { font-family: monospace; font-size: 12px; color: #38bdf8; }
.chain-name { font-weight: 600; color: #f1f5f9; margin-top: 2px; }
.chain-evidence { color: #94a3b8; font-size: 11px; margin-top: 2px; }
.agent-not-tested { color: #94a3b8; font-style: italic; padding: 8px; background: #0f172a; border-radius: 4px; }
.agent-scores { display: flex; gap: 12px; margin-bottom: 8px; }
.agent-score { background: #0f172a; padding: 8px 12px; border-radius: 6px; flex: 1; text-align: center; }
.agent-score span { display: block; color: #94a3b8; font-size: 11px; }
.agent-score strong { font-size: 20px; color: #f8fafc; }
.runtime-score { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 10px; }
.runtime-score div { background: #0f172a; padding: 10px 12px; border-radius: 6px; text-align: center; border: 1px solid #334155; }
.runtime-score span { display: block; color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
.runtime-score strong { font-size: 20px; color: #38bdf8; }
.runtime-score .runtime-delta { color: #f59e0b; }
.runtime-reason-block { background: #0f172a; padding: 10px 12px; border-radius: 6px; margin-bottom: 10px; }
.runtime-reasons { margin: 6px 0 0; padding-left: 18px; color: #cbd5e1; font-size: 12px; }
.runtime-reasons li { margin: 2px 0; }
.claude-preview {
  background: #0f172a; padding: 12px; border-radius: 4px;
  font-size: 11px; color: #cbd5e1;
  max-height: 180px; overflow-y: auto; white-space: pre-wrap;
}
.honeypot-status { font-size: 13px; }
.hp-leaked { background: #ef4444; color: white; padding: 2px 10px; border-radius: 4px; font-weight: 600; }
.hp-clean { background: #22c55e; color: white; padding: 2px 10px; border-radius: 4px; font-weight: 600; }
.hp-touch { background: #f59e0b; color: #0f172a; padding: 2px 10px; border-radius: 4px; font-weight: 600; }
.runtime-risk-note { background: #451a03; color: #fed7aa; padding: 8px 10px; border-radius: 6px; margin-top: 8px; font-size: 12px; }
.empty { color: #64748b; font-style: italic; padding: 8px 0; }
.muted { color: #64748b; }
.formula { background: #0f172a; padding: 8px; border-radius: 4px; }
.formula td { font-size: 12px; }
.formula code { color: #38bdf8; }
details { margin: 8px 0; }
summary { cursor: pointer; padding: 8px 0; color: #94a3b8; font-size: 13px; }
summary:hover { color: #38bdf8; }
section { margin: 12px 0; }
section h4 { margin: 8px 0; color: #cbd5e1; font-size: 14px; }
code { background: #0f172a; padding: 2px 4px; border-radius: 3px; font-size: 12px; }
.footer { text-align: center; padding: 32px; color: #64748b; font-size: 12px; }
.formula-box { background: #0f172a; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 13px; color: #38bdf8; border-left: 3px solid #38bdf8; }
.file-list { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
.file-list details { background: #0f172a; padding: 6px 10px; border-radius: 6px; border: 1px solid #1e293b; }
.file-list summary { cursor: pointer; padding: 4px 0; color: #cbd5e1; font-size: 13px; }
.file-list summary:hover { color: #38bdf8; }
.file-row { background: #0f172a; padding: 8px 10px; border-radius: 6px; border: 1px solid #1e293b; color: #cbd5e1; font-size: 13px; }
.file-preview { max-height: 360px; overflow-y: auto; }

/* === SAFESKILL-style 改造 === */
.card-hero { display: flex; gap: 24px; align-items: flex-start; padding-bottom: 16px; border-bottom: 1px solid #334155; margin-bottom: 16px; }
.hero-left { flex: 1; min-width: 0; }
.hero-right { text-align: right; flex-shrink: 0; }
.skill-title { font-size: 22px; color: #f1f5f9; margin: 0 0 10px; word-break: break-all; }
.meta-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { background: #334155; color: #e2e8f0; padding: 3px 10px; border-radius: 999px; font-size: 11px; }
.chip-archetype { color: #0f172a; font-weight: 600; }
.verdict-big { border: 2px solid; border-radius: 10px; padding: 10px 18px; font-weight: 700; display: inline-flex; flex-direction: column; align-items: center; min-width: 100px; }
.verdict-label { font-size: 22px; letter-spacing: 2px; }
.verdict-en { font-size: 10px; opacity: 0.7; margin-top: 2px; letter-spacing: 1px; }
.action-hint { margin-top: 8px; font-size: 12px; color: #94a3b8; }
.score-strip { display: flex; align-items: center; gap: 16px; margin-bottom: 18px; }
.score-num { font-size: 36px; font-weight: 800; line-height: 1; }
.score-max { font-size: 14px; color: #64748b; font-weight: 400; }
.score-bar { flex: 1; height: 10px; background: #0f172a; border-radius: 5px; overflow: hidden; }
.score-fill { height: 100%; transition: width 0.4s; }
.score-cap { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
.ai-summary { background: #0b1220; padding: 14px 16px; border-radius: 8px; border-left: 4px solid #38bdf8; margin-bottom: 18px; }
.ai-summary.skipped { border-left-color: #64748b; }
.ai-summary-title { font-size: 13px; color: #38bdf8; font-weight: 600; margin-bottom: 6px; }
.ai-meta { color: #64748b; font-weight: 400; margin-left: 8px; font-size: 11px; }
.ai-summary-body { font-size: 13px; color: #cbd5e1; line-height: 1.7; white-space: pre-wrap; }
.card-section { margin: 20px 0; }
.cn-title { font-size: 15px; color: #f1f5f9; border-left: 3px solid #38bdf8; padding-left: 10px; margin: 0 0 12px; }
.cn-sub { font-size: 11px; color: #64748b; font-weight: 400; margin-left: 8px; }
.risk-cat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; }
.risk-cat-card { background: #0f172a; padding: 12px; border-radius: 8px; border: 1px solid #1e293b; text-align: center; }
.risk-cat-card.card-critical { border-color: #ef4444; background: #2a0e0e; }
.risk-cat-card.card-clean { border-color: #1e293b; }
.card-title { font-size: 13px; color: #cbd5e1; margin-bottom: 6px; }
.card-count { font-size: 22px; font-weight: 700; color: #f1f5f9; }
.card-count .card-unit { font-size: 11px; color: #64748b; font-weight: 400; }
.card-badge { display: inline-block; font-size: 10px; padding: 2px 8px; border-radius: 999px; margin-top: 4px; font-weight: 600; }
.card-badge.bad { background: #ef4444; color: white; }
.card-badge.ok { background: #166534; color: #a7f3d0; }
.det-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 6px; }
.det-cell { background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 10px; }
.det-cell.det-hit { border-color: #ef4444; background: #2a0e0e; }
.det-cell.det-miss { opacity: 0.6; }
.det-name { font-size: 12px; color: #e2e8f0; font-weight: 600; }
.det-meta { font-size: 10px; color: #64748b; margin: 2px 0 4px; }
.det-meta code { font-size: 10px; padding: 0 4px; }
.det-badge { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
.det-badge.bad { background: #ef4444; color: white; }
.det-badge.ok { background: #1e293b; color: #64748b; }
.formula-details { margin-top: 16px; }
.formula-details summary { font-size: 12px; color: #64748b; }

/* === LLM 结构化研判（SAFESKILL 风格风险评估）=== */
.llm-risk-section { margin-top: 18px; }
.llm-risk-header { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #1e3354; }
.llm-risk-title { font-size: 16px; color: #f1f5f9; font-weight: 600; }
.llm-risk-subtitle { font-size: 11px; color: #475569; letter-spacing: 2px; margin-left: 6px; }
.llm-risk-count { color: #ef4444; font-size: 13px; font-weight: 700; letter-spacing: 1px; }
.llm-risk-cat { margin: 8px 0; padding: 10px 14px; background: #0a1424; border-radius: 6px; border: 1px solid #1e3354; }
.llm-risk-cat summary { cursor: pointer; display: flex; align-items: center; gap: 10px; font-size: 14px; color: #f1f5f9; padding: 4px 0; }
.llm-risk-cat summary::-webkit-details-marker { display: none; }
.llm-cat-name { flex: 1; font-weight: 600; }
.llm-cat-badge { padding: 2px 10px; border-radius: 999px; font-size: 11px; color: white; font-weight: 600; }
.llm-cat-count { color: #64748b; font-size: 12px; }
.llm-risk-item { margin: 10px 0 0; padding: 12px; background: #07101f; border-radius: 6px; border: 1px solid #1a2944; }
.llm-risk-item-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
.llm-risk-num { color: #64748b; font-family: monospace; font-size: 12px; }
.llm-risk-sev { padding: 2px 8px; border-radius: 4px; font-size: 11px; color: white; font-weight: 600; }
.llm-risk-title-text { color: #f1f5f9; font-weight: 600; font-size: 13px; flex: 1; }
.llm-risk-flag { background: rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; border: 1px solid rgba(56,189,248,0.3); }
.llm-risk-loc { font-size: 12px; color: #94a3b8; margin: 6px 0; }
.llm-risk-loc code { background: #1a2944; padding: 2px 6px; border-radius: 3px; color: #38bdf8; }
.llm-risk-code { background: #1a0e0e; color: #fda4af; padding: 8px 12px; border-radius: 4px; font-size: 12px; max-height: 140px; overflow-y: auto; white-space: pre-wrap; margin: 6px 0; border-left: 3px solid #ef4444; }
.llm-risk-desc { color: #cbd5e1; font-size: 13px; line-height: 1.6; margin: 6px 0; }
.llm-risk-fix { background: rgba(34, 197, 94, 0.08); padding: 8px 10px; border-radius: 4px; border-left: 3px solid #22c55e; color: #bbf7d0; font-size: 12px; margin-top: 8px; line-height: 1.6; }
.llm-risk-fix-label { color: #22c55e; font-weight: 600; }

/* === 主页 skill 列表（紧凑行 + 跳详情）=== */
.skill-rows { display: flex; flex-direction: column; gap: 10px; }
.skill-row { background: #0e1a2f; border: 1px solid #1e3354; border-radius: 10px; padding: 14px 20px; transition: border-color 0.15s; }
.skill-row:hover { border-color: #38bdf8; }
.skill-row.v-malicious { border-left: 4px solid #ef4444; }
.skill-row.v-critical_malicious { border-left: 4px solid #7c1d1d; }
.skill-row.v-suspicious { border-left: 4px solid #f59e0b; }
.skill-row.v-safe { border-left: 4px solid #22c55e; }
.row-main { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.row-verdict { padding: 6px 14px; border-radius: 6px; color: #0f172a; font-weight: 700; font-size: 13px; min-width: 60px; text-align: center; }
.row-info { flex: 1; min-width: 240px; }
.row-title { font-size: 16px; color: #f1f5f9; font-weight: 600; word-break: break-all; }
.row-meta { display: flex; gap: 14px; flex-wrap: wrap; color: #94a3b8; font-size: 12px; margin-top: 4px; }
.row-meta span { white-space: nowrap; }
.row-score { font-size: 28px; font-weight: 700; min-width: 90px; text-align: right; }
.row-score span { font-size: 12px; color: #64748b; font-weight: 400; }
.row-badges { display: flex; gap: 4px; flex-wrap: wrap; }
.status-badge { font-size: 10px; padding: 2px 7px; border-radius: 999px; font-weight: 600; }
.status-badge.done { background: rgba(34,197,94,0.15); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }
.status-badge.missing { background: rgba(100,116,139,0.15); color: #64748b; border: 1px solid rgba(100,116,139,0.3); }
.row-detail-btn { background: #38bdf8; color: #0f172a; padding: 8px 14px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600; white-space: nowrap; }
.row-detail-btn:hover { background: #0ea5e9; }
"""


def _skill_summary_row(report: dict[str, Any], detail_url: str) -> str:
    """主页用的紧凑行：名称 + verdict 徽章 + 分数 + 处置 + 查看详情链接。"""
    name = report["skill_name"]
    risk = report["composite_risk"]
    verdict = risk["verdict"]
    verdict_cn = VERDICT_CN.get(verdict, verdict)
    verdict_color = VERDICT_COLOR.get(verdict, "#888")
    action_cn = VERDICT_ACTION_CN.get(verdict, "审核")
    archetype = report["layer_2_attack_chain"]["archetype"]["archetype"]
    archetype_cn = ARCHETYPE_CN.get(archetype, archetype)
    static_count = report["layer_1_static_scan"]["total_findings"]
    ae = report.get("layer_3_agent_eval", {}) or {}
    ai_tested = ae.get("tested")
    rt = report.get("layer_5_runtime", {}) or {}
    rt_present = rt.get("present")
    badges = []
    badges.append('<span class="status-badge done">静态✓</span>')
    badges.append(
        '<span class="status-badge done">AI✓</span>' if ai_tested
        else '<span class="status-badge missing">AI未测</span>'
    )
    badges.append(
        '<span class="status-badge done">动态✓</span>' if rt_present
        else '<span class="status-badge missing">动态未测</span>'
    )
    return f"""
    <div class="skill-row v-{verdict.lower()}">
      <div class="row-main">
        <div class="row-verdict" style="background:{verdict_color};">{_escape(verdict_cn)}</div>
        <div class="row-info">
          <div class="row-title">{_escape(name)}</div>
          <div class="row-meta">
            <span>分类: {_escape(archetype_cn)}</span>
            <span>静态命中: {static_count}</span>
            <span>处置: <strong style="color:{verdict_color};">{_escape(action_cn)}</strong></span>
          </div>
        </div>
        <div class="row-score" style="color:{verdict_color};">{risk['composite_score']:.1f}<span>/100</span></div>
        <div class="row-badges">{''.join(badges)}</div>
        <a class="row-detail-btn" href="{detail_url}">查看详情 →</a>
      </div>
    </div>
    """


def _build_detail_html(report: dict[str, Any]) -> str:
    """每个 skill 一张独立 HTML 详情页。"""
    name = report["skill_name"]
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(name)} · SkillVault 详情</title>
  <style>{CSS}</style>
</head>
<body>
  <header class="topbar">
    <div class="eyebrow">SKILLSENTINEL · SKILL DETAIL</div>
    <h1>{_escape(name)}</h1>
    <div class="subtitle">
      <a href="../dashboard.html" style="color:#38bdf8;text-decoration:none;">← 返回总览</a>
    </div>
  </header>
  <main>
    <div class="skills-grid">
      {_skill_card(report)}
    </div>
  </main>
  <div class="footer">SkillVault v1.1 · Skill 详情页</div>
</body>
</html>"""


def _safe_filename(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_一-鿿.-]+', '_', name)[:120]


def build_html(batch_summary: dict[str, Any], reports: list[dict[str, Any]]) -> str:
    # 主页：每个 skill 一行紧凑摘要 + 跳转链接（按 verdict + 分数排序）
    sorted_reports = sorted(
        reports,
        key=lambda r: (
            {"CRITICAL_MALICIOUS": 0, "MALICIOUS": 1, "SUSPICIOUS": 2, "SAFE": 3}.get(
                r["composite_risk"]["verdict"], 9),
            -r["composite_risk"]["composite_score"],
        ),
    )
    skill_rows = "\n".join(
        _skill_summary_row(r, f"skills/{_safe_filename(r['skill_name'])}.html")
        for r in sorted_reports
    )

    # Chinese-labeled verdict bar
    by_verdict_cn = {VERDICT_CN.get(k, k): v for k, v in batch_summary["by_verdict"].items()}
    by_archetype_cn = {ARCHETYPE_CN.get(k, k): v for k, v in batch_summary["by_archetype"].items()}
    color_v_cn = {VERDICT_CN.get(k, k): v for k, v in VERDICT_COLOR.items()}
    color_a_cn = {ARCHETYPE_CN.get(k, k): v for k, v in ARCHETYPE_COLOR.items()}
    verdict_bars = _bar_chart(by_verdict_cn, color_v_cn)
    archetype_bars = _bar_chart(by_archetype_cn, color_a_cn)
    chain_bars = _bar_chart(batch_summary.get("chain_trigger_counts", {}) or {}, {})

    n_safe = batch_summary["by_verdict"].get("SAFE", 0)
    n_susp = batch_summary["by_verdict"].get("SUSPICIOUS", 0)
    n_mal = (batch_summary["by_verdict"].get("MALICIOUS", 0)
             + batch_summary["by_verdict"].get("CRITICAL_MALICIOUS", 0))

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SkillVault · AI Skill 安全研判平台</title>
  <style>{CSS}</style>
</head>
<body>
  <header class="topbar">
    <div class="eyebrow">SKILLSENTINEL · AI SKILL SECURITY PLATFORM</div>
    <h1>SkillVault · AI Skill 安全研判平台</h1>
    <div class="subtitle">
      静态规则 + 攻击链 + LLM 智能体研判 + 蜜罐 + Docker 运行时证据 · 五层闭环
      <span style="margin-left:12px;color:#475569;">基准对齐: arXiv:2602.06547v2（14 项 + 3 项 ASG 扩展，共 17 条规则）</span>
    </div>
  </header>

  <main>
    <section class="summary-cards">
      <div class="summary-card"><span>已检测 Skill 总数</span><strong>{batch_summary["total_skills"]}</strong></div>
      <div class="summary-card v-mal"><span>危险 MALICIOUS</span><strong>{n_mal}</strong></div>
      <div class="summary-card v-susp"><span>留意 SUSPICIOUS</span><strong>{n_susp}</strong></div>
      <div class="summary-card v-safe"><span>安全 SAFE</span><strong>{n_safe}</strong></div>
      <div class="summary-card"><span>静态规则命中总数</span><strong>{batch_summary["total_static_findings"]}</strong></div>
      <div class="summary-card"><span>攻击链触发数</span><strong>{batch_summary["total_chains_triggered"]}</strong></div>
    </section>

    <h2 class="section-title">综合风险评分公式 <span class="section-sub">所有 skill 共用同一套数学定义</span></h2>
    <div class="formula-box">
      R = 100 × (
      0.22·S<sub>static</sub> + 0.18·S<sub>chain</sub> + 0.10·S<sub>soph</sub>
      + 0.08·S<sub>phases</sub> + 0.17·(1 − S<sub>resilience</sub>)
      + 0.10·S<sub>honeypot</sub> + 0.15·S<sub>runtime</sub>
      )
      &nbsp;,&nbsp; 权重之和 = 1.0 &nbsp;,&nbsp;
      Verdict 阈值: SAFE [0,15) · SUSPICIOUS [15,40) · MALICIOUS [40,75) · CRITICAL [75,100]
    </div>

    <h2 class="section-title">总体分布 <span class="section-sub">verdict / 攻击原型 / 攻击链</span></h2>
    <div class="panel">
      <h2>风险判定分布</h2>
      {verdict_bars}
    </div>
    <div class="panel">
      <h2>攻击原型分布（§4.2）</h2>
      {archetype_bars}
    </div>
    <div class="panel">
      <h2>攻击链触发统计（Table 11）</h2>
      {chain_bars}
    </div>

    <h2 class="section-title">Skill 列表 <span class="section-sub">点"查看详情"打开独立报告页</span></h2>
    <div class="skill-rows">
      {skill_rows}
    </div>
  </main>

  <div class="footer">
    SkillVault v1.1 · 基于 ASG (AgentSkillGuard) · Codex Runtime Security
  </div>
</body>
</html>
"""


def _summarize(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute a batch_summary from an explicit set of reports.

    Used when the dashboard is scoped to a single skill so the summary
    cards (Skills Evaluated, etc.) reflect only what is shown, not the
    aggregated history on disk.
    """
    by_verdict: dict[str, int] = {}
    by_archetype: dict[str, int] = {}
    chain_trigger_counts: dict[str, int] = {}
    total_static = 0
    total_chains = 0
    for r in reports:
        verdict = r["composite_risk"]["verdict"]
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        archetype = r["layer_2_attack_chain"]["archetype"]["archetype"]
        by_archetype[archetype] = by_archetype.get(archetype, 0) + 1
        total_static += r["layer_1_static_scan"]["total_findings"]
        chains = r["layer_2_attack_chain"]["chains_triggered"]
        total_chains += len(chains)
        for c in chains:
            name = c.get("name", c.get("chain_id", "?"))
            chain_trigger_counts[name] = chain_trigger_counts.get(name, 0) + 1
    return {
        "generated_at_utc": datetime.utcnow().isoformat(),
        "total_skills": len(reports),
        "total_static_findings": total_static,
        "total_chains_triggered": total_chains,
        "by_verdict": by_verdict,
        "by_archetype": by_archetype,
        "chain_trigger_counts": chain_trigger_counts,
    }


def build_from_results(
    results_dir: Path,
    output_html: Path,
    only_skill: str | None = None,
) -> Path:
    """Read asg_report.json files under results_dir/<skill>/, build dashboard.

    If ``only_skill`` is given, only that skill's report is rendered and the
    summary is recomputed from it alone — so each run shows just the skill
    that was analyzed, not the full aggregated history.
    """
    results_dir = Path(results_dir).resolve()
    reports: list[dict[str, Any]] = []
    for d in sorted(results_dir.iterdir()):
        if not d.is_dir():
            continue
        if only_skill is not None and d.name != only_skill:
            continue
        p = d / "asg_report.json"
        if not p.exists():
            continue
        try:
            reports.append(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue

    if only_skill is not None:
        if not reports:
            raise FileNotFoundError(
                f"No asg_report.json for skill '{only_skill}' under {results_dir}"
            )
        batch_summary = _summarize(reports)
    else:
        batch_path = results_dir / "batch_summary.json"
        if batch_path.exists():
            batch_summary = json.loads(batch_path.read_text(encoding="utf-8"))
        else:
            batch_summary = {
                "generated_at_utc": datetime.utcnow().isoformat(),
                "total_skills": len(reports),
                "total_static_findings": 0,
                "total_chains_triggered": 0,
                "by_verdict": {},
                "by_archetype": {},
                "chain_trigger_counts": {},
            }

    html_text = build_html(batch_summary, reports)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_text, encoding="utf-8")

    # 每个 skill 写一个独立详情页到 <output>/skills/<name>.html
    skills_dir = output_html.parent / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    for r in reports:
        detail = _build_detail_html(r)
        (skills_dir / f"{_safe_filename(r['skill_name'])}.html").write_text(
            detail, encoding="utf-8")
    return output_html


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build ASG dashboard HTML")
    parser.add_argument("--results-dir", default="analysis_results/asg")
    parser.add_argument("--output", default="asg/dashboard.html")
    args = parser.parse_args()

    out = build_from_results(Path(args.results_dir), Path(args.output))
    print(f"Wrote: {out.resolve()}")
