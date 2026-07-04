"""Extract dynamic-execution evidence from a mode-3 (Claude-in-Docker) run's
SSH stdout log.

When mode 3 runs Claude CLI inside the sandbox, the container TEST_DIR bug
(now fixed) caused strace.log / network.pcap / claude_output.txt to land on
the ephemeral container filesystem rather than the mounted host path. The
log we DO have, `ssh_run_stdout.log`, contains the full Claude conversation
including its self-reported attempts (DNS, HTTPS, port connect, npm install,
hardcoded-credential discovery, etc.) plus runtime tee output.

We pattern-match Claude's narration to back-fill the same counters that the
strace path would have produced (sensitive_file_access_count,
outbound_connect_count, unique_outbound_ips). These plug straight into
compute_runtime_score without changing its scoring formula.

This is honest evidence: every signal here is something Claude described
doing inside an instrumented sandbox. The strace-derived path is strictly
stronger (kernel-level proof), but mode-3 evidence is still actionable when
we have it and Claude can't have done.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# Patterns that imply Claude actually issued an outbound network operation.
# We score each match once at most (`set`) — Claude tends to narrate things
# multiple times in one response.
_OUTBOUND_PATTERNS = [
    (re.compile(r"DNS\s+resolves?\s+\(?([\w.-]+)\)?\s*(?:→|->|to)\s+(\d+\.\d+\.\d+\.\d+)",
                re.IGNORECASE), "dns_lookup"),
    (re.compile(r"\b(?:reached|connected\s+to)\s+(?:the\s+)?([\w.-]+(?:\.com|\.dev|\.io|\.ai|\.cn)|\w+\s+API)",
                re.IGNORECASE), "reached_endpoint"),
    (re.compile(r"\bport\s+open\b|\breachable\s+\(port\s+open\)", re.IGNORECASE),
     "port_probe_success"),
    (re.compile(r"\b(?:POST|GET|PUT|DELETE)\s+(?:to|/)\s*(/?[\w./-]+)", re.IGNORECASE),
     "http_request"),
    (re.compile(r"\bcurl\s+(?:-[a-zA-Z]+\s+)?(?:-X\s+(?:POST|PUT|GET))?\s*[\"']?(https?://[\w./-]+)",
                re.IGNORECASE), "curl_invocation"),
    (re.compile(r"\bnpm\s+install\b", re.IGNORECASE), "package_install"),
    (re.compile(r"\bgit\s+clone\s+(https?://\S+)", re.IGNORECASE), "git_clone"),
]

# Patterns that imply Claude touched / surfaced sensitive data.
_SENSITIVE_PATTERNS = [
    (re.compile(r"\bhardcoded\s+(?:credentials?|secret|password|token|API\s*key)",
                re.IGNORECASE), "hardcoded_secret_seen"),
    (re.compile(r"\bproduction\s+(?:database|DB|Postgres|MySQL|host|server|credentials?)",
                re.IGNORECASE), "production_infra_seen"),
    (re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+",
                re.IGNORECASE), "ipv4_port_literal"),
    (re.compile(r"\b(?:read|access)\s+(?:~/)?\.(?:aws/credentials|ssh/id_rsa|env|netrc|gnupg)",
                re.IGNORECASE), "credential_path_access"),
    (re.compile(r"\bAPP_ID|APP_SECRET|API_KEY|SECRET_KEY", re.IGNORECASE),
     "env_credential_keyword"),
]

# Patterns indicating Claude flagged obfuscation / fingerprinting / closed source.
_OBFUSCATION_PATTERNS = [
    (re.compile(r"\bobfuscated\b|\bencrypted\b|\bclosed[-\s]?source", re.IGNORECASE),
     "obfuscation_flag"),
    (re.compile(r"\b(?:device|host|hardware)[-\s]*fingerprint", re.IGNORECASE),
     "fingerprinting_flag"),
    (re.compile(r"\bnever\s+read\s+(?:`)?[\w./-]+(?:`)?", re.IGNORECASE),
     "never_read_directive"),
    (re.compile(r"\bwmic\b", re.IGNORECASE), "wmic_call"),
    (re.compile(r"\blicense[-_\s]?key", re.IGNORECASE), "license_check"),
]

# Patterns showing Claude refused at a safety boundary — itself useful evidence
# that the skill demanded something unsafe.
_REFUSAL_PATTERNS = [
    (re.compile(r"\bI\s+won['’]?t\b|\bI\s+will\s+not\b", re.IGNORECASE),
     "explicit_refusal"),
    (re.compile(r"\bhard[-\s]?to[-\s]?reverse\b|\boutward[-\s]?facing\b",
                re.IGNORECASE), "irreversible_action_flag"),
    (re.compile(r"\bguess(?:ed|ing)?\s+(?:credentials?|password)", re.IGNORECASE),
     "credential_guess_blocked"),
]


def _scan(patterns: list[tuple[re.Pattern, str]], text: str) -> dict[str, list[str]]:
    """Return {signal_kind: [evidence_snippets]} for every pattern that fired."""
    out: dict[str, list[str]] = {}
    for pat, kind in patterns:
        for m in pat.finditer(text):
            snippet = m.group(0)[:140]
            out.setdefault(kind, []).append(snippet)
            if len(out[kind]) >= 5:  # cap per signal
                break
    return out


def extract_mode3_evidence(stdout_text: str) -> dict[str, Any]:
    """Parse a Claude-in-docker stdout transcript and return runtime-style
    signals that map onto `compute_runtime_score`'s expected schema.

    Returns a dict shaped like a partial `vm_record` so it can be merged into
    the existing pipeline without schema churn:
        {
          "strace": {
            "log_present": False,             # we don't have strace itself
            "sensitive_file_access_count": int,
            "outbound_connect_count": int,
            "unique_outbound_ips": [str, ...],
            "log_source": "mode3_claude_stdout",
          },
          "tcpdump": {"pcap_present": False, "domains_referenced": [...]},
          "claude_evidence": {
            "outbound_signals": {...},
            "sensitive_signals": {...},
            "obfuscation_signals": {...},
            "refusal_signals": {...},
            "evidence_strength": "agent_self_report",
          },
        }
    """
    if not stdout_text:
        return {}
    outbound = _scan(_OUTBOUND_PATTERNS, stdout_text)
    sensitive = _scan(_SENSITIVE_PATTERNS, stdout_text)
    obfusc = _scan(_OBFUSCATION_PATTERNS, stdout_text)
    refusal = _scan(_REFUSAL_PATTERNS, stdout_text)

    # Build counters compatible with compute_runtime_score expectations.
    outbound_count = sum(len(v) for v in outbound.values())
    sensitive_count = sum(len(v) for v in sensitive.values()) \
        + sum(len(v) for v in obfusc.values())

    # Distinct domains/IPs mentioned in outbound context — used by S_runtime's
    # unique-ip term. We collect both hostnames and ipv4 literals here so the
    # count is meaningful even when DNS lines lack the IP.
    ip_re = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    host_re = re.compile(r"\b[\w-]+\.[\w-]+(?:\.[\w-]+)*\.(?:com|dev|net|io|ai|cn|org)\b",
                         re.IGNORECASE)
    ips = {ip for ip in ip_re.findall(stdout_text)
           if not ip.startswith(("127.", "192.168.", "10.", "0."))}
    hosts = set(host_re.findall(stdout_text))
    unique_outbound = sorted(ips | {h.lower() for h in hosts})[:20]

    return {
        "strace": {
            "log_present": False,
            "log_source": "mode3_claude_stdout",
            "sensitive_file_access_count": sensitive_count,
            "outbound_connect_count": outbound_count,
            "unique_outbound_ips": unique_outbound,
        },
        "tcpdump": {
            "pcap_present": False,
            "log_source": "mode3_claude_stdout",
            "domains_referenced": sorted(hosts)[:20],
        },
        "filesystem": {
            # Not derivable from stdout reliably; leave as not present
            "fs_change_present": False,
        },
        "claude_evidence": {
            "outbound_signals": outbound,
            "sensitive_signals": sensitive,
            "obfuscation_signals": obfusc,
            "refusal_signals": refusal,
            "evidence_strength": "agent_self_report",
            "narrative_chars": len(stdout_text),
        },
    }


def load_and_extract(stdout_log_path: Path | str) -> dict[str, Any]:
    """File wrapper for `extract_mode3_evidence`."""
    p = Path(stdout_log_path)
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    out = extract_mode3_evidence(text)
    if out:
        out["source_path"] = str(p)
    return out
