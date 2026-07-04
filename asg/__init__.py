"""ASG (AgentSkillGuard) — SkillVault 核心检测模块.

This package extends the Codex Runtime Security Prototype with:
  - Claude API integration (real agent-in-the-loop evidence)
  - Paper-aligned 14-pattern static rules + 3 extensions (P5/P6/P7)
  - Attack-chain detector (E2->E1, SC2+P1 from paper Table 11)
  - Composite risk scorer with explicit mathematical formula
  - Honeypot credential generation and exfiltration detection
  - Extended sample library covering 6 paper attack categories
  - Unified CLI entry point producing dashboard-compatible JSON

The module is designed to coexist with the existing Codex framework.
No existing teammate code is modified.

Run:
    python -m asg.asg_cli scan <skill_path>
"""

__version__ = "1.0.0"
