"""Attack-chain detector based on paper Table 11 co-occurrence matrix.

Paper findings we operationalize here:
  - E2->E1 chain: credential harvest -> external transmission (OR=2.31, p=0.020)
    appears in 36.9% of confirmed malicious skills.
  - SC2<->P1 anti-correlation (OR=0.11, p<0.001) defines two archetypes:
        * Data Thieves   = SC2 without P1   (110 skills, 70.5%)
        * Agent Hijackers = P1 without SC2  (16 skills, 10.2%)
  - smp_170 factory fingerprint: E2+SC2 pair achieves OR=556 discrimination.
  - E2+E1+P4 triple: 26.1% of skills, concentrates in higher sophistication.
  - Strongest positive: P2+SC3 (lift 4.18) when hijackers obfuscate.

Reference: arXiv:2602.06547v2 §4.2 and Table 11.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# Chain definitions
# ============================================================
CHAINS: list[dict[str, Any]] = [
    {
        "chain_id": "E2_E1",
        "name": "Data Exfiltration Chain",
        "required_rules": ["E2", "E1"],
        "phase_sequence": ["cred_access", "exfil"],
        "severity_boost": "HIGH",
        "paper_evidence": "OR=2.31, p=0.020; 36.9% of malicious skills (§4.2)",
        "description": "Credential harvesting followed by external transmission.",
    },
    {
        "chain_id": "E2_SC2_FACTORY",
        "name": "smp_170 Brand Impersonation Factory Fingerprint",
        "required_rules": ["E2", "SC2"],
        "phase_sequence": ["cred_access", "execution"],
        "severity_boost": "CRITICAL",
        "paper_evidence": "OR=556, 97.6% sensitivity for smp_170 (§4.2)",
        "description": "E2+SC2 co-occurrence — paper's strongest single fingerprint.",
    },
    {
        "chain_id": "E2_E1_P4_ADVANCED",
        "name": "Advanced Data Thief Triple",
        "required_rules": ["E2", "E1", "P4"],
        "phase_sequence": ["cred_access", "exfil", "impact"],
        "severity_boost": "CRITICAL",
        "paper_evidence": "26.1% of skills, 80% of Level-3 attacks (§4.2)",
        "description": "Harvest + exfil + user-alert suppression.",
    },
    {
        "chain_id": "P2_SC3_HIJACKER",
        "name": "Hijacker Obfuscation Pattern",
        "required_rules": ["P2", "SC3"],
        "phase_sequence": ["evasion", "evasion"],
        "severity_boost": "CRITICAL",
        "paper_evidence": "lift=4.18, phi=0.537 — strongest positive in matrix (§4.2)",
        "description": "Hidden instructions + obfuscated code (advanced evasion).",
    },
    {
        "chain_id": "EXEC_CRED_ACCESS",
        "name": "Canonical Agent Skill Pattern",
        "required_rules": ["SC2", "E2"],
        "phase_sequence": ["execution", "cred_access"],
        "severity_boost": "HIGH",
        "paper_evidence": "89 skills (strongest phase co-occurrence) (§4.1)",
        "description": "Execution-Credential Access kill-chain coupling.",
    },
    {
        "chain_id": "ASG_PERSIST_CHAIN",
        "name": "Persistence-Enabled Attack (ASG extension)",
        "required_rules": ["P6"],
        "phase_sequence": ["impact"],
        "severity_boost": "CRITICAL",
        "paper_evidence": "ASG extension — persistence not in paper's 14 patterns",
        "description": "Skill plants persistence hook (~/.bashrc, cron, etc.).",
    },
]


# ============================================================
# Archetype classification
# ============================================================
def classify_archetype(rule_ids: set[str]) -> dict[str, Any]:
    """Return paper-aligned archetype label.

    Paper Section 4.2:
        Data Thief   : SC2 present AND P1 absent
        Agent Hijacker: P1 present AND SC2 absent
        Hybrid       : both SC2 and P1 present (5.1% of skills)
        Platform-Native: PE1 dangerously-skip-permissions present
        Benign       : neither SC2 nor P1
    """
    has_sc2 = "SC2" in rule_ids
    has_p1 = "P1" in rule_ids
    has_pe1 = "PE1" in rule_ids
    has_e2 = "E2" in rule_ids
    has_p4 = "P4" in rule_ids
    has_p6 = "P6" in rule_ids
    # Broader "code-level malicious" indicator set used as fallback when
    # paper's strict SC2 marker is absent (e.g., raw-socket reverse shells).
    has_code_attack = any(
        r in rule_ids for r in ("SC1", "SC2", "SC3", "E1", "PE3")
    )
    has_instruction_attack = any(
        r in rule_ids for r in ("P1", "P2", "P4", "P5", "P6", "P7")
    )

    if has_sc2 and has_p1:
        archetype = "Hybrid"
        archetype_confidence = 0.85
        archetype_paper_share = 5.1
    elif has_sc2 and not has_p1:
        archetype = "Data Thief"
        archetype_confidence = 0.90
        archetype_paper_share = 70.5
    elif has_p1 and not has_sc2:
        archetype = "Agent Hijacker"
        archetype_confidence = 0.90
        archetype_paper_share = 10.2
    elif has_pe1:
        archetype = "Platform-Native"
        archetype_confidence = 0.75
        archetype_paper_share = 3.8
    elif has_code_attack and has_instruction_attack:
        archetype = "Hybrid"
        archetype_confidence = 0.65
        archetype_paper_share = None
    elif has_code_attack:
        # Paper's Data Thief is SC2-centered, but raw-socket / SC1 / PE3
        # variants still qualify as the data-thief archetype semantically.
        archetype = "Data Thief"
        archetype_confidence = 0.70
        archetype_paper_share = 70.5
    elif has_instruction_attack:
        archetype = "Agent Hijacker"
        archetype_confidence = 0.70
        archetype_paper_share = 10.2
    elif has_e2 or has_p4 or has_p6:
        archetype = "Partial-Risk"
        archetype_confidence = 0.50
        archetype_paper_share = None
    else:
        archetype = "Benign"
        archetype_confidence = 0.50
        archetype_paper_share = None

    return {
        "archetype": archetype,
        "confidence": archetype_confidence,
        "paper_archetype_share_percent": archetype_paper_share,
        "has_SC2": has_sc2,
        "has_P1": has_p1,
        "has_PE1": has_pe1,
    }


# ============================================================
# Sophistication level (paper §3.6)
# ============================================================
def classify_sophistication(
    total_findings: int,
    rule_ids: set[str],
    shadow_features_detected: bool = False,
) -> dict[str, Any]:
    """Paper §3.6:
    Level 1 (Basic):       1-2 patterns,  no evasion (no SC3 no P2), no shadow features
    Level 2 (Intermediate): 3-4 patterns, OR evasion OR shadow features
    Level 3 (Advanced):     5+ patterns,  AND evasion AND shadow features
    """
    has_evasion = "SC3" in rule_ids or "P2" in rule_ids

    if total_findings >= 5 and has_evasion and shadow_features_detected:
        level = 3
        label = "Advanced"
    elif total_findings >= 3 or has_evasion or shadow_features_detected:
        level = 2
        label = "Intermediate"
    elif total_findings >= 1:
        level = 1
        label = "Basic"
    else:
        level = 0
        label = "None"

    return {
        "level": level,
        "label": label,
        "criterion_evasion_present": has_evasion,
        "criterion_shadow_features": shadow_features_detected,
        "criterion_pattern_count": total_findings,
    }


# ============================================================
# Chain detection
# ============================================================
def detect_chains(rule_ids_hit: list[str]) -> list[dict[str, Any]]:
    """Match against the chain catalog. Each chain that has all required rules
    fires once.
    """
    rule_set = set(rule_ids_hit)
    triggered: list[dict[str, Any]] = []

    for chain in CHAINS:
        required = set(chain["required_rules"])
        if required.issubset(rule_set):
            triggered.append(
                {
                    "chain_id": chain["chain_id"],
                    "name": chain["name"],
                    "required_rules": chain["required_rules"],
                    "phase_sequence": chain["phase_sequence"],
                    "severity_boost": chain["severity_boost"],
                    "paper_evidence": chain["paper_evidence"],
                    "description": chain["description"],
                }
            )
    return triggered


# ============================================================
# Public API
# ============================================================
def analyze(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Run archetype + chain + sophistication analysis on a scan result.

    Input shape: output of rules.scan_skill_directory().
    """
    rule_ids = scan_result.get("rule_ids_hit", [])
    rule_set = set(rule_ids)
    total = scan_result.get("total_findings", 0)

    chains = detect_chains(rule_ids)
    archetype = classify_archetype(rule_set)
    has_shadow = "P2" in rule_set or "SC3" in rule_set
    sophistication = classify_sophistication(total, rule_set, has_shadow)

    return {
        "archetype": archetype,
        "sophistication": sophistication,
        "chains_triggered": chains,
        "chain_count": len(chains),
        "kill_chain_phases_covered": sorted(
            set(scan_result.get("by_kill_chain_phase", {}).keys())
        ),
        "kill_chain_phase_coverage_count": len(
            scan_result.get("by_kill_chain_phase", {})
        ),
    }
