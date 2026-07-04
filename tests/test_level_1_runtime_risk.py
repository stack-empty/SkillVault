import unittest

from asg.risk_scorer import compute_risk, compute_runtime_score


def _runtime_layer(
    sensitive_file_access_count=0,
    outbound_connect_count=0,
    unique_outbound_ips=None,
    fs_change_present=False,
    pcap_present=False,
):
    return {
        "present": True,
        "strace": {
            "sensitive_file_access_count": sensitive_file_access_count,
            "outbound_connect_count": outbound_connect_count,
            "unique_outbound_ips": unique_outbound_ips or [],
        },
        "filesystem": {"fs_change_present": fs_change_present},
        "tcpdump": {"pcap_present": pcap_present},
    }


def _minimal_scan_result():
    return {
        "by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }


def _minimal_chain_result():
    return {
        "chain_count": 0,
        "sophistication": {"level": 0},
        "kill_chain_phase_coverage_count": 1,
    }


class Level1RuntimeRiskTests(unittest.TestCase):
    def test_runtime_score_no_evidence(self):
        result = compute_runtime_score({})

        self.assertEqual(result["S_runtime"], 0)
        self.assertEqual(result["runtime_signals"]["sensitive_file_access_count"], 0)
        self.assertEqual(result["runtime_signals"]["outbound_connect_count"], 0)

    def test_runtime_score_sensitive_access(self):
        result = compute_runtime_score(
            _runtime_layer(sensitive_file_access_count=2)
        )

        self.assertGreater(result["S_runtime"], 0)
        self.assertTrue(any(
            "sensitive file access" in reason
            for reason in result["runtime_score_reasons"]
        ))

    def test_runtime_score_outbound_connect(self):
        result = compute_runtime_score(_runtime_layer(outbound_connect_count=1))

        self.assertGreater(result["S_runtime"], 0)
        self.assertTrue(any(
            "outbound connect" in reason
            for reason in result["runtime_score_reasons"]
        ))

    def test_runtime_score_sensitive_plus_outbound(self):
        sensitive_only = compute_runtime_score(
            _runtime_layer(sensitive_file_access_count=1)
        )
        outbound_only = compute_runtime_score(
            _runtime_layer(outbound_connect_count=1)
        )
        combined = compute_runtime_score(
            _runtime_layer(
                sensitive_file_access_count=1,
                outbound_connect_count=1,
            )
        )

        self.assertGreater(combined["S_runtime"], sensitive_only["S_runtime"])
        self.assertGreater(combined["S_runtime"], outbound_only["S_runtime"])

    def test_runtime_score_honeypot_leak(self):
        clean = compute_runtime_score(_runtime_layer())
        leaked = compute_runtime_score(
            _runtime_layer(),
            {"any_honeypot_leaked": True},
        )

        self.assertGreaterEqual(leaked["S_runtime"], clean["S_runtime"] + 0.2)
        self.assertTrue(any(
            "honeypot" in reason
            for reason in leaked["runtime_score_reasons"]
        ))

    def test_composite_risk_runtime_delta(self):
        risk = compute_risk(
            scan_result=_minimal_scan_result(),
            chain_result=_minimal_chain_result(),
            agent_eval=None,
            honeypot_result=None,
            layer_5_runtime=_runtime_layer(
                sensitive_file_access_count=1,
                outbound_connect_count=1,
                unique_outbound_ips=["203.0.113.10"],
            ),
        )

        self.assertGreater(risk["sub_scores"]["S_runtime"], 0)
        self.assertGreater(risk["runtime_score_delta"], 0)


if __name__ == "__main__":
    unittest.main()
