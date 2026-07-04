import json
import re
import tempfile
import unittest
from pathlib import Path

from asg import dashboard_builder, honeypot, vm_evidence
from asg.risk_scorer import compute_runtime_score


class Level2HoneypotMaterializationTests(unittest.TestCase):
    def test_generate_bundle_contains_expected_fake_files(self):
        bundle = honeypot.generate_bundle(
            sample_name="sample_a",
            run_id="run_1",
            include_files=True,
        )

        for rel_path in (
            ".env",
            ".ssh/id_rsa",
            ".ssh/config",
            ".aws/credentials",
            ".codex/config.json",
            ".config/gh/hosts.yml",
        ):
            self.assertIn(rel_path, bundle.files)

    def test_generate_bundle_does_not_create_real_key_shapes(self):
        bundle = honeypot.generate_bundle(
            sample_name="sample_a",
            run_id="run_1",
            include_files=True,
        )
        text = "\n".join(bundle.all_markers()) + "\n" + "\n".join(bundle.files.values())

        self.assertNotRegex(text, re.compile(r"sk-[A-Za-z0-9_-]{8,}"))
        self.assertNotRegex(text, re.compile(r"ghp_[A-Za-z0-9_]{8,}"))
        self.assertNotRegex(text, re.compile(r"AKIA[0-9A-Z]{16}"))

    def test_scan_evidence_detects_marker_leak(self):
        bundle = honeypot.generate_bundle(sample_name="sample_a", run_id="run_1")
        marker = bundle.dotenv_openai_marker

        result = honeypot.scan_evidence_for_leaks(
            bundle,
            [f"stdout accidentally printed {marker}"],
        )

        self.assertTrue(result["any_honeypot_leaked"])
        self.assertEqual(result["matches"][0]["marker_type"], "OPENAI")

    def test_scan_evidence_redacts_context_preview(self):
        bundle = honeypot.generate_bundle(sample_name="sample_a", run_id="run_1")
        marker = bundle.dotenv_github_marker

        result = honeypot.scan_evidence_for_leaks(
            bundle,
            [f"token={marker}"],
        )

        self.assertTrue(result["matches"])
        self.assertNotIn(marker, result["matches"][0]["context_preview"])
        self.assertIn("<redacted:", result["matches"][0]["context_preview"])

    def test_vm_evidence_detects_honeypot_touched_from_strace(self):
        bundle = honeypot.generate_bundle(sample_name="sample_a", run_id="run_1")
        with tempfile.TemporaryDirectory() as tmp:
            evidence_dir = Path(tmp)
            honeypot.write_metadata(bundle, evidence_dir / "honeypot_bundle.json")
            metadata = json.loads((evidence_dir / "honeypot_bundle.json").read_text())
            metadata.update(
                {
                    "deployed": True,
                    "deployment_mode": "vm_container_home",
                    "files_created": list(bundle.files.keys()),
                    "marker_count": len(bundle.all_markers()),
                }
            )
            (evidence_dir / "honeypot_bundle.json").write_text(json.dumps(metadata))
            (evidence_dir / "strace.log").write_text(
                'openat(AT_FDCWD, "/home/codexsafe/.env", O_RDONLY) = 3\n',
                encoding="utf-8",
            )

            record = vm_evidence.ingest_evidence_dir(evidence_dir)

        hp = record["honeypot_evidence"]
        self.assertTrue(hp["touched"])
        self.assertIn("/home/codexsafe/.env", hp["touched_files"])

    def test_runtime_score_increases_when_honeypot_touched_or_leaked(self):
        runtime = {"present": True, "strace": {}, "filesystem": {}, "tcpdump": {}}
        clean = compute_runtime_score(runtime, {})
        touched = compute_runtime_score(runtime, {"touched": True})
        leaked = compute_runtime_score(runtime, {"any_honeypot_leaked": True})

        self.assertGreater(touched["S_runtime"], clean["S_runtime"])
        self.assertGreater(leaked["S_runtime"], touched["S_runtime"])

    def test_dashboard_does_not_render_full_marker(self):
        bundle = honeypot.generate_bundle(sample_name="sample_a", run_id="run_1")
        full_marker = bundle.dotenv_openai_marker
        report = {
            "skill_name": "sample_a",
            "layer_1_static_scan": {"total_findings": 0},
            "layer_2_attack_chain": {
                "archetype": {"archetype": "Benign"},
                "sophistication": {"level": 0, "label": "None"},
                "chains_triggered": [],
            },
            "layer_3_agent_eval": {"tested": False, "skipped_reason": "test"},
            "layer_4_honeypot": {
                "enabled": True,
                "deployed": True,
                "deployment_mode": "vm_container_home",
                "bundle_id": bundle.bundle_id,
                "files_created": list(bundle.files.keys()),
                "marker_count": len(bundle.all_markers()),
                "redacted_preview": bundle.redacted_preview,
                "touched": True,
                "touched_files": ["/home/codexsafe/.env"],
                "any_honeypot_leaked": False,
                "leak_sources": [],
            },
            "layer_5_runtime": {"present": False},
            "composite_risk": {
                "composite_score": 8.5,
                "verdict": "SAFE",
                "formula": "test",
                "sub_scores": {
                    "S_static": 0,
                    "S_chain": 0,
                    "S_soph": 0,
                    "S_phases": 0,
                    "S_resilience": 0.5,
                    "S_honeypot": 0,
                    "S_runtime": 0.1,
                },
                "weights": {
                    "w_static": 0.22,
                    "w_chain": 0.18,
                    "w_soph": 0.10,
                    "w_phases": 0.08,
                    "w_agent": 0.17,
                    "w_honeypot": 0.10,
                    "w_runtime": 0.15,
                },
                "runtime_score_delta": 1.5,
                "runtime_score_reasons": ["honeypot files touched in VM container fake HOME"],
            },
            "findings": [],
        }
        batch = {
            "generated_at_utc": "2026-05-12T00:00:00+00:00",
            "total_skills": 1,
            "total_static_findings": 0,
            "total_chains_triggered": 0,
            "by_verdict": {"SAFE": 1},
            "by_archetype": {"Benign": 1},
            "chain_trigger_counts": {},
        }

        html = dashboard_builder.build_html(batch, [report])

        self.assertNotIn(full_marker, html)
        self.assertIn("redacted:", html)


if __name__ == "__main__":
    unittest.main()
