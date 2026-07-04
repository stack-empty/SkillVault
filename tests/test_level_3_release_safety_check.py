import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "code" / "scripts" / "release_safety_check.py"
SPEC = importlib.util.spec_from_file_location("release_safety_check", SCRIPT_PATH)
release_safety_check = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = release_safety_check
SPEC.loader.exec_module(release_safety_check)

MAKE_RELEASE_PATH = Path(__file__).resolve().parents[1] / "code" / "scripts" / "make_clean_release.py"
MAKE_SPEC = importlib.util.spec_from_file_location("make_clean_release", MAKE_RELEASE_PATH)
make_clean_release = importlib.util.module_from_spec(MAKE_SPEC)
assert MAKE_SPEC.loader is not None
sys.modules[MAKE_SPEC.name] = make_clean_release
MAKE_SPEC.loader.exec_module(make_clean_release)


def _run(root: Path, **kwargs):
    (root / ".gitignore").write_text(
        "\n".join(
            [
                "asg/vm_config.json",
                "asg/vm_config.local.json",
                ".env",
                "*.pem",
                "*.key",
                "**/honeypot_bundle.json",
                "**/fake_homes/",
                "analysis_results/private/",
                "analysis_results/controlled_sinkhole_dynamic/",
                "analysis_results/real_skill_intake/quarantine/",
                "__pycache__/",
                ".pytest_cache/",
                "*.pyc",
                "*.pcap",
                "*.pcapng",
            ]
        ),
        encoding="utf-8",
    )
    return release_safety_check.run_release_safety_check(
        repo_root=root,
        output_dir=root / "analysis_results" / "release_safety_check",
        write_reports=False,
        **kwargs,
    )


class Level3ReleaseSafetyCheckTests(unittest.TestCase):
    def test_detects_real_api_key_pattern(self):
        secret = "sk-LANYI-" + "xxx123SECRET"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "leak.txt").write_text(f"token {secret}", encoding="utf-8")

            report = _run(root)

        self.assertTrue(any(
            f["severity"] == "CRITICAL" and f["pattern_name"] == "lanyi_sk"
            for f in report["findings"]
        ))

    def test_ignores_asg_fake_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.txt").write_text(
                "OPENAI_API_KEY=ASG_FAKE_OPENAI_KEY_ABC123456789",
                encoding="utf-8",
            )

            report = _run(root)

        self.assertFalse(any(
            f["severity"] == "CRITICAL" and f["category"] == "secret_pattern"
            for f in report["findings"]
        ))

    def test_detects_vm_config_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "asg").mkdir()
            (root / "asg" / "vm_config.json").write_text("{}", encoding="utf-8")

            report = _run(root)

        self.assertTrue(any(
            f["severity"] == "CRITICAL" and f["category"] == "vm_config"
            for f in report["findings"]
        ))

    def test_detects_private_key_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "key.txt").write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
                encoding="utf-8",
            )

            report = _run(root)

        self.assertTrue(any(
            f["severity"] == "CRITICAL" and f["category"] == "private_key"
            for f in report["findings"]
        ))

    def test_detects_full_honeypot_marker_in_public_artifact(self):
        marker = "ASG_CANARY_OPENAI_ABCDEF123456"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dashboard.html").write_text(marker, encoding="utf-8")

            report = _run(root)

        self.assertTrue(any(
            f["category"] == "honeypot_marker"
            and f["severity"] in {"HIGH", "CRITICAL"}
            for f in report["findings"]
        ))

    def test_redacted_preview_does_not_expose_secret(self):
        secret = "sk-LANYI-" + "xxx123SECRET"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "leak.txt").write_text(f"token {secret}", encoding="utf-8")

            report = _run(root)

        previews = [f["redacted_preview"] for f in report["findings"]]
        self.assertFalse(any(secret in preview for preview in previews))
        self.assertTrue(any("***REDACTED***" in preview for preview in previews))

    def test_gitignore_required_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("*.pyc\n", encoding="utf-8")

            checker = release_safety_check.ReleaseSafetyChecker(root)
            report = checker.run(write_reports=False)

        self.assertTrue(any(
            f["category"] == "gitignore" and f["pattern_name"] == "missing:asg/vm_config.json"
            for f in report["findings"]
        ))
        self.assertTrue(any(
            f["category"] == "gitignore" and f["pattern_name"] == "missing:.env"
            for f in report["findings"]
        ))

    def test_large_file_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "blob.bin").write_bytes(b"x" * 128)

            report = _run(
                root,
                large_warning_bytes=64,
                large_high_bytes=1024,
                large_critical_bytes=2048,
            )

        self.assertTrue(any(
            f["category"] == "large_file" and f["severity"] == "WARNING"
            for f in report["findings"]
        ))

    def test_clean_release_excludes_vm_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_source_fixture(root)
            (root / "asg" / "vm_config.json").write_text('{"password":"secret"}', encoding="utf-8")
            release_dir = make_clean_release.make_clean_release(root, root / "dist" / "clean")

        self.assertFalse((release_dir / "asg" / "vm_config.json").exists())

    def test_clean_release_excludes_honeypot_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_source_fixture(root)
            (root / "asg" / "sample").mkdir(parents=True)
            (root / "asg" / "sample" / "honeypot_bundle.json").write_text("{}", encoding="utf-8")
            release_dir = make_clean_release.make_clean_release(root, root / "dist" / "clean")

        self.assertFalse(any(release_dir.rglob("honeypot_bundle.json")))

    def test_clean_release_excludes_fake_home_env_and_ssh_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_source_fixture(root)
            fake_home = root / "asg" / "fake_homes" / "sample_001"
            (fake_home / ".ssh").mkdir(parents=True)
            (fake_home / ".env").write_text("OPENAI_API_KEY=ASG_FAKE_OPENAI_KEY_TEST", encoding="utf-8")
            (fake_home / ".ssh" / "id_rsa").write_text("fake key", encoding="utf-8")
            release_dir = make_clean_release.make_clean_release(root, root / "dist" / "clean")

        self.assertFalse(any(path.name == ".env" for path in release_dir.rglob(".env")))
        self.assertFalse(any(path.name == "id_rsa" for path in release_dir.rglob("id_rsa")))

    def test_release_check_accepts_root_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_source_fixture(root)
            exit_code = release_safety_check.main([
                "--root",
                str(root),
                "--output-dir",
                str(root / "out"),
            ])

        self.assertEqual(exit_code, 0)

    def test_clean_release_does_not_contain_full_canary_marker(self):
        marker = "ASG_CANARY_OPENAI_ABCDEF123456"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_source_fixture(root)
            (root / "README.md").write_text(f"marker={marker}", encoding="utf-8")
            release_dir = make_clean_release.make_clean_release(root, root / "dist" / "clean")
            text = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in release_dir.rglob("*")
                if path.is_file() and path.suffix in {".md", ".json", ".py", ".html", ".txt"}
            )

        self.assertNotIn(marker, text)
        self.assertIn("ASG_CANARY_***REDACTED***", text)

    def test_clean_release_passes_on_sanitized_tree(self):
        marker = "ASG_CANARY_OPENAI_ABCDEF123456"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_source_fixture(root)
            (root / "asg" / "vm_config.json").write_text('{"password":"secret"}', encoding="utf-8")
            (root / "asg" / "sample").mkdir(parents=True)
            (root / "asg" / "sample" / "honeypot_bundle.json").write_text(marker, encoding="utf-8")
            (root / "analysis_results" / "controlled_sinkhole_dynamic" / "fake_homes" / "sample" / ".ssh").mkdir(parents=True)
            (root / "analysis_results" / "controlled_sinkhole_dynamic" / "fake_homes" / "sample" / ".env").write_text("OPENAI_API_KEY=bad", encoding="utf-8")
            (root / "analysis_results" / "controlled_sinkhole_dynamic" / "fake_homes" / "sample" / ".ssh" / "id_rsa").write_text("bad", encoding="utf-8")

            release_dir = make_clean_release.make_clean_release(root, root / "dist" / "clean")
            report = release_safety_check.run_release_safety_check(
                repo_root=release_dir,
                output_dir=release_dir / "analysis_results" / "release_safety_check",
                write_reports=False,
            )

        self.assertTrue(report["passed"])


def _write_source_fixture(root: Path) -> None:
    (root / "asg").mkdir(parents=True, exist_ok=True)
    (root / "code" / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "web_ui").mkdir(parents=True, exist_ok=True)
    (root / "dashboard").mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "competition_materials").mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("clean release fixture\n", encoding="utf-8")
    (root / "ASG_NEW_FEATURES.md").write_text("level_3 fixture\n", encoding="utf-8")
    (root / "ASG_HANDOFF_FOR_AI.md").write_text("handoff fixture\n", encoding="utf-8")
    (root / "asg" / "README.md").write_text("asg fixture\n", encoding="utf-8")
    (root / "code" / "scripts" / "tool.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "web_ui" / "README.md").write_text("web fixture\n", encoding="utf-8")
    (root / "dashboard" / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (root / "docs" / "README.md").write_text("docs fixture\n", encoding="utf-8")
    (root / "competition_materials" / "README.md").write_text("competition fixture\n", encoding="utf-8")
    _run(root)


if __name__ == "__main__":
    unittest.main()
