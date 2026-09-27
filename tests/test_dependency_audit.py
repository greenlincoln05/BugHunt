"""The local npm advisory helper never installs code or treats a match as a finding."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest

from bughunt.dependency_audit import audit_npm_dependencies


class DependencyAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "clone"
        self.workspace.mkdir()
        (self.workspace / "package.json").write_text('{"name":"sample","version":"1.0.0"}', encoding="utf-8")
        (self.workspace / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
        self.output = self.root / "reports" / "audit.json"
        tracked = {"package.json", "package-lock.json"}
        self.tracked = patch("bughunt.dependency_audit._tracked_files", return_value=tracked)
        self.tracked.start()
        self.addCleanup(self.tracked.stop)

    def test_isolated_audit_records_unverified_leads(self):
        report = {"vulnerabilities": {"sample-dep": {
            "severity": "high", "isDirect": True, "range": "<2.0.0",
            "via": [{"title": "Example advisory", "url": "https://github.com/advisories/example"}]}},
            "metadata": {"vulnerabilities": {"high": 1, "total": 1}}}
        run = SimpleNamespace(returncode=1, stdout=json.dumps(report).encode(), stderr=b"")
        with patch("bughunt.dependency_audit.shutil.which", return_value="npm.cmd"), \
             patch("bughunt.dependency_audit.subprocess.run", return_value=run) as process, \
             patch.dict("bughunt.dependency_audit.os.environ", {"OPENAI_API_KEY": "must-not-escape", "NODE_OPTIONS": "--bad"}):
            result = audit_npm_dependencies(self.workspace, self.output)
        saved = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(result["lead_count"], 1)
        self.assertFalse(result["finding_confirmed"])
        self.assertEqual(saved["leads"][0]["package"], "sample-dep")
        self.assertNotEqual(process.call_args.kwargs["cwd"], self.workspace)
        self.assertNotIn("OPENAI_API_KEY", process.call_args.kwargs["env"])
        self.assertNotIn("NODE_OPTIONS", process.call_args.kwargs["env"])
        command = process.call_args.args[0]
        self.assertIn("--ignore-scripts", command)
        self.assertNotEqual(command[command.index("--userconfig") + 1],
                            command[command.index("--globalconfig") + 1])
        self.assertEqual((self.workspace / "package-lock.json").read_text(encoding="utf-8"), '{"lockfileVersion":3}')

    def test_collision_is_preserved_without_running_npm(self):
        self.output.parent.mkdir()
        self.output.write_text("keep", encoding="utf-8")
        with patch("bughunt.dependency_audit.subprocess.run") as process:
            with self.assertRaisesRegex(ValueError, "already exists"):
                audit_npm_dependencies(self.workspace, self.output)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "keep")
        process.assert_not_called()

    def test_output_must_be_outside_source(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            audit_npm_dependencies(self.workspace, self.workspace / "audit.json")

    def test_registry_failure_removes_empty_output(self):
        run = SimpleNamespace(returncode=1, stdout=b'{"error":{"summary":"unavailable"}}', stderr=b"")
        with patch("bughunt.dependency_audit.shutil.which", return_value="npm.cmd"), \
             patch("bughunt.dependency_audit.subprocess.run", return_value=run):
            with self.assertRaisesRegex(ValueError, "could not retrieve advisories"):
                audit_npm_dependencies(self.workspace, self.output)
        self.assertFalse(self.output.exists())

    def test_requires_tracked_root_lockfile(self):
        with patch("bughunt.dependency_audit._tracked_files", return_value={"package.json"}):
            with self.assertRaisesRegex(ValueError, "track a root package-lock.json"):
                audit_npm_dependencies(self.workspace, self.output)


if __name__ == "__main__":
    unittest.main()
