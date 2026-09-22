"""Local source-code clone helper: HTTPS-only, no credentials, no overwrite,
no real network access in tests -- `git` invocation itself is mocked, matching
this project's offline test suite (see hackerone/model_access for the same
pattern at the HTTP layer)."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import tempfile
import unittest

from bughunt.workspace import MAX_DEPTH, MIN_DEPTH, clone_source


def completed(returncode=0, stdout=b"", stderr=b""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class WorkspaceValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rejects_non_https_transports(self):
        for url in ("ssh://git@example.com/x/y.git", "git://example.com/x/y.git",
                    "ext::sh -c 'touch pwned'", "file:///etc/passwd", "http://example.com/x/y.git"):
            with self.assertRaises(ValueError):
                clone_source(url, self.root / "dest")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            clone_source("https://user:pass@example.com/x/y.git", self.root / "dest")

    def test_rejects_url_without_path(self):
        with self.assertRaises(ValueError):
            clone_source("https://example.com", self.root / "dest")

    def test_rejects_existing_destination(self):
        target = self.root / "dest"
        target.mkdir()
        with self.assertRaises(ValueError):
            clone_source("https://example.com/x/y.git", target)

    def test_rejects_out_of_range_depth(self):
        for depth in (MIN_DEPTH - 1, MAX_DEPTH + 1, 0, -1):
            with self.assertRaises(ValueError):
                clone_source("https://example.com/x/y.git", self.root / "dest", depth=depth)


class WorkspaceCloneTests(unittest.TestCase):
    """No real git process runs here; `subprocess.run` is mocked so these stay offline."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_successful_clone_reports_head_and_branch(self):
        with patch("bughunt.workspace.subprocess.run", side_effect=[
            completed(0),
            completed(0, stdout=b"deadbeef00\n"),
            completed(0, stdout=b"main\n"),
        ]) as run:
            result = clone_source("https://example.com/octocat/hello.git", self.root / "dest", depth=5)
        self.assertEqual(result["head"], "deadbeef00")
        self.assertEqual(result["branch"], "main")
        self.assertEqual(result["depth"], 5)
        clone_call = run.call_args_list[0]
        self.assertIn("--depth", clone_call.args[0])
        self.assertIn("5", clone_call.args[0])
        self.assertIn("--", clone_call.args[0])
        self.assertEqual(clone_call.kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")

    def test_clone_failure_surfaces_git_stderr(self):
        with patch("bughunt.workspace.subprocess.run", return_value=completed(128, stderr=b"fatal: repository not found")):
            with self.assertRaises(ValueError) as caught:
                clone_source("https://example.com/octocat/missing.git", self.root / "dest")
        self.assertIn("repository not found", str(caught.exception))

    def test_clone_timeout_is_reported_not_hung(self):
        with patch("bughunt.workspace.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=300)):
            with self.assertRaises(ValueError) as caught:
                clone_source("https://example.com/octocat/slow.git", self.root / "dest")
        self.assertIn("timed out", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
