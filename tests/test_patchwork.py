"""Local patch-workspace evidence capture: no network, no target contact."""

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from bughunt.patchwork import MAX_TIMEOUT_SECONDS, MIN_TIMEOUT_SECONDS, capture_regression


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)


class PatchworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        git("init", "-q", cwd=self.workspace)
        git("-c", "user.email=a@b.c", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init", cwd=self.workspace)
        self.now = datetime(2026, 9, 22, 12, tzinfo=timezone.utc)

    def test_passing_command_is_captured_with_real_output(self):
        result = capture_regression(self.workspace, "echo regression-ok", timeout_seconds=10, clock=lambda: self.now)
        self.assertTrue(result["passed"])
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["timed_out"])
        self.assertIn("regression-ok", result["stdout"])
        self.assertEqual(result["captured_at"], "2026-09-22T12:00:00Z")
        self.assertFalse(result["diff_present"])

    def test_failing_command_is_captured_not_hidden(self):
        result = capture_regression(self.workspace, "python -c \"import sys; sys.exit(1)\"", timeout_seconds=10)
        self.assertFalse(result["passed"])
        self.assertEqual(result["exit_code"], 1)
        self.assertFalse(result["timed_out"])

    def test_timeout_is_captured_not_hung(self):
        result = capture_regression(self.workspace, "python -c \"import time; time.sleep(30)\"", timeout_seconds=MIN_TIMEOUT_SECONDS)
        self.assertFalse(result["passed"])
        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["exit_code"])

    def test_uncommitted_diff_is_captured(self):
        (self.workspace / "lib.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        git("add", "lib.py", cwd=self.workspace)
        result = capture_regression(self.workspace, "echo ok", timeout_seconds=10)
        self.assertTrue(result["diff_present"])
        self.assertIn("lib.py", result["diff_stat"])
        self.assertIn("+def add", result["diff"])

    def test_non_git_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as plain:
            with self.assertRaises(ValueError):
                capture_regression(plain, "echo hi", timeout_seconds=10)

    def test_missing_directory_is_refused(self):
        with self.assertRaises(ValueError):
            capture_regression(self.workspace / "does-not-exist", "echo hi", timeout_seconds=10)

    def test_blank_command_is_refused(self):
        with self.assertRaises(ValueError):
            capture_regression(self.workspace, "   ", timeout_seconds=10)

    def test_timeout_bounds_are_enforced(self):
        for bad in (MIN_TIMEOUT_SECONDS - 1, MAX_TIMEOUT_SECONDS + 1, 0, -1):
            with self.assertRaises(ValueError):
                capture_regression(self.workspace, "echo hi", timeout_seconds=bad)

    def test_large_output_is_truncated_not_dropped(self):
        result = capture_regression(self.workspace, "python -c \"print('x' * 100000)\"", timeout_seconds=10)
        self.assertTrue(result["stdout_truncated"])
        self.assertLessEqual(len(result["stdout"].encode("utf-8")), 32 * 1024)


if __name__ == "__main__":
    unittest.main()
