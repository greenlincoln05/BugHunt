from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from bughunt.cli import main
from bughunt.storage import Store


SOURCE = "https://github.com/example/library"


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "bughunt.db"
        self.dossier = self.root / "dossier.json"
        store = Store(self.db)
        store.save("opportunities", {
            "id": "h1-42", "handle": "example", "name": "Example",
            "platform": "hackerone", "program_url": "https://hackerone.com/example",
            "currency": "USD", "offers_bounties": True, "submission_state": "open",
        })
        store.close()
        self.document = {
            "schema_version": 1, "source": "hackerone", "handle": "example",
            "program_url": "https://hackerone.com/example",
            "completeness": {"complete": True},
            "structured_scopes": [{
                "asset_type": "SOURCE_CODE", "asset_identifier": SOURCE,
                "reference": None, "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }],
        }
        self.write_dossier()

    def write_dossier(self):
        self.dossier.write_text(json.dumps(self.document), encoding="utf-8")

    def run_promote(self, source=SOURCE, min_amount="50", max_amount="200"):
        args = ["--db", str(self.db), "opportunity", "promote", "h1-42",
                "--dossier", str(self.dossier), "--source-url", source,
                "--payout-min", min_amount, "--payout-max", max_amount]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_promotes_only_declared_source_and_stays_unverified(self):
        code, output, error = self.run_promote()
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertFalse(result["testing_authorized"])
        self.assertTrue(result["verification_required"])
        store = Store(self.db)
        self.addCleanup(store.close)
        program = store.get("programs", "h1-42")
        self.assertEqual(program["scope"], [SOURCE])
        self.assertEqual(program["source_code_assets"], [{"url": SOURCE,
            "eligible_for_bounty": True, "eligible_for_submission": True}])
        self.assertEqual(program["payout_min"], "50")
        self.assertEqual(program["payout_max"], "200")
        self.assertFalse(program["automation_allowed"])
        self.assertIsNone(program["verified_at"])
        self.assertIsNone(program["verification_expires_at"])
        actions = [json.loads(row[0])["action"] for row in store.connection.execute("SELECT data FROM audit")]
        self.assertEqual(actions.count("opportunity.promoted"), 1)

    def test_refuses_overwrite_and_preserves_original(self):
        self.assertEqual(self.run_promote()[0], 0)
        code, _, error = self.run_promote(max_amount="500")
        self.assertEqual(code, 2)
        self.assertIn("already exists", error)
        store = Store(self.db)
        self.addCleanup(store.close)
        self.assertEqual(store.get("programs", "h1-42")["payout_max"], "200")

    def test_fails_closed_on_unrelated_or_ineligible_dossier(self):
        for change in [
            lambda d: d["completeness"].update(complete=False),
            lambda d: d.update(handle="other"),
            lambda d: d["structured_scopes"][0].update(eligible_for_bounty=False),
            lambda d: d["structured_scopes"][0].update(asset_type="URL"),
        ]:
            with self.subTest(change=change):
                original = json.loads(json.dumps(self.document))
                change(self.document)
                self.write_dossier()
                self.assertEqual(self.run_promote()[0], 2)
                self.document = original
        self.write_dossier()
        for url in ["https://github.com/other/library", "http://github.com/example/library",
                    "https://github.com/example/library?token=secret"]:
            with self.subTest(url=url):
                self.assertEqual(self.run_promote(source=url)[0], 2)
        self.assertEqual(self.run_promote(min_amount="200", max_amount="50")[0], 2)
        store = Store(self.db)
        self.addCleanup(store.close)
        self.assertEqual(store.list("programs"), [])

    def test_policy_without_cash_blocks_stale_bounty_metadata(self):
        store = Store(self.db)
        candidate = store.get("opportunities", "h1-42")
        candidate["policy"] = "This is a vulnerability disclosure program without monetary rewards (bounties)."
        store.save("opportunities", candidate)
        store.close()
        code, _, error = self.run_promote()
        self.assertEqual(code, 2)
        self.assertIn("not an open HackerOne bounty candidate", error)


if __name__ == "__main__":
    unittest.main()
