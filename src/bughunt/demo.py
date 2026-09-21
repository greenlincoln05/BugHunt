"""Fictitious, offline data exercises the complete local workflow."""

from datetime import timedelta

from .reports import generate_reports
from .workflow import stamp


def run_demo(app, output_dir):
    store = app.store
    if any(store.list(table) for table in ("programs", "findings", "submissions", "payments")):
        raise ValueError("Demo requires an empty database. Choose a fresh --db path, or inspect existing demo reports.")
    now = app.clock()
    program = dict(id="demo-local", name="DEMO ONLY — fictitious localhost program", platform="manual",
                   program_url="http://127.0.0.1:8000", status="active", automation_allowed=True,
                   scope=["http://127.0.0.1:8000"], excluded_scope=["http://127.0.0.1:8000/admin"],
                   verified_at=stamp(now), verification_expires_at=stamp(now + timedelta(hours=24)),
                   blocked_reason=None, verification_note="Synthetic policy for offline demonstration, not a real authorization.",
                   payout_min="50", payout_max="200", currency="USD")
    with store.transaction():
        store.save("programs", program)
        store.audit("demo.created", "programs", program["id"], stamp(now), {"synthetic": True, "network_requests": 0})
    for number, amount in ((1, "100"), (2, "200")):
        finding = app.add_finding(program["id"], target=f"http://127.0.0.1:8000/demo-{number}",
                                  title=f"DEMO ONLY — synthetic finding {number}", vulnerability_type="demo_validation",
                                  severity="low", reproduction="Synthetic fixture: no vulnerability was tested or discovered.",
                                  impact="Demonstrates local reporting only; no real security impact.")
        app.confirm_finding(finding["id"], "Synthetic confirmation for the offline demo only.")
        app.record_patch(finding["id"], patch_status="not_applicable", verification="Synthetic fixture has no actual code defect.")
        submission = app.draft_submission(finding["id"])
        app.record_submission(submission["id"], f"DEMO-NOT-SUBMITTED-{number}")
        app.accept_submission(submission["id"], "Synthetic acknowledgment. No company accepted this fixture.")
        payment = app.add_payment(submission["id"], amount, "USD", (now + timedelta(days=7)).date().isoformat())
        if number == 1:
            app.receive_payment(payment["id"], "Synthetic receipt. No money was received.")
    paths = generate_reports(store.snapshot(), output_dir, now=app.clock())
    return {"demo_only": True, "network_requests": 0, "database": str(store.path.resolve()),
            "message": "All findings, submissions, and payouts in this database are fictitious.",
            "files": [str(path.resolve()) for path in paths]}
