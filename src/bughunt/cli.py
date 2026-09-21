"""Command line entry point. All operations are local and explicitly recorded."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from .catalog import rank_programs
from .reports import generate_reports
from .storage import Store
from .workflow import Workflow, stamp, utc_now


def build_parser():
    parser = argparse.ArgumentParser(description="Local bug bounty workflow; no target scanning or automatic submissions.")
    parser.add_argument("--db", type=Path, help="SQLite database (default .bughunt/bughunt.db; demo uses demo.db)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize the local database")
    program = commands.add_parser("program", help="Import, verify, and shortlist program policies").add_subparsers(dest="action", required=True)
    item = program.add_parser("import")
    item.add_argument("path", type=Path)
    program.add_parser("list")
    item = program.add_parser("shortlist", help="Rank imported advertised payout ranges; defaults to USD 50-200")
    item.add_argument("--min-payout", default="50")
    item.add_argument("--max-payout", default="200")
    item.add_argument("--currency", default="USD")
    item.add_argument("--limit", type=int, default=10)
    item = program.add_parser("verify", help="Record your check of active bounty, scope, and automation permission")
    item.add_argument("id")
    item.add_argument("--note", required=True)
    item.add_argument("--automation-allowed", action="store_true", required=True)
    item.add_argument("--valid-hours", type=int, default=24)
    for action, option in (("block", "reason"), ("unblock", "note")):
        item = program.add_parser(action)
        item.add_argument("id")
        item.add_argument("--" + option, required=True)
    item = commands.add_parser("scope", help="Check a URL against recorded policy (does not contact target)")
    item.add_argument("program_id")
    item.add_argument("target")
    item = commands.add_parser("audit-target", help="Record an audit you have actually completed")
    item.add_argument("program_id")
    item.add_argument("target")
    item.add_argument("--note", required=True)
    finding = commands.add_parser("finding").add_subparsers(dest="action", required=True)
    finding.add_parser("list")
    item = finding.add_parser("add")
    item.add_argument("program_id")
    item.add_argument("--target", required=True)
    item.add_argument("--title", required=True)
    item.add_argument("--type", dest="vulnerability_type", required=True)
    item.add_argument("--severity", choices=["informational", "low", "medium", "high", "critical"], required=True)
    item.add_argument("--reproduction-file", type=Path, required=True)
    item.add_argument("--impact", required=True)
    item.add_argument("--cvss", dest="cvss_score")
    item = finding.add_parser("confirm")
    item.add_argument("id")
    item.add_argument("--evidence", required=True)
    item = finding.add_parser("brief", help="Write a patch task for Astra (who writes the CVE/bug fix)")
    item.add_argument("id")
    item.add_argument("--output", type=Path)
    item = finding.add_parser("patch")
    item.add_argument("id")
    item.add_argument("--status", choices=["not_started", "in_progress", "ready", "verified", "not_applicable"], required=True)
    item.add_argument("--reference")
    item.add_argument("--verification")
    submission = commands.add_parser("submission").add_subparsers(dest="action", required=True)
    submission.add_parser("list")
    for action in ("draft", "export", "record", "reject", "review", "accept", "error", "resume"):
        item = submission.add_parser(action)
        item.add_argument("id", help="Finding ID for draft, submission ID otherwise")
        if action == "export":
            item.add_argument("--output", type=Path, required=True)
        elif action == "record":
            item.add_argument("--external-id", required=True)
        elif action == "reject":
            item.add_argument("--reason", required=True)
        elif action in {"review", "accept", "error", "resume"}:
            item.add_argument("--note", required=True)
        if action == "accept":
            item.add_argument("--expected-payment-date")
        if action == "error":
            item.add_argument("--kind", choices=["rate_limit", "authentication", "unclear_status", "downtime"], required=True)
    payment = commands.add_parser("payment").add_subparsers(dest="action", required=True)
    payment.add_parser("list")
    item = payment.add_parser("add")
    item.add_argument("submission_id")
    item.add_argument("--amount", required=True)
    item.add_argument("--currency", default="USD")
    item.add_argument("--expected-date")
    item = payment.add_parser("receive")
    item.add_argument("id")
    item.add_argument("--note", required=True)
    item = commands.add_parser("reports")
    item.add_argument("--out", type=Path, default=Path("reports"))
    commands.add_parser("audit", help="Read the timestamped activity log")
    item = commands.add_parser("demo", help="Create clearly fictitious localhost records in a separate database")
    item.add_argument("--out", type=Path, default=Path("reports/demo"))
    return parser


def dispatch(args, store):
    app = Workflow(store)
    if args.command == "init":
        return {"database": str(store.path.resolve()), "schema_version": 1}
    if args.command == "program":
        if args.action == "import":
            return app.import_programs(args.path)
        if args.action == "list":
            return store.list("programs")
        if args.action == "shortlist":
            return rank_programs(store.list("programs"), args.min_payout, args.max_payout, args.currency, args.limit)
        if args.action == "verify":
            return app.verify_program(args.id, note=args.note, valid_hours=args.valid_hours, automation_allowed=args.automation_allowed)
        if args.action == "block":
            return app.block_program(args.id, args.reason)
        return app.unblock_program(args.id, args.note)
    if args.command == "scope":
        return app.scope_check(args.program_id, args.target)
    if args.command == "audit-target":
        return app.record_audit(args.program_id, args.target, args.note)
    if args.command == "finding":
        if args.action == "list":
            return store.list("findings")
        if args.action == "add":
            return app.add_finding(args.program_id, target=args.target, title=args.title,
                                   vulnerability_type=args.vulnerability_type, severity=args.severity,
                                   reproduction=args.reproduction_file.read_text(encoding="utf-8"),
                                   impact=args.impact, cvss_score=args.cvss_score)
        if args.action == "confirm":
            return app.confirm_finding(args.id, args.evidence)
        if args.action == "brief":
            brief = app.patch_brief(args.id)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("x", encoding="utf-8") as handle:
                    json.dump(brief, handle, indent=2, ensure_ascii=False, allow_nan=False)
                    handle.write("
")
                return {"output": str(args.output.resolve()), "assignee": "Astra"}
            return brief
        return app.record_patch(args.id, patch_status=args.status, reference=args.reference, verification=args.verification)
    if args.command == "submission":
        if args.action == "list":
            return store.list("submissions")
        if args.action == "draft":
            return app.draft_submission(args.id)
        if args.action == "export":
            bundle = app.submission_bundle(args.id)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive create avoids overwriting evidence or other local files.
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(bundle, handle, indent=2, ensure_ascii=False, allow_nan=False)
                handle.write("\n")
            with store.transaction():
                app._audit("submission.exported", "submissions", bundle["submission"], output=str(args.output.resolve()))
            return {"output": str(args.output.resolve()), "submitted": False}
        if args.action == "record":
            return app.record_submission(args.id, args.external_id)
        if args.action == "reject":
            return app.reject_submission(args.id, args.reason)
        if args.action == "review":
            return app.review_rejection(args.id, args.note)
        if args.action == "accept":
            return app.accept_submission(args.id, args.note, args.expected_payment_date)
        if args.action == "error":
            return app.record_error(args.id, args.kind, args.note)
        return app.resume_submission(args.id, args.note)
    if args.command == "payment":
        if args.action == "list":
            return store.list("payments")
        if args.action == "add":
            return app.add_payment(args.submission_id, args.amount, args.currency, args.expected_date)
        return app.receive_payment(args.id, args.note)
    if args.command == "reports":
        paths = generate_reports(store.snapshot(), args.out)
        with store.transaction():
            store.audit("reports.generated", "reports", "all", stamp(app.clock()), {"output_dir": str(args.out.resolve())})
        return {"files": [str(path.resolve()) for path in paths]}
    if args.command == "audit":
        return store.snapshot()["audit"]
    if args.command == "demo":
        from .demo import run_demo
        return run_demo(app, args.out)
    raise ValueError("Unknown command")


def main(argv=None):
    args = build_parser().parse_args(argv)
    path = args.db or Path(".bughunt/demo.db" if args.command == "demo" else ".bughunt/bughunt.db")
    store = None
    try:
        store = Store(path)
        result = dispatch(args, store)
        # ASCII escapes preserve arbitrary program titles across Windows consoles.
        print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))
        return 3 if args.command == "scope" and not result["allowed"] else 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        if store is not None:
            try:
                with store.transaction():
                    store.audit("command.failed", "command", args.command, stamp(utc_now()),
                                {"action": getattr(args, "action", None), "reason": str(exc)})
            except sqlite3.Error:
                pass  # Report the original failure even when the database is unavailable.
        print(f"bughunt: {exc}", file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()
