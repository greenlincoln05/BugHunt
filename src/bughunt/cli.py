"""Local workflow commands and explicit read-only platform discovery."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

from .catalog import rank_programs
from .reports import generate_reports
from .storage import Store, SCHEMA_VERSION
from .workflow import Workflow, stamp, utc_now


def build_parser():
    parser = argparse.ArgumentParser(description="Local bug bounty workflow; no target scanning or automatic submissions.")
    parser.add_argument("--db", type=Path, help="SQLite database (default .bughunt/bughunt.db; demo uses demo.db)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize the local database")
    commands.add_parser("setup", help="Show account/credential readiness without revealing secrets")
    model = commands.add_parser("model", help="Check explicit OpenAI model configuration without inference").add_subparsers(dest="action", required=True)
    model.add_parser("status", help="Local configuration presence only; no network request")
    model.add_parser("check", help="Read model metadata; does not prove Trusted Access approval")
    item = commands.add_parser("progress", help="Show first-dollar receipt evidence and next actions")
    item.add_argument("--out", type=Path, help="Also write first_dollar.json and first_dollar.md")
    item.add_argument("--source-db", type=Path, help="Read a live database from another checkout without modifying it; cannot combine with --db")
    worker = commands.add_parser("worker", help="Unattended read-only opportunity discovery").add_subparsers(dest="action", required=True)
    worker.add_parser("status")
    worker.add_parser("stop")
    item = worker.add_parser("resume")
    item.add_argument("--note", required=True)
    for action in ("once", "run"):
        item = worker.add_parser(action)
        item.add_argument("--max-pages", type=int, default=3)
        item.add_argument("--interval-seconds", type=int, default=900)
        item.add_argument("--out", type=Path, default=Path("reports/discovery"))
        if action == "run":
            item.add_argument("--max-cycles", type=int, default=0)
    opportunity = commands.add_parser("opportunity", help="Inspect discovered candidates, not authorized targets").add_subparsers(dest="action", required=True)
    opportunity.add_parser("list")
    item = opportunity.add_parser("dossier", help="Fetch official scope metadata for a discovered candidate")
    item.add_argument("id", help="Discovered opportunity ID, for example h1-123")
    item.add_argument("--max-pages", type=int, default=3)
    item.add_argument("--output", type=Path, required=True)
    item = opportunity.add_parser("export")
    item.add_argument("--out", type=Path, default=Path("reports/discovery"))
    workspace = commands.add_parser("workspace", help="Local analysis workspaces for a program's own declared source, never a live target").add_subparsers(dest="action", required=True)
    item = workspace.add_parser("clone", help="Clone one declared source-code asset (pick the URL yourself from a dossier's source_code_assets)")
    item.add_argument("--url", required=True, help="https:// Git remote; see a dossier's source_code_assets[].reference")
    item.add_argument("--into", type=Path, required=True, help="Destination directory; must not already exist")
    item.add_argument("--depth", type=int, default=1, help="Shallow-clone depth (1-1000)")
    program = commands.add_parser("program", help="Import, verify, and shortlist program policies").add_subparsers(dest="action", required=True)
    item = program.add_parser("import")
    item.add_argument("path", type=Path)
    program.add_parser("list")
    item = program.add_parser("shortlist", help="Rank imported advertised payout ranges; defaults to USD 50-2000, not a ceiling")
    item.add_argument("--min-payout", default="50")
    item.add_argument("--max-payout", default="2000")
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
    item = finding.add_parser("evidence", help="Run a regression command in a local patch workspace and capture real output (does not mark a patch verified)")
    item.add_argument("id")
    item.add_argument("--workspace", type=Path, required=True, help="Existing Git checkout of source the program has made available; never a live target")
    item.add_argument("--command", dest="regression_command", required=True, help="Exact command to run inside the workspace, e.g. \"pytest tests/test_fix.py\"")
    item.add_argument("--timeout", type=int, default=300, help="Seconds before the command is killed (5-1800)")
    item.add_argument("--output", type=Path)
    item = finding.add_parser("patch")
    item.add_argument("id")
    item.add_argument("--status", choices=["not_started", "in_progress", "ready", "verified", "not_applicable"], required=True)
    item.add_argument("--reference")
    item.add_argument("--verification")
    item.add_argument("--evidence-file", type=Path, help="A `finding evidence` output file; fills --reference/--verification from it "
                       "instead of retyping them. Refused for --status verified unless that file shows a passing run.")
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
    item.add_argument("--receipt-reference", help="Unique platform receipt reference (user attestation)")
    item.add_argument("--received-at", help="Actual timezone-aware receipt timestamp; defaults to now")
    item = commands.add_parser("reports")
    item.add_argument("--out", type=Path, default=Path("reports"))
    commands.add_parser("audit", help="Read the timestamped activity log")
    item = commands.add_parser("demo", help="Create clearly fictitious localhost records in a separate database")
    item.add_argument("--out", type=Path, default=Path("reports/demo"))
    return parser


def dispatch(args, store):
    app = Workflow(store)
    if args.command == "init":
        return {"database": str(store.path.resolve()), "schema_version": SCHEMA_VERSION}
    if args.command == "model":
        from .model_access import model_readiness
        return model_readiness(check_access=args.action == "check")
    if args.command == "progress":
        from .progress import build_progress, export_progress
        from .storage import read_snapshot
        snapshot = read_snapshot(args.source_db) if args.source_db else store.snapshot()
        document = build_progress(snapshot, credentials_present=bool(
            os.environ.get("HACKERONE_USERNAME") and os.environ.get("HACKERONE_API_TOKEN")))
        document["source_database"] = str((args.source_db or store.path).resolve())
        if args.out:
            document["files"] = export_progress(document, args.out)
        return document
    if args.command == "setup":
        return {"hackerone": {"integration": "read-only program discovery", "create_account": "https://hackerone.com/users/sign_up",
                "token_instructions": "https://docs.hackerone.com/en/articles/8410331-api-token",
                "api_identifier_present": bool(os.environ.get("HACKERONE_USERNAME")),
                "api_token_present": bool(os.environ.get("HACKERONE_API_TOKEN")),
                "next_step": "Configure API token identifier and token locally, then run worker once. No live access is checked here."},
                "bugcrowd": {"integration": "manual catalog/report export", "create_account": "https://login.hackers.bugcrowd.com/signin/register"},
                "intigriti": {"integration": "manual catalog/report export", "create_account": "https://app.intigriti.com/"},
                "account_guide": "docs/accounts-and-afk.md", "paid_services_required": False,
                "notice": "Accounts alone do not authorize automated testing; verify each program's current policy."}
    if args.command == "worker":
        from .worker import DiscoveryWorker
        worker = DiscoveryWorker(store)
        if args.action == "status":
            return worker.status()
        if args.action == "stop":
            return worker.stop()
        if args.action == "resume":
            return worker.resume(args.note)
        options = dict(max_pages=args.max_pages, interval_seconds=args.interval_seconds, output_dir=args.out)
        if args.action == "once":
            return worker.cycle(**options)
        return worker.run(max_cycles=args.max_cycles, **options)
    if args.command == "opportunity":
        if args.action == "list":
            return store.list("opportunities")
        if args.action == "dossier":
            from .dossier import fetch_program_dossier
            from .hackerone import HackerOneClient
            candidate = store.get("opportunities", args.id)
            if args.output.exists():
                raise ValueError("Dossier output already exists; choose a new path")
            document = fetch_program_dossier(HackerOneClient.from_environment(), candidate["handle"], max_pages=args.max_pages)
            document["opportunity"] = candidate
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2, allow_nan=False)
                handle.write("\n")
            with store.transaction():
                store.audit("opportunity.dossier_exported", "opportunities", args.id, stamp(app.clock()),
                            {"output": str(args.output.resolve()), "complete": document["completeness"]["complete"]})
            return {"output": str(args.output.resolve()), "complete": document["completeness"]["complete"],
                    "source_code_assets": len(document.get("source_code_assets") or []),
                    "review_needed": True, "testing_authorized": False}
        from .worker import DiscoveryWorker
        return {"files": DiscoveryWorker(store).export(args.out)}
    if args.command == "workspace":
        from .workspace import clone_source
        result = clone_source(args.url, args.into, depth=args.depth)
        with store.transaction():
            store.audit("workspace.cloned", "workspace", str(args.into.resolve()), stamp(app.clock()),
                        {"url": args.url, "depth": args.depth})
        return result
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
                    handle.write("\n")
                app.record_brief(args.id)
                return {"output": str(args.output.resolve()), "assignee": "Astra"}
            return brief
        if args.action == "evidence":
            from .patchwork import capture_regression
            app.require_confirmed_finding(args.id)
            evidence = capture_regression(args.workspace, args.regression_command, timeout_seconds=args.timeout, clock=app.clock)
            evidence["finding_id"] = args.id
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("x", encoding="utf-8") as handle:
                    json.dump(evidence, handle, indent=2, ensure_ascii=False, allow_nan=False)
                    handle.write("\n")
                app.record_evidence(args.id, evidence)
                return {"output": str(args.output.resolve()), "passed": evidence["passed"],
                        "exit_code": evidence["exit_code"], "timed_out": evidence["timed_out"]}
            return evidence
        reference, verification = args.reference, args.verification
        if args.evidence_file:
            try:
                evidence = json.loads(args.evidence_file.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise ValueError(f"Could not read --evidence-file: {error}") from error
            if not isinstance(evidence, dict) or "passed" not in evidence:
                raise ValueError("--evidence-file does not look like a `finding evidence` output file")
            if args.status == "verified" and evidence.get("passed") is not True:
                raise ValueError("--evidence-file does not show a passing regression; review manually before marking verified")
            reference = reference or str(args.evidence_file.resolve())
            verification = verification or (
                f"Captured via `finding evidence`: command `{evidence.get('command')}` "
                f"exit_code={evidence.get('exit_code')} timed_out={evidence.get('timed_out')} "
                f"passed={evidence.get('passed')} at {evidence.get('captured_at')}. "
                f"diff_present={evidence.get('diff_present')}. Full stdout/stderr/diff in {args.evidence_file.resolve()}.")
        return app.record_patch(args.id, patch_status=args.status, reference=reference, verification=verification)
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
        return app.receive_payment(args.id, args.note, receipt_reference=args.receipt_reference, received_at=args.received_at)
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
        external_snapshot = args.command == "progress" and args.source_db is not None
        if external_snapshot and args.db is not None:
            raise ValueError("Use either progress --source-db or --db, not both")
        if not external_snapshot:
            store = Store(path)
        result = dispatch(args, store)
        # ASCII escapes preserve arbitrary program titles across Windows consoles.
        print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False), flush=True)
        if args.command == "finding" and args.action == "brief" and args.output is None:
            # Only acknowledge delivery once serialization, writing, and flushing succeeded.
            Workflow(store).record_brief(args.id)
        if args.command == "finding" and args.action == "evidence" and args.output is None:
            Workflow(store).record_evidence(args.id, result)
        if args.command == "worker" and args.action in {"once", "run"} and result.get("outcome") == "paused":
            return 4
        if args.command == "model" and args.action == "check" and result.get("model_retrievable") is not True:
            return 4
        return 3 if args.command == "scope" and not result["allowed"] else 0
    except KeyboardInterrupt:
        print("bughunt: worker interrupted; saved progress is retained", file=sys.stderr)
        return 130
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
