"""Local first-dollar progress and a deterministic queue of next actions.

Receipt references are user attestations, not independent payment verification.
No network requests or workflow mutations happen here.
"""

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re

from .reports import _atomic_write, _table
from .scope import check_scope
from .workflow import stamp, utc_now


def _time(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


def build_progress(snapshot, *, now=None, credentials_present=False):
    now = now or utc_now()
    if now.tzinfo is None:
        raise ValueError("Progress time must be timezone-aware")
    programs = {row["id"]: row for row in snapshot.get("programs", [])}
    findings = {row["id"]: row for row in snapshot.get("findings", [])}
    submissions = {row["id"]: row for row in snapshot.get("submissions", [])}
    payments = {row["id"]: row for row in snapshot.get("payments", [])}
    demo = any(row.get("action") == "demo.created" for row in snapshot.get("audit", []))
    actions = []

    def action(kind, entity_id, message):
        actions.append({"kind": kind, "entity_id": entity_id, "next_step": message})

    jobs = snapshot.get("jobs", [])
    job = next((row for row in jobs if row.get("id") == "hackerone-discovery"), {})
    last_sync = _time(job.get("last_success_at"))
    recent_sync = last_sync is not None and now - timedelta(hours=24) <= last_sync <= now
    if demo:
        action("demo_database", None, "Use the production database; this database contains fictitious activity.")
    if not credentials_present and (not recent_sync or job.get("paused_reason") == "authentication"):
        action("credentials", None, "Make the existing HackerOne credentials available to this process; run setup to check presence without printing secrets.")
    if job.get("paused_reason"):
        action("discovery_paused", job.get("id"), "Resolve " + job["paused_reason"] + "; then run worker resume with a resolution note.")
    elif job.get("stop_requested"):
        action("discovery_stopped", job.get("id"), "Restart the discovery worker when ready.")
    elif not recent_sync:
        action("discovery_stale", job.get("id"), "Run worker once or start the worker to complete a fresh discovery snapshot; honor its backoff.")
    if not programs:
        action("select_program", None, "Review opportunity list and opportunity dossier; import one current program policy with its scope and advertised bounty terms.")
    for program_id, program in sorted(programs.items()):
        expiry, verified = _time(program.get("verification_expires_at")), _time(program.get("verified_at"))
        if program.get("status") != "active" or program.get("blocked_reason"):
            action("program_blocked", program_id, "Resolve the recorded program status or policy block before further work.")
        elif (program.get("automation_allowed") is not True or not expiry or not verified
              or verified > now or expiry <= now or expiry <= verified):
            action("policy_review", program_id, "Review current official scope and automation terms, then record verification only if permitted.")
        elif not any(row.get("program_id") == program_id for row in findings.values()):
            action("local_research", program_id, "Review the permitted source or owned local sandbox and record only reproducible findings with evidence.")
    for finding_id, finding in sorted(findings.items()):
        if any(row.get("finding_id") == finding_id for row in submissions.values()):
            continue
        decision = check_scope(programs.get(finding.get("program_id"), {}), finding.get("target"), now=now)
        if not decision["allowed"]:
            action("finding_scope_blocked", finding_id, decision["reason"])
        elif finding.get("status") != "confirmed":
            action("confirm_finding", finding_id, "Reproduce the finding locally and record actual confirmation evidence.")
        elif finding.get("patch_status") not in {"verified", "not_applicable"}:
            action("prepare_patch", finding_id, "Use finding brief to prepare a focused fix and record the real verification results or a not-applicable rationale.")
        else:
            action("draft_report", finding_id, "Create and export the report, then use the official submission channel.")
    for submission_id, submission in sorted(submissions.items()):
        status = submission.get("status")
        if status in {"accepted", "paid"}:
            related = [row for row in payments.values() if row.get("submission_id") == submission_id]
            if not related:
                action("record_award", submission_id, "Record the actual award amount and expected payment date from the platform.")
            for payment in sorted(related, key=lambda row: row["id"]):
                if payment.get("status") == "pending":
                    action("await_payment", payment["id"], "Check the official payment status; record receipt only after funds arrive, using its unique reference.")
            continue
        if submission.get("paused_reason"):
            action("submission_paused", submission_id, "Resolve " + submission["paused_reason"] + " and record a resolution note.")
        elif (_time(submission.get("retry_after")) or now) > now:
            action("submission_backoff", submission_id, "Wait until " + submission["retry_after"] + " before retrying.")
        elif status == "needs_review":
            action("retry_exhausted", submission_id, "Two resubmissions are exhausted; review the official rejection with the user.")
        elif status == "rejected" and not submission.get("retry_reviewed"):
            action("review_rejection", submission_id, "Review the rejection and document concrete changes before resubmission.")
        elif status in {"draft", "rejected"}:
            finding = findings.get(submission.get("finding_id"), {})
            decision = check_scope(programs.get(finding.get("program_id"), {}), finding.get("target"), now=now)
            if not decision["allowed"]:
                action("submission_scope_blocked", submission_id, decision["reason"])
            elif finding.get("patch_status") not in {"verified", "not_applicable"}:
                action("prepare_patch", finding.get("id"), "Record a verified patch or a not-applicable rationale before submission.")
            else:
                action("submit_report", submission_id, "Export and submit through the official portal, then record its report ID.")
        elif status == "submitted":
            action("await_triage", submission_id, "Check for official acknowledgment or triage changes; acceptance and an award are not yet recorded.")

    totals, seen_references, excluded = {}, set(), []
    for payment_id, payment in sorted(payments.items()):
        if payment.get("status") != "received":
            continue
        submission = submissions.get(payment.get("submission_id"), {})
        finding = findings.get(submission.get("finding_id"), {})
        program = programs.get(finding.get("program_id"), {})
        reference = payment.get("receipt_reference")
        received = _time(payment.get("received_at"))
        submitted = _time(submission.get("submitted_at"))
        accepted = _time(submission.get("accepted_at"))
        currency = payment.get("currency", "")
        raw_amount = payment.get("amount")
        try:
            amount = Decimal(raw_amount) if isinstance(raw_amount, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]{1,2})?", raw_amount) else Decimal("NaN")
        except (InvalidOperation, TypeError, ValueError):
            amount = Decimal("NaN")
        reason = None
        if demo:
            reason = "demo_database"
        elif (payment.get("evidence_kind") != "user_attested_reference"
              or not isinstance(reference, str) or not reference.strip()):
            reason = "receipt_reference_missing"
        elif (not program or not submission.get("external_id") or not submitted
              or submission.get("status") not in {"accepted", "paid"} or not accepted
              or not submitted <= accepted <= now):
            reason = "submission_evidence_missing"
        elif not received or received > now or received < submitted:
            reason = "receipt_date_invalid"
        elif not amount.is_finite() or amount <= 0 or not isinstance(currency, str) or len(currency) != 3 or not currency.isascii() or not currency.isalpha():
            reason = "amount_or_currency_invalid"
        key = (submission.get("platform"), reference.strip() if isinstance(reference, str) else None)
        if not reason and key in seen_references:
            reason = "duplicate_receipt_reference"
        if reason:
            excluded.append({"payment_id": payment_id, "reason": reason})
            continue
        seen_references.add(key)
        currency = currency.upper()
        totals[currency] = totals.get(currency, Decimal(0)) + amount
    if excluded and not demo:
        action("review_receipts", None, "Some received records lack unique receipt evidence or valid dates; inspect excluded_payments before treating them as revenue.")
    return {
        "generated_at": stamp(now), "demo_only": demo,
        "milestone": {"target_amount": "1.00", "currency": "USD",
                      "receipt_recorded": not demo and totals.get("USD", Decimal(0)) >= Decimal("1"),
                      "platform_verified": False,
                      "evidence_basis": "Local user-attested receipt references; verify against official platform receipts. No currency conversion."},
        "received_with_references": {key: format(value, ".2f") for key, value in sorted(totals.items())},
        "excluded_payments": excluded,
        "counts": {"opportunities": len(snapshot.get("opportunities", [])), "programs": len(programs),
                   "findings": len(findings), "submissions": len(submissions), "payments": len(payments)},
        "discovery": {"status": job.get("status", "not_started"), "last_complete_sync_at": job.get("last_success_at"),
                      "next_run_at": job.get("next_run_at"), "paused_reason": job.get("paused_reason"),
                      "credentials_visible": credentials_present,
                      "recent_successful_sync": recent_sync,
                      "credential_note": "Credentials are process-local. A successful saved sync does not expose its worker token to this process."},
        "next_actions": actions,
    }


def export_progress(document, output_dir):
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    amount = document["received_with_references"].get("USD", "0.00")
    markdown = ("# First-dollar progress\n\n"
                + ("**DEMO ONLY — no real earnings.**\n\n" if document["demo_only"] else "")
                + f"Generated at {document['generated_at']}.\n\n"
                + f"USD {amount} recorded with unique receipt references. Target: USD 1.00.\n\n"
                + document["milestone"]["evidence_basis"] + " This report does not independently verify payments.\n\n"
                + "## Next actions\n\n"
                + _table(["Action", "Record", "Next step"], [[row["kind"], row["entity_id"], row["next_step"]] for row in document["next_actions"]])
                + "\n\n## Excluded received payments\n\n"
                + _table(["Payment", "Reason"], [[row["payment_id"], row["reason"]] for row in document["excluded_payments"]]) + "\n")
    outputs = [("first_dollar.json", json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"),
               ("first_dollar.md", markdown)]
    for name, content in outputs:
        _atomic_write(directory / name, content)
    return [str((directory / name).resolve()) for name, _ in outputs]
