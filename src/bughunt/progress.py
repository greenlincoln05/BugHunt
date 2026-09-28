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
from .scope import check_scope, check_source_scope
from .workflow import stamp, utc_now


def _time(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


_PIPELINE_STAGES = ("triage", "clone", "finding", "patch", "evidence", "draft")


def _eligible_source_urls(program):
    assets = program.get("source_code_assets")
    if not isinstance(assets, list):
        return []
    return sorted({asset["url"] for asset in assets
                   if isinstance(asset, dict) and isinstance(asset.get("url"), str)
                   and asset.get("eligible_for_bounty") is True
                   and asset.get("eligible_for_submission") is True})


def _latest_audit(audit, action, entity_type, entity_id, now):
    # Audit rows in a Store snapshot are ordered by their database ID. A clone or
    # export event establishes only that an action happened then, not that its
    # output still exists in the current filesystem.
    for row in reversed(audit):
        when = _time(row.get("created_at"))
        if (row.get("action") != action or row.get("entity_type") != entity_type
                or row.get("entity_id") != entity_id or when is None or when > now):
            continue
        return row
    return None


def _latest_clone(audit, source_url, now):
    for row in reversed(audit):
        when = _time(row.get("created_at"))
        if (row.get("action") == "workspace.cloned" and row.get("entity_type") == "workspace"
                and when is not None and when <= now and isinstance(row.get("details"), dict)
                and row["details"].get("url") == source_url):
            return row
    return None


def _passing_evidence_recorded(audit, finding_id, now):
    capture = _latest_audit(audit, "patch.evidence_captured", "findings", finding_id, now)
    details = capture.get("details") if capture and isinstance(capture.get("details"), dict) else {}
    return (details.get("passed") is True and details.get("exit_code") == 0
            and details.get("timed_out") is False)


def _confirmation_recorded(finding):
    return finding.get("status") == "confirmed" and bool(finding.get("confirmation_evidence"))


def _patch_record_complete(finding):
    status = finding.get("patch_status")
    return ((status == "verified" and bool(finding.get("patch_reference"))
             and bool(finding.get("verification")))
            or (status == "not_applicable" and bool(finding.get("verification"))))


def _build_pipeline(snapshot, programs, findings, submissions, now):
    audit = snapshot.get("audit", [])
    triage_runs = [row for row in audit
                   if row.get("action") == "opportunity.triaged"
                   and row.get("entity_type") == "opportunities"
                   and _time(row.get("created_at")) is not None
                   and _time(row.get("created_at")) <= now]
    last_triage = triage_runs[-1].get("details") if triage_runs else None
    if not isinstance(last_triage, dict):
        last_triage = {}
    tracks = []
    covered_findings = set()

    def append_track(program_id, target_kind, target, finding=None):
        program = programs.get(program_id, {})
        finding_id = finding.get("id") if finding else None
        source = target_kind == "source_code"
        if source:
            decision = check_source_scope(program, target, now=now)
            clone = _latest_clone(audit, target, now)
            promoted = _latest_audit(audit, "opportunity.promoted", "programs", program_id, now)
            triage_status = ("candidate_promoted" if promoted and isinstance(promoted.get("details"), dict)
                             and promoted["details"].get("source_url") == target else "program_recorded")
            clone_status = "historical_clone_recorded" if clone else "not_recorded"
        else:
            decision = check_scope(program, target, now=now) if target_kind == "http" else {
                "allowed": False, "reason": "Unknown finding target kind."}
            clone = None
            triage_status = clone_status = "not_applicable"

        if not finding:
            finding_status = patch_status = evidence_status = "not_recorded"
        else:
            if finding.get("status") == "confirmed":
                finding_status = ("confirmation_recorded" if _confirmation_recorded(finding)
                                  else "confirmation_evidence_missing")
            else:
                finding_status = "unconfirmed_recorded"
            patch_state = finding.get("patch_status", "not_started")
            if patch_state == "verified":
                patch_status = ("verified_recorded" if finding.get("patch_reference")
                                and finding.get("verification") else "verification_evidence_missing")
            elif patch_state == "not_applicable":
                patch_status = ("not_applicable_rationale_recorded" if finding.get("verification")
                                else "not_applicable_rationale_missing")
            else:
                patch_status = patch_state
            capture = _latest_audit(audit, "patch.evidence_captured", "findings", finding_id, now)
            if capture:
                details = capture.get("details") if isinstance(capture.get("details"), dict) else {}
                evidence_status = ("passing_command_recorded" if details.get("passed") is True
                                   and details.get("exit_code") == 0 and details.get("timed_out") is False
                                   else "nonpassing_command_recorded")
            elif patch_status == "not_applicable_rationale_recorded":
                evidence_status = "not_applicable_rationale_recorded"
            elif finding.get("verification"):
                evidence_status = "manual_verification_only"
            else:
                evidence_status = "not_recorded"

        related = [row for row in submissions.values() if row.get("finding_id") == finding_id] if finding_id else []
        submission = max(related, key=lambda row: (_time(row.get("created_at")) or datetime.min.replace(tzinfo=now.tzinfo),
                                                   str(row.get("id", ""))), default=None)
        if submission:
            export = _latest_audit(audit, "submission.exported", "submissions", submission["id"], now)
            if submission.get("status") in {"draft", "rejected"}:
                draft_status = "historical_export_recorded" if export else "draft_recorded"
            else:
                draft_status = "submission_status_recorded"
        else:
            export = None
            draft_status = "not_recorded"

        if submission and submission.get("status") not in {"draft", "rejected"}:
            next_stage, next_step = None, "Follow the recorded submission status and official triage or payment."
        elif not decision["allowed"]:
            next_stage, next_step = None, "Review the current program policy and scope: " + decision["reason"]
        elif not finding:
            if source and not clone:
                next_stage, next_step = "clone", "Run workspace clone for this exact declared source URL, then review the local checkout."
            else:
                next_stage, next_step = "finding", "Inspect the local source or owned sandbox; record only a reproducible security finding. Recheck any historical clone path first."
        elif finding_status != "confirmation_recorded":
            next_stage, next_step = "finding", "Reproduce the issue and record real confirmation evidence with finding confirm."
        elif patch_status not in {"verified_recorded", "not_applicable_rationale_recorded"}:
            next_stage, next_step = "patch", "Prepare a focused fix and record actual patch verification or a not-applicable rationale."
        elif evidence_status == "nonpassing_command_recorded" or (source and patch_status == "verified_recorded"
                                                                    and evidence_status != "passing_command_recorded"):
            next_stage, next_step = "evidence", "Review the latest captured run; use finding evidence in the local checkout and inspect the result before drafting."
        elif submission is None:
            next_stage, next_step = "draft", "Create a local submission draft and export it for human review."
        elif submission.get("status") in {"draft", "rejected"}:
            next_stage = "draft"
            next_step = ("Review the recorded export and submit through the official portal yourself."
                         if export else "Export the local draft for human review before portal submission.")

        tracks.append({
            "program_id": program_id, "target_kind": target_kind, "target": target,
            "finding_id": finding_id, "submission_id": submission.get("id") if submission else None,
            "source_policy_current": decision["allowed"] if source else None,
            "recorded_clone_path": clone.get("entity_id") if clone else None,
            "stages": {"triage": triage_status, "clone": clone_status,
                       "finding": finding_status, "patch": patch_status,
                       "evidence": evidence_status, "draft": draft_status},
            "next_stage": next_stage, "next_step": next_step,
        })

    for program_id, program in sorted(programs.items()):
        for url in _eligible_source_urls(program):
            matching = sorted((row for row in findings.values()
                               if row.get("program_id") == program_id
                               and row.get("target_kind") == "source_code"
                               and row.get("target") == url), key=lambda row: row["id"])
            for finding in matching or [None]:
                append_track(program_id, "source_code", url, finding)
                if finding:
                    covered_findings.add(finding["id"])
    for finding_id, finding in sorted(findings.items()):
        if finding_id not in covered_findings:
            append_track(finding.get("program_id"), finding.get("target_kind", "http"),
                         finding.get("target"), finding)

    return {
        "stage_order": list(_PIPELINE_STAGES),
        "triage": {"opportunities_recorded": len(snapshot.get("opportunities", [])),
                   "batch_runs_recorded": len(triage_runs),
                   "last_batch_attempted": last_triage.get("attempted"),
                   "last_recorded_shortlist_size": last_triage.get("source_eligible"),
                   "note": ("Batch audit totals and the last recorded cumulative shortlist size are historical, "
                            "not a per-candidate eligibility decision.")},
        "tracks": tracks,
        "evidence_note": ("Clone/export events are historical and do not prove files still exist. "
                          "A passing captured command is not independent proof of patch correctness, "
                          "scope eligibility, report acceptance, or payment."),
    }


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

    def finding_scope(finding):
        program = programs.get(finding.get("program_id"), {})
        if finding.get("target_kind", "http") == "source_code":
            return check_source_scope(program, finding.get("target"), now=now)
        if finding.get("target_kind", "http") != "http":
            return {"allowed": False, "reason": "Unknown finding target kind."}
        return check_scope(program, finding.get("target"), now=now)

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
        if snapshot.get("opportunities"):
            action("select_program", None,
                   "Run a bounded opportunity triage, inspect an exact source-code dossier and current policy, then promote or import one bounty-eligible program for review.")
        else:
            action("select_program", None, "Review opportunity list and opportunity dossier; import one current program policy with its scope and advertised bounty terms.")
    for program_id, program in sorted(programs.items()):
        expiry, verified = _time(program.get("verification_expires_at")), _time(program.get("verified_at"))
        eligible_sources = _eligible_source_urls(program)
        source_ready = any(check_source_scope(program, url, now=now)["allowed"] for url in eligible_sources)
        if program.get("status") != "active" or program.get("blocked_reason"):
            action("program_blocked", program_id, "Resolve the recorded program status or policy block before further work.")
        elif eligible_sources and not source_ready:
            action("source_policy_review", program_id,
                   "Review the current official policy, exclusions, bounty eligibility and open submissions; run program verify-source for the exact repository. This does not permit live testing.")
        elif source_ready:
            for url in eligible_sources:
                if (check_source_scope(program, url, now=now)["allowed"]
                        and not any(row.get("program_id") == program_id
                                    and row.get("target_kind") == "source_code"
                                    and row.get("target") == url for row in findings.values())):
                    clone = _latest_clone(snapshot.get("audit", []), url, now)
                    message = ("Inspect the historically recorded clone path; if it is gone, re-clone the exact declared source. "
                               "Review locally and record only a reproduced security finding with evidence."
                               if clone else "Run workspace clone for the exact declared source URL, review it locally, and record only a reproduced security finding with evidence.")
                    action("local_research", program_id, message)
        elif (program.get("automation_allowed") is not True or not expiry or not verified
              or verified > now or expiry <= now or expiry <= verified):
            action("policy_review", program_id, "Review current official scope and automation terms, then record verification only if permitted.")
        elif not any(row.get("program_id") == program_id for row in findings.values()):
            action("local_research", program_id, "Review the permitted source or owned local sandbox and record only reproducible findings with evidence.")
    for finding_id, finding in sorted(findings.items()):
        if any(row.get("finding_id") == finding_id for row in submissions.values()):
            continue
        decision = finding_scope(finding)
        if not decision["allowed"]:
            action("finding_scope_blocked", finding_id, decision["reason"])
        elif not _confirmation_recorded(finding):
            action("confirm_finding", finding_id, "Reproduce the finding locally and record actual confirmation evidence.")
        elif not _patch_record_complete(finding):
            action("prepare_patch", finding_id, "Use finding brief to prepare a focused fix and record the real verification results or a not-applicable rationale.")
        elif (finding.get("target_kind") == "source_code" and finding.get("patch_status") == "verified"
              and not _passing_evidence_recorded(snapshot.get("audit", []), finding_id, now)):
            action("capture_evidence", finding_id,
                   "Run finding evidence in the local source checkout, inspect the captured result, and recheck scope before drafting.")
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
            decision = finding_scope(finding)
            if not decision["allowed"]:
                action("submission_scope_blocked", submission_id, decision["reason"])
            elif not _confirmation_recorded(finding):
                action("confirm_finding", finding.get("id"), "Record actual confirmation evidence before submission.")
            elif not _patch_record_complete(finding):
                action("prepare_patch", finding.get("id"), "Record a verified patch or a not-applicable rationale before submission.")
            elif (finding.get("target_kind") == "source_code" and finding.get("patch_status") == "verified"
                  and not _passing_evidence_recorded(snapshot.get("audit", []), finding.get("id"), now)):
                action("capture_evidence", finding.get("id"),
                       "Capture and inspect a passing local regression run before exporting or submitting this source finding.")
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
        "pipeline": _build_pipeline(snapshot, programs, findings, submissions, now),
        "next_actions": actions,
    }


def export_progress(document, output_dir):
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    amount = document["received_with_references"].get("USD", "0.00")
    pipeline = document["pipeline"]
    triage = pipeline["triage"]
    pipeline_rows = [[row["program_id"], row["target"], row["finding_id"],
                      *[row["stages"][stage] for stage in pipeline["stage_order"]],
                      row["next_stage"], row["next_step"]]
                     for row in pipeline["tracks"]]
    markdown = ("# First-dollar progress\n\n"
                + ("**DEMO ONLY — no real earnings.**\n\n" if document["demo_only"] else "")
                + f"Generated at {document['generated_at']}.\n\n"
                + f"USD {amount} recorded with unique receipt references. Target: USD 1.00.\n\n"
                + document["milestone"]["evidence_basis"] + " This report does not independently verify payments.\n\n"
                + "## Local pipeline\n\n"
                + (f"Recorded opportunities: {triage['opportunities_recorded']}; bounded triage batches: "
                   f"{triage['batch_runs_recorded']}; last batch attempted: "
                   f"{triage['last_batch_attempted'] if triage['last_batch_attempted'] is not None else 'unknown'}; "
                   f"last recorded shortlist size: "
                   f"{triage['last_recorded_shortlist_size'] if triage['last_recorded_shortlist_size'] is not None else 'unknown'}.\n\n")
                + pipeline["triage"]["note"] + " " + pipeline["evidence_note"] + "\n\n"
                + _table(["Program", "Target", "Finding", *pipeline["stage_order"], "Next stage", "Next step"],
                         pipeline_rows)
                + ("\n\nNo selected source asset or recorded finding yet." if not pipeline_rows else "")
                + "\n\n"
                + "## Next actions\n\n"
                + _table(["Action", "Record", "Next step"], [[row["kind"], row["entity_id"], row["next_step"]] for row in document["next_actions"]])
                + "\n\n## Excluded received payments\n\n"
                + _table(["Payment", "Reason"], [[row["payment_id"], row["reason"]] for row in document["excluded_payments"]]) + "\n")
    outputs = [("first_dollar.json", json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"),
               ("first_dollar.md", markdown)]
    for name, content in outputs:
        _atomic_write(directory / name, content)
    return [str((directory / name).resolve()) for name, _ in outputs]
