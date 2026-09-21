"""Local workflow state machine; no network scanning or external submission."""

from datetime import date, datetime, timedelta, timezone
import os
from pathlib import Path
import re
import shlex
import sys
from decimal import Decimal, InvalidOperation
from uuid import uuid4

from .catalog import load_catalog
from .scope import check_scope


def utc_now():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def required(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value.strip()


def money(value):
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Amount must be a positive decimal") from exc
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
        raise ValueError("Amount must be positive with at most two decimal places")
    return format(amount, ".2f")


def receipt_timestamp(value, label):
    """Validate receipt chronology without silently assuming a timezone."""
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and "T" in value:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise ValueError
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError(f"{label} must be a timezone-aware ISO 8601 timestamp") from exc


class Workflow:
    def __init__(self, store, clock=utc_now):
        self.store = store
        self.clock = clock

    def _audit(self, action, table, record, **details):
        self.store.audit(action, table, record["id"], stamp(self.clock()), details)

    def import_programs(self, path):
        programs = load_catalog(path)
        with self.store.transaction():
            for program in programs:
                # Importing/replacing policy never constitutes verifying live platform status.
                program["verified_at"] = None
                program["verification_expires_at"] = None
                program["verification_note"] = None
                try:
                    previous = self.store.get("programs", program["id"])
                except ValueError:
                    previous = None
                if previous and previous.get("blocked_reason"):
                    program["blocked_reason"] = previous["blocked_reason"]
                self.store.save("programs", program)
                self._audit("program.imported", "programs", program, source=str(path), verification_cleared=True)
        return programs

    def verify_program(self, program_id, *, note, valid_hours=24, automation_allowed=False):
        note = required(note, "Verification evidence/note")
        if isinstance(valid_hours, bool) or not isinstance(valid_hours, int) or not 1 <= valid_hours <= 168:
            raise ValueError("Verification validity must be between 1 and 168 hours")
        if automation_allowed is not True:
            raise ValueError("Explicit confirmation of automated testing permission is required")
        with self.store.transaction():
            program = self.store.get("programs", program_id)
            if program.get("blocked_reason"):
                raise ValueError("Program is blocked; review and explicitly unblock it first")
            now = self.clock()
            program.update(status="active", automation_allowed=True, verified_at=stamp(now),
                           verification_expires_at=stamp(now + timedelta(hours=valid_hours)), verification_note=note)
            self.store.save("programs", program)
            self._audit("program.verified", "programs", program, note=note, expires_at=program["verification_expires_at"])
        return program

    def block_program(self, program_id, reason):
        reason = required(reason, "Restriction/confidentiality reason")
        with self.store.transaction():
            program = self.store.get("programs", program_id)
            program.update(blocked_reason=reason, automation_allowed=False, verified_at=None, verification_expires_at=None)
            self.store.save("programs", program)
            self._audit("program.blocked", "programs", program, reason=reason)
        return program

    def unblock_program(self, program_id, note):
        note = required(note, "Review note")
        with self.store.transaction():
            program = self.store.get("programs", program_id)
            program.update(blocked_reason=None, automation_allowed=False, verified_at=None, verification_expires_at=None)
            self.store.save("programs", program)
            self._audit("program.unblocked", "programs", program, note=note)
        return program

    def scope_check(self, program_id, target):
        with self.store.transaction():
            program = self.store.get("programs", program_id)
            result = check_scope(program, target, self.clock())
            self._audit("scope.checked", "programs", program, target=target, **result)
        return result

    def _require_scope(self, program_id, target):
        program = self.store.get("programs", program_id)
        result = check_scope(program, target, self.clock())
        if not result["allowed"]:
            raise ValueError(f"Scope denied: {result['reason']}")
        return program, result["normalized_url"]

    def record_audit(self, program_id, target, note):
        note = required(note, "Audit note")
        with self.store.transaction():
            program, target = self._require_scope(program_id, target)
            self._audit("target.audited", "programs", program, target=target, note=note)
        return {"program_id": program_id, "target": target, "note": note}

    def add_finding(self, program_id, *, target, title, vulnerability_type, severity, reproduction, impact, cvss_score=None):
        if severity not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError("Unsupported severity")
        if cvss_score is not None:
            try:
                score = Decimal(str(cvss_score))
            except InvalidOperation as exc:
                raise ValueError("CVSS score must be between 0 and 10") from exc
            if not score.is_finite() or not 0 <= score <= 10:
                raise ValueError("CVSS score must be between 0 and 10")
            cvss_score = str(score)
        record = dict(id="finding-" + uuid4().hex, program_id=program_id,
                      title=required(title, "Title"), type=required(vulnerability_type, "Vulnerability type"),
                      severity=severity, reproduction=required(reproduction, "Reproduction steps"),
                      impact=required(impact, "Impact"), cvss_score=cvss_score,
                      status="unconfirmed", patch_status="not_started", patch_reference=None,
                      verification=None, created_at=stamp(self.clock()), updated_at=stamp(self.clock()))
        with self.store.transaction():
            _, record["target"] = self._require_scope(program_id, target)
            self.store.save("findings", record)
            self._audit("finding.created", "findings", record)
        return record

    def confirm_finding(self, finding_id, evidence):
        evidence = required(evidence, "Confirmation evidence")
        with self.store.transaction():
            finding = self.store.get("findings", finding_id)
            self._require_scope(finding["program_id"], finding["target"])
            finding.update(status="confirmed", confirmation_evidence=evidence, updated_at=stamp(self.clock()))
            self.store.save("findings", finding)
            self._audit("finding.confirmed", "findings", finding, evidence=evidence)
        return finding

    def record_patch(self, finding_id, *, patch_status, reference=None, verification=None):
        if patch_status not in {"not_started", "in_progress", "ready", "verified", "not_applicable"}:
            raise ValueError("Unsupported patch status")
        if patch_status in {"ready", "verified"}:
            reference = required(reference, "Patch reference")
        if patch_status in {"verified", "not_applicable"}:
            verification = required(verification, "Verification evidence or not-applicable rationale")
        with self.store.transaction():
            finding = self.store.get("findings", finding_id)
            finding.update(patch_status=patch_status, patch_reference=reference,
                           verification=verification, updated_at=stamp(self.clock()))
            self.store.save("findings", finding)
            self._audit("patch.updated", "findings", finding, status=patch_status)
        return finding

    def patch_brief(self, finding_id):
        """Self-contained hand-off for Astra, which writes the code fix. Nothing is executed.

        Building the brief does not audit; call ``record_brief`` once it was delivered."""
        finding = self.store.get("findings", finding_id)
        program, _ = self._require_scope(finding["program_id"], finding["target"])
        if finding["status"] != "confirmed":
            raise ValueError("Finding must be confirmed before requesting a patch")
        runner = Path(__file__).resolve().parents[2] / "run_bughunt.py"
        argv = [sys.executable, str(runner)] if runner.exists() else [sys.executable, "-m", "bughunt"]
        argv += ["--db", str(self.store.path.resolve()), "finding", "patch", finding["id"],
                 "--status", "verified", "--reference", "PATH_OR_URL_TO_PATCH",
                 "--verification", "ACTUAL_TEST_COMMAND_AND_OUTPUT"]
        placeholders = {"PATH_OR_URL_TO_PATCH", "ACTUAL_TEST_COMMAND_AND_OUTPUT"}
        if os.name == "nt":
            def quote(value):
                return value if value not in placeholders and re.fullmatch(r"[A-Za-z0-9_./:-]+", value) else "'" + value.replace("'", "''") + "'"
            command = "& " + " ".join(quote(value) for value in argv)
            command_shell = "powershell"
        else:
            command = " ".join("'" + value + "'" if value in placeholders else shlex.quote(value) for value in argv)
            command_shell = "posix"
        return {"schema_version": 1, "generated_at": stamp(self.clock()), "assignee": "Astra",
                "dispatched": False,
                "record_patch": {"argv": argv, "command": command, "shell": command_shell},
                "delivery": "Generated locally only; give this brief to the patch author yourself. No agent has been started.",
                "task": "Write the code fix for this confirmed issue (CVE/bug); Astra authors the patch.",
                "finding": {k: finding.get(k) for k in ("id", "title", "type", "severity", "cvss_score",
                            "target", "reproduction", "impact", "confirmation_evidence")},
                "program": {k: program.get(k) for k in ("id", "name", "platform", "program_url", "scope", "excluded_scope",
                            "verification_note", "verified_at", "verification_expires_at")},
                "requirements": ["Change only code the program makes available and permits you to modify.",
                                 "Add a regression test that fails before and passes after the fix.",
                                 "Do not test outside the listed scope or against excluded assets.",
                                 "Recheck current program permission before testing; this brief is a snapshot, not ongoing authorization.",
                                 f'Record a tested patch with `{command}` in {command_shell}; replace both placeholders with real evidence. '
                                 'For automation, use record_patch.argv with shell=False instead of parsing the displayed command.']}

    def record_brief(self, finding_id):
        with self.store.transaction():
            finding = self.store.get("findings", finding_id)
            self._audit("patch.briefed", "findings", finding)

    def draft_submission(self, finding_id):
        with self.store.transaction():
            finding = self.store.get("findings", finding_id)
            program, _ = self._require_scope(finding["program_id"], finding["target"])
            if finding["status"] != "confirmed":
                raise ValueError("Finding must be confirmed before drafting a submission")
            if any(s["finding_id"] == finding_id for s in self.store.list("submissions")):
                raise ValueError("Finding already has a submission; use its existing record")
            submission = dict(id="submission-" + uuid4().hex, finding_id=finding_id,
                              platform=program["platform"], external_id=None, status="draft", attempts=0,
                              rejection_reason=None, retry_reviewed=False, revision_note=None,
                              created_at=stamp(self.clock()), updated_at=stamp(self.clock()),
                              submitted_at=None, accepted_at=None, expected_payment_date=None,
                              paused_reason=None, retry_after=None)
            self.store.save("submissions", submission)
            self._audit("submission.drafted", "submissions", submission)
        return submission

    def record_submission(self, submission_id, external_id):
        external_id = required(external_id, "Official platform submission ID")
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if submission["status"] not in {"draft", "rejected"}:
                raise ValueError("Only drafts or reviewed rejections can be marked submitted")
            if submission["attempts"] >= 3:
                raise ValueError("Two resubmissions already used; manual escalation required")
            if submission["status"] == "rejected" and not submission["retry_reviewed"]:
                raise ValueError("Review the rejection and record a revision before resubmitting")
            if submission.get("paused_reason"):
                raise ValueError("Submission is paused; resolve authentication/status and resume first")
            if submission.get("retry_after") and datetime.fromisoformat(submission["retry_after"].replace("Z", "+00:00")) > self.clock():
                raise ValueError(f"Submission backoff active until {submission['retry_after']}")
            finding = self.store.get("findings", submission["finding_id"])
            self._require_scope(finding["program_id"], finding["target"])
            if finding["status"] != "confirmed" or finding["patch_status"] not in {"verified", "not_applicable"}:
                raise ValueError("Confirmed evidence and a verified patch (or not-applicable rationale) are required")
            now = stamp(self.clock())
            submission.update(status="submitted", external_id=external_id, attempts=submission["attempts"] + 1,
                              submitted_at=submission["submitted_at"] or now, last_submitted_at=now,
                              updated_at=now, retry_reviewed=False, retry_after=None)
            self.store.save("submissions", submission)
            self._audit("submission.recorded", "submissions", submission, external_id=external_id, attempt=submission["attempts"])
        return submission

    def reject_submission(self, submission_id, reason):
        reason = required(reason, "Rejection reason")
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if submission["status"] != "submitted":
                raise ValueError("Only submitted reports may be rejected")
            submission.update(status="needs_review" if submission["attempts"] >= 3 else "rejected",
                              rejection_reason=reason, retry_reviewed=False, revision_note=None,
                              updated_at=stamp(self.clock()))
            self.store.save("submissions", submission)
            self._audit("submission.rejected", "submissions", submission, reason=reason, escalated=submission["attempts"] >= 3)
        return submission

    def review_rejection(self, submission_id, note):
        note = required(note, "Revision and review note")
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if submission["status"] != "rejected" or submission["attempts"] >= 3:
                raise ValueError("Submission is not eligible for a retry review")
            submission.update(retry_reviewed=True, revision_note=note, updated_at=stamp(self.clock()))
            self.store.save("submissions", submission)
            self._audit("submission.retry_reviewed", "submissions", submission, note=note)
        return submission

    def accept_submission(self, submission_id, note, expected_payment_date=None):
        note = required(note, "Platform acceptance evidence")
        if expected_payment_date:
            date.fromisoformat(expected_payment_date)
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if submission["status"] != "submitted":
                raise ValueError("Only submitted reports may be accepted")
            submission.update(status="accepted", accepted_at=stamp(self.clock()), updated_at=stamp(self.clock()),
                              acceptance_note=note, expected_payment_date=expected_payment_date)
            self.store.save("submissions", submission)
            self._audit("submission.accepted", "submissions", submission, note=note)
        return submission

    def record_error(self, submission_id, kind, note):
        note = required(note, "Error details")
        if kind not in {"rate_limit", "authentication", "unclear_status", "downtime"}:
            raise ValueError("Unsupported error kind")
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if submission["status"] in {"accepted", "paid", "needs_review"}:
                raise ValueError("This submission is not eligible for retry handling")
            if kind in {"rate_limit", "downtime"}:
                submission["retry_after"] = stamp(self.clock() + timedelta(hours=1))
            else:
                submission["paused_reason"] = kind
            submission["updated_at"] = stamp(self.clock())
            self.store.save("submissions", submission)
            self._audit("submission.error", "submissions", submission, kind=kind, note=note)
        return submission

    def resume_submission(self, submission_id, note):
        note = required(note, "Resolution evidence")
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if not submission.get("paused_reason"):
                raise ValueError("Submission has no authentication/status pause to resolve")
            submission.update(paused_reason=None, updated_at=stamp(self.clock()))
            self.store.save("submissions", submission)
            self._audit("submission.resumed", "submissions", submission, note=note)
        return submission

    def add_payment(self, submission_id, amount, currency, expected_date=None):
        amount = money(amount)
        if not isinstance(currency, str) or len(currency) != 3 or not currency.isascii() or not currency.isalpha():
            raise ValueError("Currency must be a three-letter code")
        if expected_date:
            date.fromisoformat(expected_date)
        with self.store.transaction():
            submission = self.store.get("submissions", submission_id)
            if submission["status"] not in {"accepted", "paid"}:
                raise ValueError("Payments require explicit platform acceptance")
            payment = dict(id="payment-" + uuid4().hex, submission_id=submission_id,
                           amount=amount, currency=currency.upper(), status="pending", expected_date=expected_date,
                           received_at=None, created_at=stamp(self.clock()))
            self.store.save("payments", payment)
            submission.update(status="accepted", updated_at=stamp(self.clock()))
            self.store.save("submissions", submission)
            self._audit("payment.expected", "payments", payment)
        return payment

    def receive_payment(self, payment_id, note, *, receipt_reference=None, received_at=None):
        """Record a user's receipt attestation, never platform verification.

        A platform receipt reference permits idempotent retries and prevents the
        same receipt from being counted through different local payment rows.
        Legacy note-only receipts remain available but carry weaker evidence.
        """
        note = required(note, "Payment receipt evidence")
        if receipt_reference is not None:
            receipt_reference = required(receipt_reference, "Payment receipt reference")
        receipt_date = receipt_timestamp(received_at, "Receipt date") if received_at is not None else None
        with self.store.transaction():
            payment = self.store.get("payments", payment_id)
            submission = self.store.get("submissions", payment["submission_id"])
            if payment["status"] != "pending":
                if (payment["status"] == "received" and receipt_reference is not None
                        and payment.get("receipt_reference") == receipt_reference
                        and payment.get("receipt_note") == note
                        and (receipt_date is None or stamp(receipt_date) == payment.get("received_at"))):
                    return payment
                raise ValueError("Payment has already been received")
            now = receipt_timestamp(self.clock(), "Current time")
            receipt_date = receipt_date or now
            if receipt_date > now:
                raise ValueError("Receipt date must not be in the future")
            submitted_at = receipt_timestamp(submission.get("submitted_at"), "Submission date")
            if receipt_date < submitted_at:
                raise ValueError("Receipt date must not precede the submission")
            if receipt_reference is not None:
                submissions = {record["id"]: record for record in self.store.list("submissions")}
                for other in self.store.list("payments"):
                    if (other["id"] != payment_id and other.get("receipt_reference") == receipt_reference
                            and submissions[other["submission_id"]]["platform"] == submission["platform"]):
                        raise ValueError("Receipt reference is already recorded for another payment on this platform")
            payment.update(status="received", received_at=stamp(receipt_date), receipt_note=note,
                           receipt_reference=receipt_reference, recorded_at=stamp(now),
                           evidence_kind="user_attested_reference" if receipt_reference is not None else "manual_note")
            self.store.save("payments", payment)
            pending = any(p["submission_id"] == submission["id"] and p["status"] == "pending" for p in self.store.list("payments"))
            submission.update(status="accepted" if pending else "paid", updated_at=stamp(now))
            self.store.save("submissions", submission)
            self._audit("payment.received", "payments", payment, note=note, receipt_reference=receipt_reference,
                        received_at=payment["received_at"], evidence_kind=payment["evidence_kind"])
        return payment

    def submission_bundle(self, submission_id):
        submission = self.store.get("submissions", submission_id)
        finding = self.store.get("findings", submission["finding_id"])
        program = self.store.get("programs", finding["program_id"])
        return {"schema_version": 1, "generated_at": stamp(self.clock()),
                "delivery": "Manual upload through the official program portal; this export does not submit anything.",
                "program": program, "finding": finding, "submission": submission}
