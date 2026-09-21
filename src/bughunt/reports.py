"""Deterministic, local reports from a recorded BugHunt snapshot.

Reports describe recorded activity, not live platform state. Monetary amounts
stay as Decimal values, and currencies are never combined or converted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import html
import json
import os
from pathlib import Path
import tempfile
from typing import Any

__all__ = ["generate_reports"]

_UTC = timezone.utc


def _timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=_UTC) if parsed.tzinfo is None else parsed.astimezone(_UTC)
    except (ValueError, TypeError, OverflowError):
        return None


def _iso(value: datetime) -> str:
    return value.astimezone(_UTC).isoformat().replace("+00:00", "Z")


def _cell(value: Any) -> str:
    """Escape both Markdown syntax and HTML in an untrusted table cell."""
    if value is None or value == "":
        return "—"
    text = " ".join(str(value).split())
    text = "".join(character for character in text if ord(character) >= 32 and ord(character) != 127)
    text = html.escape(text, quote=True)
    for character in ("\\", "|", "`", "*", "_", "[", "]", "(", ")", "#", "!", "~"):
        text = text.replace(character, "\\" + character)
    return text


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def _date(value: Any) -> str:
    parsed = _timestamp(value)
    if parsed is None:
        return "—"
    if isinstance(value, str) and len(value) == 10:
        return parsed.date().isoformat()
    return _iso(parsed)


def _records(snapshot: dict, key: str) -> list[dict]:
    # Store snapshots use unique IDs. Deduplication also makes imported snapshots
    # safe from repeated records; the most recent recorded event wins.
    def order(record: dict) -> tuple:
        timestamps = [_timestamp(record.get(field)) for field in ("created_at", "updated_at", "received_at")]
        latest = max((value for value in timestamps if value is not None), default=datetime.min.replace(tzinfo=_UTC))
        return latest, record.get("status") == "received", json.dumps(record, sort_keys=True, default=str)

    unique: dict[str, dict] = {}
    anonymous: list[dict] = []
    for record in sorted(snapshot.get(key, []), key=order):
        if record.get("id") is None:
            anonymous.append(record)
        else:
            unique[str(record["id"])] = record
    return sorted([*unique.values(), *anonymous], key=lambda record: (str(record.get("id", "")), order(record)))


def _latest_submission(submissions: list[dict]) -> dict | None:
    return max(
        submissions,
        key=lambda record: (_timestamp(record.get("created_at")) or datetime.min.replace(tzinfo=_UTC), str(record.get("id", ""))),
        default=None,
    )


def _vulnerabilities(findings: list[dict], submissions: list[dict], programs: dict) -> str:
    by_finding: dict[Any, list[dict]] = {}
    for submission in submissions:
        by_finding.setdefault(submission.get("finding_id"), []).append(submission)
    results = []
    for finding in findings:
        submission = _latest_submission(by_finding.get(finding.get("id"), [])) or {}
        program = programs.get(finding.get("program_id"), {})
        results.append({
            "finding_id": finding.get("id"),
            "title": finding.get("title"),
            "target": finding.get("target"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "patch_status": finding.get("patch_status"),
            "submission_platform": submission.get("platform") or program.get("platform"),
            "submission_id": submission.get("external_id") or submission.get("id"),
        })
    return json.dumps(results, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def _submission_report(submissions: list[dict], findings: dict, programs: dict, now: datetime) -> str:
    rows = []
    for submission in submissions:
        finding = findings.get(submission.get("finding_id"), {})
        program = programs.get(finding.get("program_id"), {})
        rows.append([
            submission.get("id"), finding.get("title") or submission.get("finding_id"),
            program.get("name"), submission.get("platform"), submission.get("external_id"),
            submission.get("status"), _date(submission.get("created_at")),
            _date(submission.get("submitted_at")), _date(submission.get("accepted_at")),
            _date(submission.get("updated_at")), _date(submission.get("expected_payment_date")),
            submission.get("attempts", 0), submission.get("rejection_reason"),
            "Yes" if submission.get("retry_reviewed") else "No",
        ])
    report = f"# Submission status\n\nGenerated at {_iso(now)}. All recorded submission states are included.\n\n"
    report += _table([
        "Local ID", "Finding", "Program", "Platform", "Platform ID", "Status", "Created (UTC)",
        "Submitted (UTC)", "Accepted (UTC)", "Updated (UTC)", "Expected payment date",
        "Attempts", "Rejection reason", "Retry reviewed",
    ], rows)
    if not rows:
        report += "\n\nNo submissions recorded."
    return report + "\n"


def _average_resolution(submissions: list[dict], start: datetime | None, end: datetime) -> str:
    durations = []
    for submission in submissions:
        submitted = _timestamp(submission.get("submitted_at"))
        accepted = _timestamp(submission.get("accepted_at"))
        if submitted is None or accepted is None or accepted < submitted or accepted > end:
            continue
        if start is not None and accepted < start:
            continue
        durations.append((accepted - submitted).total_seconds() / 86400)
    if not durations:
        return "N/A (no complete, valid submission-to-acceptance timestamps)"
    return f"{sum(durations) / len(durations):.2f} days ({len(durations)} submissions)"


def _amount(payment: dict) -> Decimal | None:
    try:
        value = Decimal(str(payment.get("amount")))
        return value if value.is_finite() and value >= 0 else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def _money(value: Decimal) -> str:
    # At least two places, while preserving precision for currencies/assets that
    # record fractions smaller than a cent.
    return format(value, f".{max(2, -value.as_tuple().exponent)}f")


def _weekly_report(findings: list[dict], submissions: list[dict], payments: list[dict], audit: list[dict], now: datetime) -> str:
    start = now - timedelta(days=7)

    def in_period(value: Any, beginning: datetime | None = start) -> bool:
        parsed = _timestamp(value)
        return parsed is not None and parsed <= now and (beginning is None or parsed >= beginning)

    def targets(beginning: datetime | None) -> int:
        return len({
            str(record.get("details", {}).get("target") or record.get("entity_id"))
            for record in audit
            if record.get("action") == "target.audited"
            and in_period(record.get("created_at"), beginning)
            and (record.get("details", {}).get("target") or record.get("entity_id"))
        })

    metrics = [["Distinct targets audited", targets(start), targets(None)]]
    for label, records, date_field in (
        ("Vulnerabilities recorded", findings, "created_at"),
        ("Submissions sent", submissions, "submitted_at"),
        ("Submissions accepted", submissions, "accepted_at"),
    ):
        metrics.append([
            label,
            sum(in_period(record.get(date_field)) for record in records),
            sum(in_period(record.get(date_field), None) for record in records),
        ])
    metrics.append([
        "Average resolution time (submitted to accepted)",
        _average_resolution(submissions, start, now), _average_resolution(submissions, None, now),
    ])

    totals: dict[str, dict[str, Decimal]] = {}
    pending_rows = []
    invalid_payments = 0
    for payment in payments:
        amount = _amount(payment)
        currency = str(payment.get("currency") or "").strip().upper()
        if amount is None or not currency or payment.get("status") not in {"pending", "received"}:
            invalid_payments += 1
            continue
        currency_totals = totals.setdefault(currency, {"pending": Decimal(0), "received": Decimal(0), "weekly_received": Decimal(0)})
        currency_totals[payment["status"]] += amount
        if payment["status"] == "received" and in_period(payment.get("received_at")):
            currency_totals["weekly_received"] += amount
        if payment["status"] == "pending":
            pending_rows.append([
                payment.get("id"), payment.get("submission_id"), _money(amount), currency,
                _date(payment.get("expected_date")), _date(payment.get("created_at")),
            ])

    report = (
        f"# Weekly payout report\n\nGenerated at {_iso(now)}.\n\n"
        f"Reporting window: {_iso(start)} through {_iso(now)} (inclusive, UTC).\n\n"
        "## Activity\n\n" + _table(["Metric", "Trailing 7 days", "All-time through report time"], metrics)
        + "\n\nAcceptance metrics use the recorded acceptance date, including submissions subsequently marked paid. "
        "Resolution averages include acceptances in the indicated period and exclude missing or reversed timestamps. "
        "Missing or future event dates are excluded from activity counts. "
        "Targets are counted only from explicit target.audited records.\n\n"
        "## Payouts by currency\n\n"
        "Pending totals cover all currently pending payment records. Received totals cover all payment records marked received. "
        "These are separate statuses of individual installments; submission estimates are not added to payments. "
        "Currencies are never combined.\n\n"
    )
    report += _table(
        ["Currency", "Pending (all-time current balance)", "Received (all-time recorded)", "Received (trailing 7 days)"],
        [[currency, _money(values["pending"]), _money(values["received"]), _money(values["weekly_received"])] for currency, values in sorted(totals.items())],
    )
    if not totals:
        report += "\n\nNo valid payments recorded."
    if invalid_payments:
        report += f"\n\nExcluded {invalid_payments} payment records with invalid amounts, missing currencies, or unsupported statuses."
    report += "\n\n## Pending payments\n\n" + _table(
        ["Payment ID", "Submission ID", "Amount", "Currency", "Expected date", "Recorded (UTC)"], pending_rows,
    )
    if not pending_rows:
        report += "\n\nNo pending payments."
    return report + "\n"


def _atomic_write(path: Path, content: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generate_reports(snapshot: dict, output_dir: str | Path, now: datetime | None = None) -> list[Path]:
    """Write the three specified reports and return their paths in format order.

    ``now`` defaults to UTC. Naive input timestamps are interpreted as UTC. The
    vulnerability export uses each finding's newest submission by creation time,
    preferring its platform ID and falling back to the local ID when absent.
    Output replacement is atomic per file, not transactional across all files.
    """
    report_time = _timestamp(now) if now is not None else datetime.now(_UTC)
    if report_time is None:
        raise ValueError("now must be a valid datetime")
    programs = {record.get("id"): record for record in _records(snapshot, "programs")}
    findings = _records(snapshot, "findings")
    submissions = _records(snapshot, "submissions")
    payments = _records(snapshot, "payments")
    audit = _records(snapshot, "audit")
    reports = {
        "vulnerabilities_found.json": _vulnerabilities(findings, submissions, programs),
        "submissions_status.md": _submission_report(submissions, {record.get("id"): record for record in findings}, programs, report_time),
        "weekly_payout_report.md": _weekly_report(findings, submissions, payments, audit, report_time),
    }
    if any(record.get("action") == "demo.created" for record in audit):
        notice = "> **DEMO ONLY:** This database contains fictitious findings, submissions, and payouts. No real award or payment is represented.\n\n"
        for filename in ("submissions_status.md", "weekly_payout_report.md"):
            reports[filename] = notice + reports[filename]
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for filename, content in reports.items():
        path = directory / filename
        _atomic_write(path, content)
        paths.append(path)
    return paths
