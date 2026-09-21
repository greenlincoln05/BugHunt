# Architecture and implementation boundary

The first release is a local workflow foundation using Python's standard library.
The user's latest priority overrides the source document's preference for
high-severity, high-payout targets: the shortlist defaults to USD 50–200 and the
catalog is intended for selected startup or medium-company programs.

| Module | Responsibility |
| --- | --- |
| `catalog.py` | Strict local import schema and deterministic payout shortlist |
| `scope.py` | Offline URL normalization, policy freshness, and scope decision |
| `storage.py` | SQLite entities, foreign keys, transactions, schema version, audit |
| `workflow.py` | Finding, patch, submission, retry, acceptance, and payment states |
| `reports.py` | Deterministic JSON/Markdown exports and currency-safe totals |
| `cli.py` | Explicit local commands and useful exit codes |
| `demo.py` | Isolated, clearly fictitious end-to-end demonstration |

Records store structured JSON in four related tables. SQLite foreign keys protect
relationships, while business rules live in `Workflow`. Every state mutation
acquires a write transaction before reading and updating records. Schema version
1 rejects newer unsupported databases. The CLI and source runner share the same
entry point, so tests exercise the user-facing code path.

Program imports deliberately discard verification dates and retain prior blocks.
`program verify` records a human attestation, with evidence and a short expiration.
Scope is checked before adding/confirming findings, drafting submissions, and
recording each submission attempt. A blocked or stale policy cannot authorize
these actions. Recording administrative outcomes such as rejection, acceptance,
and payment remains possible after a program closes.

Submission states are `draft -> submitted -> accepted -> paid`, or
`submitted -> rejected -> submitted` after explicit revision review. The original
attempt plus two retries exhausts the counter; rejection then becomes
`needs_review`. Authentication/status pauses and timestamped retry eligibility
are stored independently so resolving one does not erase the other.

Payment rows represent individual installments. `pending -> received` updates the
same row. Totals never add submission estimates to payment amounts, and currencies
are reported separately. Timestamps use UTC; expected payment dates are calendar
dates. Reports describe local records rather than live platform truth.

## Remaining work from the source specification

1. **Discovery adapters:** documented official APIs or supported catalog exports
   for each platform, source timestamps and raw policy provenance, current bounty
   verification, and explicit company-size metadata. Do not invent payout speed
   statistics or use the local shortlist as proof of authorization.
2. **Reconnaissance executor:** controlled, non-destructive checks on specifically
   configured authorized assets, with redirect reauthorization, network/DNS
   enforcement, request budgets, rate limits, and reproducible evidence capture.
   The current scope matcher alone is not an HTTP execution sandbox.
3. **Patch workspace:** isolated checkouts for source made available by the program,
   focused fixes, before/after regression checks, and proof-of-concept artifacts.
   A user-entered `verified` record is currently an attestation, not test execution.
4. **Official submission adapters:** platform-specific authentication providers,
   idempotency, supported report fields and attachments, acknowledgment/status
   synchronization, and handling restrictions on automation. No credentials are
   accepted by this release; do not place account secrets in catalogs or reports.
5. **Worker and scheduling:** durable jobs and persisted retry eligibility, explicit
   pause notifications, target downtime handling, bounded concurrency, and weekly
   report scheduling. Current backoff state does not run work in the background.
6. **Confirmation and payout reconciliation:** optional authorized email/platform
   access and duplicate-resistant updates. Platforms handle actual payment; the
   application only records evidence of it.

No platform access, live testing, messages, submissions, schedules, or payments
were performed to implement this foundation. The demo and tests are offline.

## Validation

Run `python scripts/test.py`. The suite covers hostile URL boundary cases, catalog
types and duplicates, payout ranking, time-window behavior, workflow transitions,
retry exhaustion, independent pause gates, transactional rollback, persistence,
exact payment totals, Markdown escaping, and the full CLI demonstration/export.
