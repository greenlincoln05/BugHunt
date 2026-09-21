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
| `hackerone.py` | Read-only official API adapter, credentials, pagination, sanitized errors |
| `worker.py` | Durable discovery batches, leases, backoff, snapshot publication, stop/resume |
| `dossier.py` | Bounded official structured-scope and reward-exclusion retrieval for review |
| `progress.py` | Next-action queue and local receipt-backed first-dollar progress, excluding demos |
| `model_access.py` | Secret-safe explicit model configuration and metadata access checks, without inference |

Records store structured JSON in four related workflow tables and two discovery
tables (`jobs` and `opportunities`). SQLite foreign keys protect
relationships, while business rules live in `Workflow`. Every state mutation
acquires a write transaction before reading and updating records. Schema version
2 upgrades existing version-1 databases and rejects newer unsupported databases. The CLI and source runner share the same
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

1. **Discovery adapters:** HackerOne program discovery is implemented, with raw
   policy text, a completed-snapshot timestamp, bounded pagination, and unknown
   payouts preserved. Selected candidates can export detailed scope and reward
   exclusion dossiers for review. Other platforms, automatic synchronization,
   and company-size metadata remain to be added. A discovery snapshot never
   becomes a verified test authorization automatically.
2. **Reconnaissance executor:** controlled, non-destructive checks on specifically
   configured authorized assets, with redirect reauthorization, network/DNS
   enforcement, request budgets, rate limits, and reproducible evidence capture.
   The current scope matcher alone is not an HTTP execution sandbox.
3. **Patch workspace:** isolated checkouts for source made available by the program,
   focused fixes, before/after regression checks, and proof-of-concept artifacts.
   A user-entered `verified` record is currently an attestation, not test execution.
4. **Official submission adapters:** platform-specific authentication providers,
   idempotency, supported report fields and attachments, acknowledgment/status
   synchronization, and handling restrictions on automation. Submission adapters
   are not implemented. Discovery and model preflight read environment credentials;
   do not place account secrets in catalogs or reports.
5. **Worker and scheduling:** the discovery worker has durable cursors, complete
   snapshot publication, single active-batch leases, stop/resume, and persisted
   backoff. Submission execution, external notifications, target downtime handling,
   and OS startup scheduling remain to be added. No worker contacts target assets.
6. **Confirmation and payout reconciliation:** optional authorized email/platform
   access and duplicate-resistant updates. Platforms handle actual payment; the
   application only records evidence of it.

No authenticated platform access, live testing, messages, submissions, schedules,
or payments were performed to implement this build. The demo and tests are offline;
the new worker uses the network only when you configure and run it.

## Validation

Run `python scripts/test.py`. The suite covers hostile URL boundary cases, catalog
types and duplicates, payout ranking, time-window behavior, workflow transitions,
retry exhaustion, independent pause gates, transactional rollback, persistence,
exact payment totals, Markdown escaping, and the full CLI demonstration/export.
