# Architecture and implementation boundary

The first release is a local workflow foundation using Python's standard library.
The user's latest priority overrides the source document's preference for
high-severity, high-payout targets: the shortlist defaults to USD 50–2000, which is
a starting point rather than a ceiling, and the catalog is intended for selected
startup or medium-company programs. A higher advertised payout does not relax any
scope, verification, or evidence requirement below — submission and payment
recording stay explicit, human-run actions regardless of the amount.

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
| `patchwork.py` | Runs one chosen command in one chosen local Git workspace and captures real regression/diff evidence; never marks a patch verified itself |
| `workspace.py` | Bounded, HTTPS-only local clone of a program's own declared source-code asset; never a live target |
| `triage.py` | Bounded, resumable batch dossier check over discovered candidates; writes a local source-eligible shortlist |

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

## Stated end goal: OSS-source-first, human reviews and clicks submit

The user's direction (2026-09-22) is to minimize their own involvement down to
reviewing a diff/writeup and clicking submit, then getting paid. Two things stay
true regardless: every real bug bounty platform ties automation permission and
payout identity/KYC to a specific accountable human, and unreviewed AI-submitted
reports get accounts banned on these platforms today -- so a fully unattended
"find, exploit, submit, collect" loop against **live** targets isn't just outside
what this project does, it would work against the user's own goal even if built.

The buildable path that gets close: target programs with a declared source-code
asset instead of a live web/API target. There is no live system to touch --
analysis happens against a local clone, which is ordinary software engineering,
not testing someone's production infrastructure. That removes essentially all of
the scope/disruption/legal risk that live-target automation carries, and it is
where the chain below should keep getting less manual over time:

`opportunity dossier` (surfaces `source_code_assets`) -> `workspace clone` (one
human-chosen URL, HTTPS only) -> find and fix a real bug in the clone -> `finding
evidence` (real regression + diff, capped and timed out safely) -> `finding patch
--evidence-file ...` (captured evidence fills the record instead of retyping it)
-> `submission draft`/`export` (bundle ready for review). The only steps that
must stay an explicit, separate human action are picking the clone URL, deciding
whether a fix is actually correct, and clicking submit -- everything else is fair
game to keep automating and streamlining.

1. **Discovery adapters:** HackerOne program discovery is implemented, with raw
   policy text, a completed-snapshot timestamp, bounded pagination, and unknown
   payouts preserved. Selected candidates can export detailed scope and reward
   exclusion dossiers for review, including which declared assets are source
   code (`source_code_assets`) versus live infrastructure. `opportunity triage`
   turns that per-candidate dossier check into a bounded, resumable batch over
   every already-discovered candidate (own request budget, stops early instead
   of hammering the API on auth/rate-limit failure, one candidate's error never
   blocks the rest, skips what it already checked unless `--recheck`), and
   writes a local shortlist of source-eligible candidates. Other platforms and
   automatic synchronization remain to be added. A discovery or triage result
   never becomes a verified test authorization automatically.
2. **Reconnaissance executor (live targets):** intentionally not being built
   toward. Controlled, non-destructive checks on specifically configured
   authorized live assets would need redirect reauthorization, network/DNS
   enforcement, request budgets, rate limits, and reproducible evidence capture
   -- and even then, still a human go/no-go per program. The current scope
   matcher alone is not an HTTP execution sandbox, and that gap is deliberate.
3. **Patch workspace:** `workspace clone` (bounded, HTTPS-only, no credentials,
   no overwrite) sets up the local checkout; `finding evidence` runs one chosen
   command in it and captures the real exit code, stdout/stderr, and uncommitted
   diff; `finding patch --evidence-file ...` carries that captured evidence
   straight into the patch record instead of it being retyped. None of these
   touch a live target, none choose the command or URL for you, and none change
   `patch_status` on their own -- a human still reviews the evidence and runs
   `finding patch` deliberately. Remaining: ephemeral/disposable checkouts,
   automatic before/after diffing against the program's real upstream, an
   actual semi-autonomous find-the-bug step (static analysis/fuzzing) run
   against a fresh clone, and proof-of-concept artifact capture.
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
