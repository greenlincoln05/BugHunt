# First-dollar workflow

Earning a bounty requires a reproducible finding, a valid submission, program
acceptance, and actual payment. No real payment is currently recorded in this
checkout's production database.

## Progress and next actions

Run from the repository root with Python 3.11 or newer:

```powershell
python run_bughunt.py setup
python run_bughunt.py worker status
python run_bughunt.py progress --out reports/progress
```

`progress` produces a next-action queue from the database: missing credentials,
stale discovery, policy review, unfinished findings, submission pauses, backoff,
rejection review, pending triage, and receipt evidence. It does not mutate records
or contact any service. Credential presence refers only to the current process;
another terminal or running worker can have different credentials.

If a worker runs from another checkout, read that database directly without
creating, migrating, or updating it:

```powershell
python run_bughunt.py progress --source-db C:\Users\Lincoln\BugHunt\.bughunt\bughunt.db --out reports/progress
```

`--source-db` opens a consistent, read-only SQLite snapshot and cannot be combined
with `--db`. A recent successful sync means the reporter can use saved discovery
even when its own process has no API token. This does not prove the worker is
still alive or grant the reporter credentials for new API calls. The launcher
restores its parent shell's environment; prompted credentials remain in the
child worker's memory until that process exits.

The generated `first_dollar.json` and `first_dollar.md` stay local and are ignored
by Git. The USD 1 threshold counts received installments with unique platform
receipt references and valid dates, tied to accepted submissions with official
report IDs. Demo databases and note-only legacy receipts cannot satisfy it.
Currencies remain separate. This is a **user attestation**, not independent
platform or bank verification. Check the actual official receipt before declaring
the milestone complete.

## Retrieve official scope metadata

With HackerOne credentials configured locally:

```powershell
python run_bughunt.py worker once
python run_bughunt.py opportunity list
python run_bughunt.py opportunity dossier OPPORTUNITY_ID --max-pages 3 --output reports/dossiers/selected-program.json
```

The dossier reads structured scopes and reward exclusion categories from the
[official HackerOne API](https://api.hackerone.com/hacker-resources/) and attaches
the candidate policy already saved by discovery. It never visits asset URLs.
Collection is capped at 1-20 scope pages plus one exclusions request. Inspect
`completeness`: an incomplete collection must not be treated as complete scope.
Use a new output filename for each retrieval; existing evidence is not overwritten.

The candidate policy can predate the scope request. Review the current official
program page, advertised bounty, policy exclusions, and permission for the
intended activity. A dossier does not import or verify a program automatically.
Unsupported asset types remain metadata rather than local URL scope rules.

## Record an actual receipt once

After an accepted report and recorded award installment:

```powershell
python run_bughunt.py payment receive PAYMENT_ID --note "Actual receipt evidence" --receipt-reference UNIQUE_PLATFORM_RECEIPT --received-at 2026-09-21T12:00:00Z
python run_bughunt.py progress --out reports/progress
```

Use the actual receipt time with a timezone. It cannot be in the future or before
the report submission. Omit the date to use now. Replaying the same reference,
note, and date for one payment does not duplicate the receipt or audit event.
Reusing a reference for another payment on the same platform is rejected.
One reference represents one installment; splitting one transfer across several
reports is not yet supported. Note-only receipts remain manual records and do
not establish the first-dollar milestone.

## Model access

HackerOne tokens and OpenAI API keys serve different services. Keep secrets
local; never commit them or paste them into chat. Discovery needs only
`HACKERONE_USERNAME` (the token identifier) and `HACKERONE_API_TOKEN`.

Daybreak requires Trusted Access approval for the specific model and product
surface. An API key or purchased Codex credits alone does not confer that access.
Use the [individual application](https://chatgpt.com/cyber) and confirm which
workspace or API project is approved. Daybreak Red requires separate approval.
See the [official access guide](https://learn.chatgpt.com/docs/cyber-safety).

Once you have an approved API project, configure `OPENAI_API_KEY` locally and set
`BUGHUNT_OPENAI_MODEL` to the exact approved model ID. Optional routing variables
are `OPENAI_ORG_ID` and `OPENAI_PROJECT_ID`. No model is chosen automatically.

```powershell
python run_bughunt.py model status
python run_bughunt.py model check
```

`status` checks presence only. `check` sends a bounded GET to the official
retrieve-model endpoint; it does not perform inference or start research. The
output does not reveal keys or account identifiers. Retrievable model metadata
is not proof of Trusted Access approval or permission to run inference. A failed
check exits 4 and never selects a fallback model. The approved research executor
is a later integration, after access and program terms are established.

Unattended worker operations retry SQLite BUSY/LOCKED errors up to three times
with five-second delays. If the database remains unavailable, the worker exits
with a clear attention state marked `persisted: false`; restart after resolving
the contention. Initial database opening and schema setup still use the normal
CLI error path. Other database faults remain errors rather than retry loops.

## Continuation state — 2026-09-21 UTC

- GitHub `main` was reviewed at `2b97d87335ad380d546f1eaf3161cf1a3a5938b3`.
  There were no open issues or PRs; recent CI runs passed. Baseline: 102 tests.
- This milestone adds scope dossiers, receipt-reference deduplication, a local
  progress/action queue, model metadata preflight, and database contention fixes.
  All 157 tests pass locally. Live HackerOne and OpenAI model access still need
  configured credentials in the invoking process.
- The prior Codex task recorded three cybersecurity screening failures and an
  earlier weekly usage-limit failure. The user added credits and identified an
  attempted Daybreak use without prior access. They are applying for access.
- The user identified the live runtime checkout as `C:/Users/Lincoln/BugHunt`.
  Python worker PID 82868 was verified running on 2026-09-21. Its production
  database is `.bughunt/bughunt.db` under that runtime checkout, not the development
  checkout. At 03:25:20 UTC it completed a snapshot of 223 candidates; there were
  zero programs/findings/submissions/payments. Recheck current state on each run.
  Use `progress --source-db` for that live database and keep generated reports in
  the development workspace. Do not start a duplicate worker or copy its token
  out of process memory. New standalone API requests still need locally supplied
  credentials in their invoking process.
- The live-database integration passes all 168 tests, including read-only file
  preservation and a consistent snapshot while another connection commits.
- Daybreak access remains pending while the user arranges security keys. Do not
  repeatedly request credentials or attempt that model while approval is pending.
- Ignored `.bughunt/research/status.json` records Zabbix selected for an owned
  local sandbox, zero revenue, and no confirmed findings. This is historical
  context, not current authorization or a confirmed bug.
- Next: account/model preflight, a fresh candidate/scope review, then a bounded
  local source or owned sandbox investigation once access and current program
  terms are established. Keep third-party reports private.
- Push completed, tested changes as `AGENTS.md` requires. Exclude credentials,
  policy dumps, reports, research checkouts, databases, and receipts from Git.
- An hourly Codex heartbeat named `BugHunt first-dollar follow-up` continues this
  task. It requires the local host/app to be available; it is separate from the
  Python discovery worker and does not make unavailable credentials or models
  available. Notify only for meaningful changes or required user action.
- Continue until evidence establishes USD 1 actually received for this effort,
  then stop the recurring follow-up. Demo data, award promises, and generated
  reports do not count. Surface concrete blockers and avoid unchanged failures
  or empty retries that waste credits.
