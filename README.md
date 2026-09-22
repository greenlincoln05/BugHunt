# BugHunt

A local bug bounty workflow for modest, well-scoped opportunities. The default
shortlist favors advertised **USD 50–2000** ranges, which is a starting point
rather than a ceiling — pass wider `--min-payout`/`--max-payout` bounds for any
program a human has decided is worth pursuing. Python 3.11+ is the only runtime
requirement; there are no runtime dependencies, paid APIs, or model calls.

BugHunt provides policy checks, submission preparation, retry controls, reports,
and an unattended **read-only HackerOne program discovery worker**. It does **not**
scan targets, discover vulnerabilities, generate patches, send reports, read email,
or collect money. Bugcrowd and Intigriti currently use manual import/export.
Discovery collects candidate programs; it is not an income-generating scanner.

## Account setup and AFK discovery

Start with a HackerOne researcher account and a personal API token. The complete
[account and AFK setup guide](docs/accounts-and-afk.md) includes official account
links, hidden token entry on Windows, and start/stop commands. No paid API or model
subscription is required by the application.

```powershell
python run_bughunt.py setup
python run_bughunt.py worker status
.\scripts\Start-Worker.ps1
```

The launcher prompts for the API token identifier and a hidden token, then starts
a background worker. It checks public, open, monetary-bounty programs through
HackerOne's official API and writes `reports/discovery/opportunities.json` after
each complete refresh. It makes no requests to candidate companies' assets.

Use `python run_bughunt.py worker stop` to stop between request batches. Scope and
automation permission still need program-specific verification before testing.
The API does not supply reliable payout ranges in this endpoint, so discovered
payout bounds stay unknown until policy review; the existing USD 50–2000 shortlist
continues to use manually recorded advertised ranges.

## Run it

From this repository directory:

```powershell
python run_bughunt.py --help
python run_bughunt.py demo
python scripts/test.py
```

The demo writes `.bughunt/demo.db` and three reports under `reports/demo/`.
Its findings, acceptance records, and $100 received / $200 pending are **entirely
fictitious**. It makes no network requests. The demo refuses to populate a database
that already contains records. To repeat it, choose a fresh database:

```powershell
python run_bughunt.py --db .bughunt/demo-2.db demo --out reports/demo-2
```

Normal commands use a separate `.bughunt/bughunt.db`. The optional `--db` argument
goes **before** the command. All paths are relative to your current directory.
If you prefer an installed command, `python -m pip install -e .` installs the
`bughunt` entry point (installation requires setuptools; the source runner does not).

## Program catalog and shortlist

Create a local JSON file with the programs you have selected from their official
platform pages. `examples/programs.json` documents the shape and deliberately
contains only a blocked, unverified localhost fixture.

```powershell
python run_bughunt.py init
python run_bughunt.py program import examples/programs.json
python run_bughunt.py program list
python run_bughunt.py program shortlist --min-payout 50 --max-payout 2000 --currency USD
```

A real catalog entry looks like this; replace the illustrative values with an
actual program's documented terms before recording verification:

```json
{
  "programs": [{
    "id": "example-program",
    "name": "Example program (replace with verified details)",
    "platform": "hackerone",
    "program_url": "https://example.com/bounty-policy",
    "status": "active",
    "automation_allowed": false,
    "scope": ["https://app.example.com/api"],
    "excluded_scope": ["https://app.example.com/api/billing"],
    "payout_min": "50",
    "payout_max": "200",
    "currency": "USD"
  }]
}
```

Supported platform labels: `hackerone`, `bugcrowd`, `intigriti`, `manual`.
Statuses: `active`, `paused`, `closed`. Payout amounts are decimal strings;
currencies are uppercase three-letter codes. IDs are lowercase hyphenated slugs.
Imports reject unknown fields, duplicate IDs, invalid types, and malformed dates.
Replacing a program clears its previous verification and preserves existing blocks.

Shortlisting selects active, unblocked records with both payout bounds in the
requested currency and an overlapping advertised range. It ranks closer ranges
first, with stable name/ID tie breaking. Unknown payout ranges are omitted.
It does not infer company size, likelihood of finding a bug, or a guaranteed award;
choose startup and medium-company programs when assembling your catalog.

## Scope and verification

After checking the official program page for an active monetary bounty, exact
scope, exclusions, and permission for automation, record the evidence:

```powershell
python run_bughunt.py program verify example-program --automation-allowed --note "Checked official policy URL, scope and automation terms; record source and date here"
python run_bughunt.py scope example-program https://app.example.com/api/profile
```

Verification is your explicit attestation, not an automatic platform check. It
expires after 24 hours by default; `--valid-hours` accepts 1–168. Permission starts
false, and a matching URL is insufficient without current verification.

- URL rules match scheme, effective port, and path segment boundaries.
- Hostname rules match the exact host on HTTP/HTTPS and any port.
- `*.example.com` matches subdomains, excluding the root domain.
- Exclusions win, and are broader than inclusions: a URL exclusion covers every
  scheme, port, and letter-case variant of its path. Wildcards (`*`, `{}`, `<>`) are
  not supported inside URL rules and make the policy invalid. Ambiguous URLs and
  malformed policies fail closed.
- Scope checks never contact the target. Future executors must recheck redirects
  and enforce DNS/network restrictions separately.

Record restrictions immediately with `program block ID --reason "..."`.
`program unblock ID --note "..."` records a review and still requires fresh
verification. `audit-target ID URL --note "..."` records an audit you actually
performed; scope checks alone never inflate the audited-target metric.

## Findings and submission records

Save reproduction steps to a local text or Markdown file. Commands print JSON,
including generated IDs needed by the next step. The IDs below are placeholders.

```powershell
python run_bughunt.py finding add example-program --target https://app.example.com/api/profile --title "Concise issue title" --type "validation" --severity low --reproduction-file reproduction.md --impact "Concrete impact supported by evidence"
python run_bughunt.py finding confirm FINDING_ID --evidence "Reference to reproduced behavior and test output"
python run_bughunt.py finding patch FINDING_ID --status verified --reference fixes/issue.patch --verification "Regression test command and result"
python run_bughunt.py submission draft FINDING_ID
python run_bughunt.py submission export SUBMISSION_ID --output reports/submission.json
```

`finding brief FINDING_ID [--output brief.json]` writes the patch task for
**Astra**, who writes the code fixes for CVEs and bugs; BugHunt itself never
generates patches. It requires a confirmed finding and current scope verification.
The brief includes the active Python executable and exact database path in its
patch-recording command. `record_patch.shell` identifies PowerShell or POSIX shell;
automated consumers should replace the two evidence placeholders in
`record_patch.argv` and run that argument list with `shell=False`. Delivery is
audited after the output file closes, or after stdout is written and flushed.

Findings support an optional `--cvss` score from 0–10. Patch references and test
evidence are recorded as supplied; BugHunt does not execute or validate the patch.
For issues without an available source patch, use `--status not_applicable
--verification "Document why no patch applies and the proposed remediation"`.

### Patch workspace (real regression evidence, still human-confirmed)

The end goal for this workflow is open-source-first: pick a program with a
declared source-code asset, work against a local clone of it, and never touch
anyone's live infrastructure. `opportunity dossier` already reports which
assets are source code:

```powershell
python run_bughunt.py opportunity dossier OPPORTUNITY_ID --output reports/dossiers/pick.json
```

The saved file's `source_code_assets` lists each declared repo (`reference`) and
whether it's eligible for bounty. Read the entries yourself — they're the
program's own unverified claim — then clone the one you chose:

```powershell
python run_bughunt.py workspace clone --url https://github.com/OWNER/REPO --into C:\path\to\checkout --depth 1
```

`workspace clone` accepts only a plain `https://` Git remote with no embedded
credentials, refuses to overwrite an existing destination, and is bounded by a
timeout — it never clones over `ssh://`/`git://`/`ext::`/`file://`. Once a patch
author (Astra or otherwise, or you) has made a change in that checkout, capture
real evidence instead of typing a freehand claim:

```powershell
python run_bughunt.py finding evidence FINDING_ID --workspace C:\path\to\checkout --command "pytest tests/test_fix.py" --timeout 300 --output reports/evidence.json
```

This runs exactly the command you give it, inside that workspace, with the same
trust and network access as if you had typed it into your own terminal. It
captures the real exit code, stdout/stderr (each capped at 32 KiB), and the
uncommitted `git diff` (capped at 200 KiB) into JSON — printed to stdout, or
written with `--output` (exclusive create, like `submission export`). **It never
changes `patch_status` and never submits or collects anything** — it only
produces evidence. Feed that file straight into the patch record instead of
retyping it:

```powershell
python run_bughunt.py finding patch FINDING_ID --status verified --evidence-file reports/evidence.json
```

`--evidence-file` fills `--reference`/`--verification` from the captured JSON
(an explicit `--reference`/`--verification` still overrides it). Marking
`--status verified` from an evidence file that shows a failing or timed-out run
is refused — review it yourself and fix it, or record `--status ready` instead
while it's still in progress.

The exported JSON includes the program policy, reproduction steps, impact,
confirmation evidence, patch reference, and submission state. Attach actual patch
and proof-of-concept files separately in the official portal. Export refuses to
overwrite an existing file and never sends anything.

After submitting through the official portal, record its ID. Record acceptance
only when the platform acknowledges it:

```powershell
python run_bughunt.py submission record SUBMISSION_ID --external-id OFFICIAL_REPORT_ID
python run_bughunt.py submission accept SUBMISSION_ID --note "Official acceptance message reference" --expected-payment-date 2026-10-01
python run_bughunt.py payment add SUBMISSION_ID --amount 100 --currency USD --expected-date 2026-10-01
python run_bughunt.py payment receive PAYMENT_ID --note "Platform payment receipt reference"
```

A finding must be confirmed before drafting. Recording submission requires fresh
scope verification and a verified patch or documented not-applicable rationale.
Payments require explicit acceptance. Installments remain separate; a submission
becomes `paid` only after all recorded installments are received. No currency
conversion is performed.

For rejected reports:

```powershell
python run_bughunt.py submission reject SUBMISSION_ID --reason "Official rejection reason"
python run_bughunt.py submission review SUBMISSION_ID --note "Reviewer decision and precise documentation/patch changes"
python run_bughunt.py submission record SUBMISSION_ID --external-id OFFICIAL_REPORT_ID
```

Every rejection needs a new review before another attempt. There is one original
submission plus at most two resubmissions. A third rejection sets `needs_review`
and cannot be retried through the normal workflow. Creating another submission
for the same finding cannot reset this limit.

`submission error ID --kind rate_limit --note "..."` sets a one-hour backoff;
`downtime` also delays eligibility by one hour. `authentication` and
`unclear_status` pause the record until `submission resume ID --note "..."`.
Resuming authentication does not bypass rate-limit backoff. These are persisted
workflow gates for manually recorded submissions. The discovery worker has its
own durable backoff and pause state; it never retries or sends a submission.

## Reports and audit trail

```powershell
python run_bughunt.py reports --out reports
python run_bughunt.py submission list
python run_bughunt.py payment list
python run_bughunt.py audit
```

- `vulnerabilities_found.json`: findings, severity, patch state, platform, and IDs.
- `submissions_status.md`: recorded statuses, dates, attempts, and rejection details.
- `weekly_payout_report.md`: trailing-seven-day activity, pending/received amounts
  by currency, and average submission-to-acceptance time.

Each report replaces its previous version atomically. Database changes and their
audit entries commit together. The log is append-only through the application,
but local database owners can edit it; it is not a tamper-proof ledger. SQLite
records and report files are unencrypted and ignored by Git. Keep sensitive
reproduction material in appropriately protected local storage; no account
credentials are stored in the database. The optional discovery worker reads its
API identifier/token from the process environment and never prints them.

CLI exit codes: `0` success, `2` invalid command/data or storage failure, `3` scope
denied, `4` discovery needs attention, `130` interrupted. Handled command failures
are logged when the database remains writable.

## Next implementation stages

The [first-dollar workflow](docs/first-dollar.md) covers `progress`, official
scope dossiers, duplicate-resistant receipt recording, and current access needs.

See [architecture.md](docs/architecture.md) for module boundaries and the remaining
platform discovery, reconnaissance, patch-development, scheduling, and account
integration work. The user-supplied Markdown is a product specification, not an
installed system prompt or authorization to operate on arbitrary targets.
