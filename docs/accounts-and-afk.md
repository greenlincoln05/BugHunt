# Accounts and unattended discovery

## Create these accounts

Start with **HackerOne**, because this build has a working read-only API adapter
for it. A bounty account does not grant blanket testing permission. Review each
program's rules, scope, exclusions, and automation terms before using its assets.

| Platform | Account to create | Supported in this build |
| --- | --- | --- |
| HackerOne | [Researcher account](https://hackerone.com/users/sign_up) | Official API program discovery and local report preparation |
| Bugcrowd | [Researcher account](https://login.hackers.bugcrowd.com/signin/register) | Manual program import and local report preparation |
| Intigriti | [Researcher signup guide](https://kb.intigriti.com/en/articles/5378975-creating-an-intigriti-account) | Manual program import and local report preparation |

On HackerOne, use Settings -> API Token to create a personal token. The API token
**identifier** and value are the two credentials; the identifier is not necessarily
your public username. Keep them local. See the official
[token instructions](https://docs.hackerone.com/en/articles/8410331-api-token).
Generating a replacement token revokes the previous one.

Bugcrowd's [researcher onboarding guide](https://docs.bugcrowd.com/researchers/onboarding/researcher-onboarding/)
walks through email verification and required 2FA. Intigriti's guide above covers
account activation, 2FA, and payment details. Complete payout/identity requirements
inside the platforms when requested; do not put those details in BugHunt.

## Start on Windows

After pulling this commit, use Python 3.11 or newer from the repository directory:

```powershell
git pull
python scripts/test.py
python run_bughunt.py setup
.\scripts\Start-Worker.ps1
```

The script prompts for the token identifier and masks token entry. It starts Python
in a hidden background process and passes credentials through its environment,
not command arguments or files. Credentials exist in the worker's memory until
it exits; they are not stored in SQLite. Previously configured environment values
are restored in your launching shell. Run the script again after restarting your
computer; there is no installed Windows service or startup task.

If your shell blocks `.ps1` scripts, the Python CLI also runs directly; follow your
machine's script policy rather than changing it globally. With credentials already
set in the current process environment, run:

```powershell
python run_bughunt.py worker once
python run_bughunt.py worker run
```

The environment keys are `HACKERONE_USERNAME` (API token identifier) and
`HACKERONE_API_TOKEN`. No `.env` file is loaded automatically. Do not paste actual
tokens into chat, screenshots, shell command arguments, or Git.

Keep the computer on and awake while the worker runs. The launcher defaults to
three pages per batch, 100 programs per page, every 15 minutes. Change these with
`-MaxPages 10 -IntervalSeconds 900`. Limits are 1–20 pages and 60–86400 seconds;
the client uses a 20-second socket timeout and a 4 MiB response limit per page.

## Check, stop, and recover

```powershell
python run_bughunt.py worker status
python run_bughunt.py opportunity list
python run_bughunt.py opportunity export
python run_bughunt.py worker stop
```

- `reports/discovery/opportunities.json` contains the last complete snapshot of
  public, open, bounty-paying program candidates, with the snapshot timestamp.
- The same directory receives the normal findings, submissions, and payout reports.
- `.bughunt/worker.stdout.log` and `.bughunt/worker.stderr.log` contain background
  process output. They are ignored by Git.
- `worker stop` is cooperative: an active page batch finishes before stopping,
  without publishing that batch. While idle, stop is checked every five seconds.
- `worker run --max-cycles 1` performs at most one batch/check and exits. `0`, the
  default, means run until stopped or attention is needed.

A partial refresh is saved in SQLite and continued later. Old candidates are not
deleted just because a page limit was reached. Once the full refresh finishes,
closed or missing programs are removed from the opportunity snapshot. Discovered
metadata never silently changes your verified local target catalog.

HTTP 429 backs off for at least one hour and honors a longer `Retry-After`. Temporary
network/server failures retry after the configured interval (at least 60 seconds).
Authentication and malformed-response errors pause and exit, avoiding endless
retries. After fixing the credentials or reviewing a connector error:

```powershell
python run_bughunt.py worker resume --note "Describe what was fixed"
.\scripts\Start-Worker.ps1
```

Resuming a pause cannot bypass a rate-limit deadline. Starting again clears the
stop request but does not clear a pause. If a process crashes mid-batch, its lease
expires after 15 minutes; a new worker can then continue. Database schema 1 is
upgraded automatically to schema 2 while preserving existing records. Old schema-1
code cannot open the migrated database; keep your normal database backups.

## What AFK mode accomplishes today

The worker collects and refreshes candidate programs through the
[official HackerOne API](https://api.hackerone.com/hacker-resources/), then writes
local reports. It sends only metadata GET requests to HackerOne. Credentials are
never forwarded through redirects or to a company's target assets.

Program payout bounds and company size are not provided by the supported endpoint.
They remain unknown. Review the saved policy and official program page for modest
USD 50–200 opportunities, then import the chosen scope and advertised payout range
through `program import` and record current permission through `program verify`.
The `fast_payments` flag is metadata, not a promised payday.

AFK discovery does **not** find vulnerabilities, run Astra, author patches, submit
reports, or earn money on its own. Claude's `finding brief` creates a local handoff
for a confirmed finding; its output now explicitly says that no agent was started.
A valid, in-scope finding and platform acceptance are still needed for any bounty.

## Review of Claude's commits

Reviewed `69ecf9a` and its newline fix `bb103b0`. The confirmation/scope checks and
exclusive file creation were sound. The handoff now includes verification evidence
and expiry, a complete patch-recording command, and explicit delivery status.
Regression tests exercise stdout, file JSON/newline correctness, overwrite refusal,
and unknown, unconfirmed, and expired findings.

The connector and worker tests use simulated API responses; a live account check
is still required after you create your account. No credentials or platform
accounts were available during this build, and no live worker was launched.
