# Roadmap

Living plan for the rest of the buildout, split around one event: **Daybreak
Trusted Access being granted**. Phase 1 is everything buildable and useful
right now, without it. Phase 2 is what actually changes once it's granted.

One constraint holds across both phases, unconditionally: **submitting a
report and recording a payment stay explicit, human-run actions** (see
`AGENTS.md`), and **live-target testing is not something this project builds
toward**, with or without Daybreak — see "What Daybreak access does *not*
unlock" at the end. Everything below works inside those lines.

## Where things stand

Built: program catalog + scope engine + finding/submission/payment state
machine (`catalog.py`, `scope.py`, `workflow.py`, `storage.py`, `cli.py`),
read-only HackerOne discovery (`hackerone.py`, `worker.py`), structured scope
dossiers with source-code-asset detection (`dossier.py`), a batch OSS
shortlist (`triage.py`), a bounded local clone helper (`workspace.py`), local
regression-evidence capture (`patchwork.py`), an OpenAI/Daybreak metadata
preflight with no inference (`model_access.py`), and a next-action tracker
(`progress.py`). 204 tests, all passing.

Gap: everything from "here's a cloned repo" to "here's a real, fixable bug in
it" currently happens only when an agent session (this one, or another) is
explicitly pointed at a specific workspace. There's no tooling yet that makes
that step itself faster, cheaper, or more mechanical — that's most of what
Phase 1 is.

## Phase 1 — now, before Daybreak access

Ordered roughly by how much it unblocks getting to a first real submission.

1. **`opportunity promote`** — bridge a triaged candidate straight into the
   program catalog. Right now `opportunity triage`/`dossier` tell you a
   program looks OSS-eligible, but getting it into `programs` (what
   `finding add`/`program verify` actually operate on) means hand-authoring a
   JSON file that matches `catalog.py`'s strict schema from scratch. This
   command should pre-fill `id`/`name`/`platform`/`program_url` from the
   opportunity and `scope` from the dossier's asset list, and still require a
   human to fill in payout figures and run `program verify` themselves — the
   verification attestation doesn't move, only the retyping goes away.

2. **`workspace audit-dependencies`** — the highest-confidence, lowest-cost
   source of real findings doesn't need any bug-finding intelligence at all:
   run standard, well-known SCA tools (`pip-audit`/`npm audit`/`osv-scanner`/
   `cargo audit`, whichever apply to the cloned repo) against a `workspace
   clone` checkout and cross-reference known CVEs in its actual pinned
   dependencies. Many programs pay bounties specifically for "you're shipping
   a dependency with a known CVE" reports. This is mechanical, bounded,
   local-only, and entirely buildable now — likely the single highest-value
   Phase 1 item.

3. **A written "find real bugs in a clone" runbook** (`docs/find-and-fix.md`)
   — formalize how an agent session should work a cloned workspace: run
   dependency auditing first (item 2), then targeted review of the usual
   high-yield areas (auth, deserialization, path/command handling, SSRF-prone
   outbound calls, injection sinks), then a regression test, then `finding
   evidence`. This isn't code — it's making "Astra's" approach consistent
   across sessions instead of ad hoc each time, so quality doesn't depend on
   which session happens to be running.

4. **Actually run the loop** — using items 2-3, work real candidates from the
   triage shortlist end to end (clone → audit/analyze → patch → `finding
   evidence` → draft) when directed to a specific one. This is where an
   actual first submission comes from; nothing above replaces doing it.

5. **Tighten submission drafting** — `finding patch --evidence-file` already
   removes retyping between evidence capture and the patch record; extend the
   same idea to `submission draft`/`export` so a finding with captured
   evidence needs the least possible manual re-entry before it's a reviewable
   bundle.

6. **`progress` covers the whole funnel** — today it tracks the original
   submission/payment lifecycle. Extend it to show triage → clone → finding →
   patch → evidence → draft as one pipeline view, so "what's the next action"
   answers the OSS-first chain, not just the tail end of it.

7. **Research (not build) a HackerOne draft-report push** — HackerOne's API
   may support creating a report as a *draft* (never sending it) so
   `submission export`'s bundle could land directly in HackerOne for you to
   review and click submit on, instead of copy-paste. This needs a broader
   (read+write) API scope than anything configured today, so it's a real
   decision point, not a silent addition — I'll bring back what the API
   actually supports before building anything against it.

8. **Keep the codebase itself reviewed** as it grows — periodic bug sweeps
   like the one that found and fixed 14 issues earlier, on whatever's changed
   since the last one.

## Phase 2 — after Daybreak Trusted Access is granted

Two things need settling first, before any integration work:

- **What "granted" provably looks like.** `model_access.py`'s `model check`
  only proves an API key can retrieve model metadata — its own output says so
  explicitly: that is not proof of Trusted Access. There may be no clean
  programmatic signal for actual approval, in which case Phase 2 opens the
  same way program scope does today: a human attestation (`model verify
  --note "..."`-style, mirroring `program verify`) rather than an automatic
  check, because there isn't a real API to check against.
- **Cost/rate posture.** Daybreak calls almost certainly cost differently than
  an agent session's own work. Before wiring it into anything, it needs the
  same bounded-batch treatment `triage.py`/`worker.py` already apply to
  HackerOne calls: a request budget, backoff, and a way to stop mid-run
  without losing progress.

With those settled:

1. **Daybreak as an additional analysis pass in the same loop**, not a
   replacement for it — it runs against a `workspace clone` checkout
   alongside the dependency audit and manual review from Phase 1, still fully
   local, still producing candidate findings for human review, never
   auto-confirming or auto-patching anything on its own.
2. **Gate it behind the real preflight**, not just key presence: no Daybreak
   call fires without both `model check` succeeding and the human attestation
   above being current — same fail-closed shape as `check_scope`.
3. **Reassess `workspace audit-dependencies` and the runbook** in light of
   what Daybreak is actually good at, so Phase 1's mechanical tooling and
   Daybreak's analysis complement each other instead of overlapping.
4. **Revisit item 7 from Phase 1** (draft-report push) if it's still
   unresolved — a faster analysis pass upstream makes a lower-friction
   submission path matter more.

### What Daybreak access does *not* unlock

Getting Trusted Access approved is about being allowed to use the model at
all — it is not a decision about testing live targets, and doesn't become
one. A reconnaissance executor against a program's live infrastructure stays
a separate, explicit decision this document doesn't make, requiring its own
per-program `automation_allowed` attestation, network/scope enforcement, and
your specific go-ahead — regardless of what model is or isn't approved by
then. If that ever becomes something to build, it gets its own plan, not a
line item here.
