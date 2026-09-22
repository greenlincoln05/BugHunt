# Repository workflow

- The user wants completed changes committed and pushed to GitHub by default so
  the repository is runnable from another machine. Do not leave completed work
  only in the local checkout. Report the pushed commit and any push failure.
- Run `python scripts/test.py` for code changes before pushing. Keep the source
  runner (`python run_bughunt.py`) usable without third-party runtime packages.
- Preserve unrelated work. Do not force-push or rewrite remote history.
- Keep credentials, local databases, generated reports, and demo output out of Git.
- The user's bounty preference is modest, well-scoped programs, USD 50–2000 by
  default; there is no fixed ceiling. A higher advertised payout (e.g. USD 2,000+)
  is fine to shortlist and pursue when a human judges the finding tractable and
  worth the effort/token cost — do not let a large payout alone lower the bar for
  scope verification, evidence, or submission review.
- No stage of this workflow submits a report or records a payment automatically.
  `submission record`/`accept` and `payment receive` are explicit, human-run CLI
  commands with required evidence arguments; keep them that way. Do not build a
  path that lets any model (Astra, Codex, Daybreak, or otherwise) call these
  without a human invoking the command with real evidence in hand.
- **Stated end goal (2026-09-22):** the user wants the human's part reduced to
  reviewing a diff/writeup and clicking submit, then getting paid. The buildable
  path there is OSS-source-first: target programs with a declared `SOURCE_CODE`
  asset (`dossier.source_code_assets`), clone it locally with `workspace clone`,
  find and fix real bugs there (no live target is ever touched), and capture real
  regression proof with `finding evidence`. Keep building this direction out —
  more of the discover -> analyze -> patch -> evidence -> draft chain should
  require less retyping each time — but the final submit stays an explicit human
  action, always, for the reasons above.
