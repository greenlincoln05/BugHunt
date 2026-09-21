# Repository workflow

- The user wants completed changes committed and pushed to GitHub by default so
  the repository is runnable from another machine. Do not leave completed work
  only in the local checkout. Report the pushed commit and any push failure.
- Run `python scripts/test.py` for code changes before pushing. Keep the source
  runner (`python run_bughunt.py`) usable without third-party runtime packages.
- Preserve unrelated work. Do not force-push or rewrite remote history.
- Keep credentials, local databases, generated reports, and demo output out of Git.
- Favor the user's USD 50–200 bounty preference when extending program selection.
