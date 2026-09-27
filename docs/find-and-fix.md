# Local source research to a reportable finding

This runbook works without an OpenAI API key. Codex can review a local clone;
the paid `workspace analyze` path remains separately gated. Keep unpublished
vulnerability details, test apps, credentials, and reports in the ignored
`.bughunt/` directory rather than the public repository.

1. **Choose the program before the code.** Read its current official scope,
   rules, exclusions, testing limits, and disclosure terms. Confirm that the
   repository and release are eligible. Use a local checkout or an environment
   you own; never treat public source availability as permission to test a
   third-party deployment.
2. **Review a bounded area.** Start with shipped stable code and trace one
   trust boundary: authentication and authorization, signed or encrypted
   state, deserialization, file and command handling, or outbound requests.
   Dependency scanners are lead generators; a CVE version match alone is not
   a report. Record the exact package version, commit, entry point, and
   assumptions privately.
3. **Reproduce the behavior locally.** Write a small test or app that uses the
   published release and its documented integration. Compare a normal request
   to the changed input, then rerun against an optimized production build when
   relevant. Use fixed test secrets and loopback networking. Preserve the
   commands and observed output in the private research notes.
4. **Test the impact claim separately.** Identify what an unauthenticated or
   lower-privileged actor can actually read, write, or execute. Check whether
   the application itself is responsible for the missing authorization. A
   changed feature flag or unexpected response in a synthetic app may prove
   a library defect without proving a bounty-eligible security breach.
5. **Prepare private evidence.** Capture a minimal reproducible archive,
   affected-version list, source permalink, expected and actual results, and
   a narrowly stated impact. Check the archive for secrets, generated output,
   and unrelated source. Search public issues and advisories for duplicates;
   private duplicates cannot be ruled out.
6. **Review before submission.** Recheck the live program policy, then have a
   person verify the PoC and decide whether the demonstrated impact meets the
   program's requirements. A person submits the report through the platform.
   Do not publish the vulnerability or a related fix while disclosure terms
   require confidentiality.

After a confirmed finding, use BugHunt's evidence and draft commands to keep
the local record current. Record a payment only from a real receipt.
