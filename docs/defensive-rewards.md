# Rewards for defensive contributions

BugHunt can track two different routes: reports of new security findings and
rewards for preventive code improvements. Choose the route before investing in
a patch. Advertised amounts are discretionary awards, not payment commitments.

## Google Patch Rewards

The [official rules](https://bughunters.google.com/about/rules/open-source/patch-rewards-program-rules)
reward qualifying hardening in listed projects. The
[scope list](https://github.com/google/bughunters/blob/main/patch-rewards-program/scope.md)
includes Django, Flask, Jinja, Werkzeug, and pip in Tier 1. The base Tier 1
awards are $500, $2,000, $7,500, or $15,000 according to the panel's assessment.
This offers a possible route for useful preventive improvements without
claiming a newly discovered vulnerability.

Start with a bounded, maintainer-supported hardening task. Check contribution
rules and existing issues/PRs before implementing it. Prepare a focused patch,
normal correctness tests, and a clear explanation of its security benefit.
Keep a patch proposal distinct from a confirmed security finding.

The patch must be accepted upstream and remain unreverted for at least one
month before submitting to Google. Patches over 12 months old are ineligible;
the rules limit individuals to three submissions per month. The human
submission uses the [Patch Rewards form](https://bughunters.google.com/report/patch_rewards).
Upstream acceptance, the waiting period, and a panel decision remain necessary.

## Source-code bounties

[Vercel](https://hackerone.com/vercel) includes eligible open-source projects.
Its [reward history](https://hackerone.com/vercel/scope_and_rewards_versions)
lists low/medium OSS awards of $200/$500 for Tier 2 and $500/$1,000 for Tier 1.
It requires a validated, actionable security finding; hardening alone is not
enough. Check the current program policy and the selected project's security
policy before relying on its eligibility.

[Microsoft Open Source](https://www.microsoft.com/en-us/msrc/opensourcebountyprogram)
offers $750-$15,000 for qualifying findings in its explicitly listed
repositories. Critical or Important impact on the latest maintained branch is
required. Samples, demos, experimental components, already known issues, and
documentation-only fixes are excluded. Moderate and Low severity receive no
award under its published table.

These programs should not be treated as payment sources for ordinary feature
work. A preventive patch suitable for Google is not automatically eligible for
a vulnerability bounty elsewhere.

## Recording progress accurately

Keep selected-program catalog imports, dated policy notes, candidate details,
and contribution drafts in ignored `reports/` or `.bughunt/` paths. Catalog
imports should remain unverified with `automation_allowed: false` until the
appropriate review has occurred; recording a source repository is not
permission to test deployments. Catalog URL rules also do not encode every
prose exclusion in a program's policy.

The current catalog has no reward-route field. A Patch Rewards entry appears
alongside vulnerability bounties in `program shortlist`; use that entry for
research/ranking only. Do not use `finding add` or the finding-based submission
workflow to represent an ordinary preventive contribution.

For a preventive contribution, track the upstream commit/PR, acceptance date,
test results, one-month eligibility date, reward-submission ID, panel outcome,
and eventual receipt separately. The existing finding workflow must not be
populated with invented vulnerabilities to make a hardening patch fit it.
Submission and payment recording remain explicit human actions. A draft,
merged patch, advertised bounty, or award promise is not received revenue.

Recheck status before spending time. The
[OSV-SCALIBR Patch Rewards pause](https://github.com/google/osv-scalibr/issues/1949#issuecomment-4900882650)
applies to new submissions, even though older accepted work may still be
reviewed and paid. It is a separate program from general Google Patch Rewards.

Sources checked on 2026-09-27. Recheck terms at implementation and submission.
