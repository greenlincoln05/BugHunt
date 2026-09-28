"""Human-reviewable local report text; never sends a submission."""


def render_submission_markdown(bundle: dict) -> str:
    """Render the existing submission bundle as a paste-ready draft."""
    program = bundle["program"]
    finding = bundle["finding"]
    title = str(finding.get("title") or "Untitled finding").strip()
    lines = [
        f"# {title}",
        "",
        f"Program: {program.get('name') or program.get('id') or 'Unknown'}",
        f"Affected asset: {finding.get('target') or 'Not recorded'}",
        f"Type: {finding.get('type') or 'Not recorded'}",
        f"Severity: {finding.get('severity') or 'Not recorded'}",
    ]
    if bundle.get("policy_warning"):
        lines.extend(("", f"Policy status: {bundle['policy_warning']}"))
    for heading, value in (
        ("Impact", finding.get("impact")),
        ("Steps to reproduce", finding.get("reproduction")),
        ("Confirmation evidence", finding.get("confirmation_evidence")),
        ("Patch and regression evidence", finding.get("verification")),
    ):
        if isinstance(value, str) and value.strip():
            lines.extend(("", f"## {heading}", "", value.strip()))
    reference = finding.get("patch_reference")
    if isinstance(reference, str) and reference.strip():
        lines.extend(("", f"Patch reference: {reference.strip()}"))
    lines.extend((
        "",
        "Review the current program rules and attach the actual proof-of-concept "
        "and patch files in the official portal before submitting.",
        "",
    ))
    return "\n".join(lines)
