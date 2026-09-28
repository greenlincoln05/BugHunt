"""Build a bounded, local-only review archive for a manual bounty submission."""

from hashlib import sha256
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from .submission_format import render_submission_markdown


MAX_ATTACHMENTS = 16
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _attachment_paths(paths):
    if len(paths) > MAX_ATTACHMENTS:
        raise ValueError(f"Review archive accepts at most {MAX_ATTACHMENTS} attachments")
    checked = []
    names = set()
    total = 0
    for path in paths:
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Attachment must be a regular file: {path}")
        name = path.name
        if name in {".", ".."} or "\\" in name or any(ord(character) < 32 for character in name):
            raise ValueError(f"Unsafe attachment filename: {name}")
        key = name.casefold()
        if key in names:
            raise ValueError(f"Duplicate attachment filename: {name}")
        names.add(key)
        size = path.stat().st_size
        if size > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"Attachment exceeds {MAX_ATTACHMENT_BYTES} bytes: {path.name}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError(f"Attachments exceed {MAX_TOTAL_BYTES} bytes in total")
        checked.append(path)
    return checked


def write_review_archive(handle, bundle, attachments):
    """Write a review ZIP to an exclusively created binary file handle."""
    paths = _attachment_paths(attachments)
    manifest = {"schema_version": 1,
                "delivery": "Private local review only; submit each file manually in the official portal.",
                "attachments": []}
    with ZipFile(handle, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("report.md", render_submission_markdown(bundle))
        archive.writestr("submission.json", json.dumps(bundle, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
        total = 0
        for path in paths:
            data = path.read_bytes()
            if len(data) > MAX_ATTACHMENT_BYTES:
                raise ValueError(f"Attachment changed or exceeds {MAX_ATTACHMENT_BYTES} bytes: {path.name}")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ValueError(f"Attachments exceed {MAX_TOTAL_BYTES} bytes in total")
            archive.writestr(f"attachments/{path.name}", data)
            manifest["attachments"].append({"file": path.name, "bytes": len(data), "sha256": sha256(data).hexdigest()})
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return len(paths)
