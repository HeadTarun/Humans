"""
services/ingestion/file_signatures.py
 
Minimal magic-byte (file signature) detection for attachment forensics.
Deliberately dependency-free: this repo's own rule (spec/task doc §23) is
not to add a library merely because it's popular, and a signature table
this small doesn't need `python-magic` or libmagic bindings, which would
add a system-library dependency for ~15 signatures.
 
This module answers ONE question: "what does the byte content actually
look like", independent of what the filename/declared MIME type claims.
It never executes, opens, or otherwise interprets the file beyond reading
its leading bytes — per the parser's security rules (spec §21), untrusted
attachments must never be executed.
"""
 
from __future__ import annotations
 
from typing import Optional
 
# (signature bytes, offset, label). Checked in order; first match wins.
# Labels are intentionally coarse-grained categories, not exact formats —
# this is for forensic sanity-checking, not a general file-type library.
_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"%PDF-", 0, "pdf"),
    (b"MZ", 0, "windows_executable"),
    (b"\x7fELF", 0, "linux_executable"),
    (b"\xca\xfe\xba\xbe", 0, "macos_executable"),  # also matches Java class files
    (b"\xfe\xed\xfa", 0, "macos_executable"),
    (b"PK\x03\x04", 0, "zip_or_office_openxml"),   # docx/xlsx/pptx/zip/jar/apk
    (b"PK\x05\x06", 0, "zip_or_office_openxml"),   # empty zip archive
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole2_legacy_office"),  # old .doc/.xls/.ppt
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF87a", 0, "gif"),
    (b"GIF89a", 0, "gif"),
    (b"{\\rtf", 0, "rtf"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7zip"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"#!", 0, "script_shebang"),
]
 
# Category groupings used for declared-vs-detected mismatch checks.
_EXECUTABLE_CATEGORIES = {"windows_executable", "linux_executable", "macos_executable", "script_shebang"}
_ARCHIVE_CATEGORIES = {"zip_or_office_openxml", "gzip", "7zip", "rar"}
 
# Which detected categories are "expected" for a given file extension.
# An extension not in this map is simply not checked for mismatch (we do
# not want to invent false positives for formats we haven't modeled).
_EXTENSION_EXPECTATIONS: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "doc": {"ole2_legacy_office", "zip_or_office_openxml"},
    "docx": {"zip_or_office_openxml"},
    "xls": {"ole2_legacy_office"},
    "xlsx": {"zip_or_office_openxml"},
    "ppt": {"ole2_legacy_office"},
    "pptx": {"zip_or_office_openxml"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "zip": _ARCHIVE_CATEGORIES,
    "rtf": {"rtf"},
}
 
 
def detect_file_type(data: bytes) -> str:
    """Returns a coarse type label based on leading bytes, or "unknown" if
    nothing matches. Never raises: a truncated/empty payload just yields
    "unknown" rather than an IndexError."""
    if not data:
        return "unknown"
    for signature, offset, label in _SIGNATURES:
        try:
            if data[offset:offset + len(signature)] == signature:
                return label
        except Exception:
            continue
    return "unknown"
 
 
def is_executable_type(detected_type: str) -> bool:
    return detected_type in _EXECUTABLE_CATEGORIES
 
 
def declared_extension(filename: str) -> Optional[str]:
    """Last dotted suffix, lowercased, no dot. 'invoice.pdf.exe' -> 'exe'
    (correctly the LAST extension — that's the one the OS/mail client
    actually uses to decide how to open the file, which is exactly the
    disguise this function needs to catch)."""
    if not filename or "." not in filename:
        return None
    return filename.rsplit(".", 1)[-1].lower() or None
 
 
def detect_extension_mismatch(filename: str, detected_type: str) -> bool:
    """True when the file's last extension implies a category that the
    actual byte signature contradicts. Returns False (no mismatch) when
    the extension isn't one we have modeled expectations for, or when
    detected_type is "unknown" — absence of a signature match is not
    evidence of anything on its own."""
    ext = declared_extension(filename)
    if not ext or detected_type == "unknown":
        return False
    expected = _EXTENSION_EXPECTATIONS.get(ext)
    if not expected:
        return False
    return detected_type not in expected
