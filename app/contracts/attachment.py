"""contracts/attachment.py — attachment structural metadata."""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from .common import BaseContract


class AttachmentRef(BaseContract):
    attachment_id: str
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    is_archive: bool = False
    is_executable_signature: bool = False
    detected_type: Optional[str] = Field(
        default=None, description="Magic-byte category from file_signatures.detect_file_type; NOT the declared/claimed type"
    )
    extension_mismatch: bool = Field(
        default=False, description="True when the filename's extension implies a category the actual byte signature contradicts (e.g. invoice.pdf.exe)"
    )
    extracted_text_reference: Optional[str] = Field(
        default=None, description="Reference to extracted text/OCR content, not the raw attachment"
    )
