"""
app/services/analysis/attachment_analyzer.py

Static attachment forensics analyzer.

PHILOSOPHY:
    - NEVER execute an attachment, not even for analysis.
    - NEVER shell out to external processes without strict controls.
    - All analysis is pure Python static inspection.
    - Hard limits on size, depth, and file count prevent decompression bombs.
    - Every finding is returned as a structured result — never as a boolean.

SUPPORTED ANALYSIS:
    - File type detection (magic bytes vs claimed extension)
    - Archive inspection (ZIP only in v1; with depth/count/size limits)
    - Office document macro detection (OLE/VBA signature heuristics)
    - Embedded URL extraction from PDFs (regex-based, no execution)
    - Executable detection
    - Extension mismatch flagging
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from typing import Optional

from app.services.ingestion import file_signatures

logger = logging.getLogger(__name__)

MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024   # 50 MB
MAX_ARCHIVE_MEMBERS = 100
MAX_ARCHIVE_DEPTH = 3
MAX_EXTRACTED_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB total extracted
MAX_EMBEDDED_URLS = 200
ANALYSIS_TIMEOUT_SECONDS = 30


@dataclass
class AttachmentAnalysisResult:
    filename: str
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    detected_mime: Optional[str] = None
    is_executable: bool = False
    is_archive: bool = False
    extension_mismatch: bool = False
    has_macros: bool = False
    embedded_urls: list[str] = field(default_factory=list)
    archive_contents: list[dict] = field(default_factory=list)
    archive_too_large: bool = False
    analysis_warnings: list[str] = field(default_factory=list)
    analysis_error: Optional[str] = None


class AttachmentAnalyzer:
    URL_PATTERN = re.compile(r'https?://[^\s<>"\x00-\x1f]+')
    EXEC_EXTENSIONS = {"exe", "dll", "scr", "vbs", "ps1", "bat", "cmd", "sh", "elf", "msi"}

    def analyze(self, payload: bytes, filename: str, mime_type: str) -> AttachmentAnalysisResult:
        size = len(payload)
        
        sha256 = hashlib.sha256(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()

        result = AttachmentAnalysisResult(
            filename=filename,
            size_bytes=size,
            sha256=sha256,
            sha1=sha1,
            md5=md5
        )

        if size > MAX_ATTACHMENT_BYTES:
            result.analysis_error = "payload_too_large"
            return result

        try:
            detected_type = file_signatures.detect_file_type(payload)
            result.detected_mime = detected_type

            result.is_executable = file_signatures.is_executable_type(detected_type)
            if not result.is_executable:
                if payload.startswith(b"MZ") or payload.startswith(b"\x7fELF") or payload.startswith(b"#!/"):
                    result.is_executable = True

            result.extension_mismatch = file_signatures.detect_extension_mismatch(filename, detected_type)
            result.is_archive = detected_type in file_signatures._ARCHIVE_CATEGORIES

            self._analyze_macros(payload, filename, detected_type, result)

            if detected_type == "pdf":
                self._extract_urls(payload, result)

            if result.is_archive and detected_type == "zip_or_office_openxml":
                self._inspect_zip(payload, result)

        except Exception as e:
            logger.warning(f"Analysis failed for {filename}: {str(e)}", exc_info=True)
            if "partial_analysis" not in result.analysis_warnings:
                result.analysis_warnings.append("partial_analysis")

        return result

    def _analyze_macros(self, payload: bytes, filename: str, detected_type: str, result: AttachmentAnalysisResult) -> None:
        try:
            ext = file_signatures.declared_extension(filename)
            if ext and ext in ("docm", "xlsm", "pptm"):
                result.has_macros = True
                return

            first_10k = payload[:10240]
            if first_10k.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                if b"VBA" in first_10k:
                    result.has_macros = True
                    return

            auto_strings = [b"AutoOpen", b"Auto_Open", b"AutoExec", b"Document_Open"]
            for s in auto_strings:
                if s in first_10k:
                    result.has_macros = True
                    return
        except Exception as e:
            logger.warning(f"Macro analysis failed: {str(e)}")
            if "partial_analysis" not in result.analysis_warnings:
                result.analysis_warnings.append("partial_analysis")

    def _extract_urls(self, payload: bytes, result: AttachmentAnalysisResult) -> None:
        try:
            text = payload.decode(errors='replace')
            urls = []
            for match in self.URL_PATTERN.finditer(text):
                urls.append(match.group(0))
                if len(urls) >= MAX_EMBEDDED_URLS:
                    break
            result.embedded_urls = urls
        except Exception as e:
            logger.warning(f"URL extraction failed: {str(e)}")
            if "partial_analysis" not in result.analysis_warnings:
                result.analysis_warnings.append("partial_analysis")

    def _inspect_zip(self, payload: bytes, result: AttachmentAnalysisResult) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(payload), allowZip64=True) as zf:
                infolist = zf.infolist()
                
                if len(infolist) > MAX_ARCHIVE_MEMBERS:
                    result.archive_too_large = True
                    return

                total_extracted_size = 0
                for info in infolist:
                    if info.is_dir():
                        continue
                    
                    total_extracted_size += info.file_size
                    if total_extracted_size > MAX_EXTRACTED_SIZE_BYTES:
                        result.archive_too_large = True
                        break
                    
                    ext = file_signatures.declared_extension(info.filename)
                    is_exec = ext in self.EXEC_EXTENSIONS if ext else False
                    
                    result.archive_contents.append({
                        "name": info.filename,
                        "size": info.file_size,
                        "is_executable": is_exec,
                        "extension_mismatch": False
                    })

        except zipfile.BadZipFile:
            if "invalid_zip_structure" not in result.analysis_warnings:
                result.analysis_warnings.append("invalid_zip_structure")
        except Exception as e:
            logger.warning(f"Zip inspection failed: {str(e)}")
            if "partial_analysis" not in result.analysis_warnings:
                result.analysis_warnings.append("partial_analysis")
