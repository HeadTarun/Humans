import sys
sys.path.insert(0, ".")
from app.services.ingestion.file_signatures import (
    detect_file_type, is_executable_type, detect_extension_mismatch, declared_extension
)
 
assert detect_file_type(b"%PDF-1.4 rest of file") == "pdf"
assert detect_file_type(b"MZ\x90\x00 rest") == "windows_executable"
assert detect_file_type(b"random garbage") == "unknown"
assert detect_file_type(b"") == "unknown"
 
assert is_executable_type("windows_executable") is True
assert is_executable_type("pdf") is False
 
assert declared_extension("invoice.pdf.exe") == "exe"
assert declared_extension("noextension") is None
 
# The canonical disguised-attachment case from the spec:
mz_bytes = b"MZ\x90\x00\x03\x00\x00\x00"
assert detect_extension_mismatch("invoice.pdf", detect_file_type(mz_bytes)) is True
 
# A real PDF named .pdf must NOT be flagged:
pdf_bytes = b"%PDF-1.7\n..."
assert detect_extension_mismatch("invoice.pdf", detect_file_type(pdf_bytes)) is False
 
# Unmodeled extension (.txt) must not be flagged even if bytes don't match anything:
assert detect_extension_mismatch("notes.txt", detect_file_type(b"plain text")) is False
 
print("ALL PASS")
