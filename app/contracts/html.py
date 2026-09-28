"""contracts/html.py — structural HTML findings, not verdicts."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import BaseContract


class HTMLFindingType(str, Enum):
    HIDDEN_TEXT = "HIDDEN_TEXT"
    FORM_ACTION = "FORM_ACTION"
    IFRAME = "IFRAME"
    OBFUSCATED_JS = "OBFUSCATED_JS"
    BRAND_LOGO_MISMATCH = "BRAND_LOGO_MISMATCH"
    EXTERNAL_STYLE_INJECTION = "EXTERNAL_STYLE_INJECTION"


class HTMLFinding(BaseContract):
    finding_id: str
    finding_type: HTMLFindingType
    element_reference: str = Field(..., description="e.g. an XPath or element index into the parsed DOM")
    description: str
    severity: str = Field(..., description="LOW | MEDIUM | HIGH")


class HTMLAnalysisResult(BaseContract):
    has_forms: bool = False
    form_actions: list[str] = Field(default_factory=list)
    external_resources: list[str] = Field(default_factory=list)
    findings: list[HTMLFinding] = Field(default_factory=list)
