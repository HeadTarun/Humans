"""
services/tools/handlers/nlp_intent_ml.py

NLP Intent ML Handler (Level 1).

BEC/URGENCY PIPELINE FIX (§5 P1):
    Root cause of the live-pipeline gap: the original handler checked
    Path(artifact_ref).resolve().startswith(Path.cwd()), which always
    failed in server context because artifacts are stored in /tmp/emails
    (or whatever EMAIL_STORAGE_DIR is set to), NOT under cwd.

    Fix: validate against the actual allowed storage directories:
    - EMAIL_STORAGE_DIR env var (default /tmp/emails)
    - tempfile.gettempdir() (covers /tmp)
    - Path.cwd() (covers test environments)

    Additionally: fall back to re-reading the package's raw_artifact_reference
    directly so NLP always runs when body text is available.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from app.contracts.evidence import EvidenceItem
from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.evidence.models import EmailEvidencePackage
from app.services.evidence.htmlparser import HTMLEmailParser
from app.services.ml.base import ModelFailureError
from app.services.ml.nlp_adapter import NLPModelAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed storage directories for artifact security check.
# Email artifacts are stored in EMAIL_STORAGE_DIR (default /tmp/emails).
# ---------------------------------------------------------------------------

def _get_allowed_dirs() -> list[Path]:
    """Return the set of allowed directories for artifact file access.

    The EmailParser stores artifacts in its storage_dir (default /tmp/emails,
    which on Windows resolves to \\tmp\\emails relative to the current drive).
    We must include the actual parser storage_dir, not just the env var
    equivalent, since they differ on Windows.
    """
    dirs: list[Path] = [
        Path(tempfile.gettempdir()).resolve(),
        Path.cwd(),
    ]

    # Add the env var override if set
    env_storage = os.environ.get("EMAIL_STORAGE_DIR")
    if env_storage:
        dirs.append(Path(env_storage).resolve())

    # Add the actual EmailParser storage_dir (cross-platform)
    # On Windows, /tmp/emails resolves to \\tmp\\emails (different from tempdir)
    try:
        from app.services.ingestion.parser import EmailParser
        parser_storage = Path(EmailParser().storage_dir).resolve()
        dirs.append(parser_storage)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "NLP_INTENT_ML import/path resolution failed: %s — model unavailable",
            type(exc).__name__,
        )

    # Also add common fallbacks for cross-platform compat
    dirs.append(Path("/tmp/emails").resolve())
    dirs.append(Path("\\tmp\\emails").resolve())

    return dirs


def _is_allowed_path(path: Path) -> bool:
    """Security check: is the resolved path under an allowed directory?"""
    path_str = str(path)
    return any(path_str.startswith(str(d)) for d in _get_allowed_dirs())


def _read_parsed_text_from_artifact(artifact_path: str) -> str:
    """
    Re-parse an .eml artifact file and extract body text.
    Returns empty string on any failure (never raises).

    Security boundary: _is_allowed_path() validates the resolved path is
    under a permitted storage directory. The open() call then handles
    FileNotFoundError / PermissionError naturally via the except block.
    """
    try:
        from app.services.ingestion.parser import EmailParser
        target = Path(artifact_path).resolve()
        if not _is_allowed_path(target):
            logger.warning(
                "nlp_intent_ml: path security check blocked %r "
                "(not under allowed storage dirs: %s)",
                artifact_path,
                [str(d) for d in _get_allowed_dirs()],
            )
            return ""
        # Attempt to open directly — FileNotFoundError / PermissionError
        # is caught by the outer except block and returns "".
        with open(target, "rb") as f_bin:
            parsed = EmailParser().parse(f_bin.read())
            # Prefer the visible HTML representation for multipart/HTML
            # email. Raw markup, CSS, tracking pixels and hidden elements do
            # not belong in NLP inference.
            if parsed.html:
                return HTMLEmailParser().parse(parsed.html).language.cleaned_text
            return parsed.plain_text or ""
    except Exception as exc:
        logger.error("nlp_intent_ml: failed to read artifact %r: %s", artifact_path, exc)
        return ""


async def handle(
    request: ToolExecutionRequest,
    state: InvestigationState,
    package: Optional[EmailEvidencePackage] = None,
) -> dict[str, Any] | list[EvidenceItem]:
    """
    Execute the NLP intent ML tool.

    Input resolution order (first non-empty text wins):
        1. artifact_reference from request.input (explicit override)
        2. package.raw_artifact_reference (normal server path)

    This ensures BEC signals fire in both test and production contexts.
    """
    if not package:
        raise ValueError("nlp_intent_ml requires the EmailEvidencePackage")

    parsed_text = ""
    package_body = getattr(package, "body", None)
    body_visible_text = getattr(package_body, "visible_text", None) if package_body else None

    # Primary path: use evidence already computed by the parser/normalizer. This
    # avoids re-reading and re-parsing the raw artifact for normal emails.
    if body_visible_text:
        parsed_text = str(body_visible_text).strip()
        logger.info(
            "nlp_intent_ml: using package.body.visible_text as primary NLP input for case %s",
            getattr(state, "case_id", "unknown"),
        )
    else:
        artifact_ref = request.input.get("artifact_reference")
        if artifact_ref:
            logger.warning(
                "nlp_intent_ml: package.body.visible_text unavailable; falling back to artifact parsing for artifact_ref=%r",
                artifact_ref,
            )
            parsed_text = _read_parsed_text_from_artifact(artifact_ref)

        if not parsed_text:
            pkg_artifact = getattr(package, "raw_artifact_reference", None)
            if pkg_artifact:
                logger.warning(
                    "nlp_intent_ml: primary body text unavailable; fallback artifact parse for pkg_ref=%r",
                    pkg_artifact,
                )
                parsed_text = _read_parsed_text_from_artifact(pkg_artifact)

    if not parsed_text:
        logger.warning(
            "nlp_intent_ml: no parsed text available for case %s "
            "(artifact_ref=%r, pkg_ref=%r) — tool will fail as no text to analyze",
            getattr(state, "case_id", "unknown"),
            request.input.get("artifact_reference"),
            getattr(package, "raw_artifact_reference", None),
        )
        return {"error": "No parsed text available for NLP ML", "status": "failed"}

    adapter = NLPModelAdapter()

    start_time = time.perf_counter()
    evidence_items, mode, unavailable_reason = adapter.analyze_with_fallback(package, parsed_text)

    if unavailable_reason:
        return {"error": unavailable_reason, "status": "failed"}

    latency_ms = (time.perf_counter() - start_time) * 1000.0
    logger.debug(
        "nlp_intent_ml: mode=%s produced %d evidence items in %.0fms for case %s",
        mode, len(evidence_items), latency_ms, getattr(state, "case_id", "unknown"),
    )

    # Return as list of dicts for ToolExecutionResult normalisation
    return [item.model_dump(mode="json") for item in evidence_items]
