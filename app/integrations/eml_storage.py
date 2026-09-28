"""
integrations/eml_storage.py

Supabase Storage client for raw .eml preservation.

Bucket layout:
    email-artifacts/cases/{case_id}/original.eml

Security:
    - SHA-256 computed locally before upload, verified after download.
    - Private bucket — no public URL is ever generated.
    - Requires SUPABASE_URL + SUPABASE_SERVICE_KEY (service-role key, not anon).

Usage:
    storage = EmlStorage()
    sha256 = await storage.upload_eml(case_id, raw_bytes)
    data    = await storage.download_eml(case_id)
    ok      = await storage.verify_eml(case_id, sha256)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_BUCKET = settings.SUPABASE_BUCKET_NAME  # default: "email-artifacts"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _storage_path(case_id: str) -> str:
    return f"cases/{case_id}/original.eml"


class EmlStorage:
    """
    Thin async client wrapping Supabase Storage REST API.

    All methods return None / False on configuration absence (SUPABASE_URL or
    SUPABASE_SERVICE_KEY not set) so callers can treat storage as optional.
    """

    def __init__(self) -> None:
        self._url: Optional[str] = settings.SUPABASE_URL
        self._key: Optional[str] = settings.SUPABASE_SERVICE_KEY
        self._enabled = bool(self._url and self._key)
        if not self._enabled:
            logger.warning(
                "EmlStorage disabled: SUPABASE_URL or SUPABASE_SERVICE_KEY not configured"
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _headers(self) -> dict:
        return {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
        }

    def _object_url(self, path: str) -> str:
        """REST endpoint for a storage object."""
        return f"{self._url}/storage/v1/object/{_BUCKET}/{path}"

    async def upload_eml(self, case_id: str, raw_bytes: bytes) -> Optional[str]:
        """
        Upload raw .eml bytes to Supabase Storage.

        Returns:
            SHA-256 hex digest of the uploaded content, or None on failure.
        """
        if not self._enabled:
            return None

        sha256 = _sha256(raw_bytes)
        path = _storage_path(case_id)
        url = self._object_url(path)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Use PUT to allow idempotent re-uploads (upsert)
                resp = await client.put(
                    url,
                    content=raw_bytes,
                    headers={
                        **self._headers(),
                        "Content-Type": "message/rfc822",
                        "x-upsert": "true",
                    },
                )
            if resp.status_code not in (200, 201):
                logger.error(
                    "EML upload failed case=%s status=%s body=%s",
                    case_id, resp.status_code, resp.text[:200],
                )
                return None

            logger.info("EML uploaded case=%s sha256=%s", case_id, sha256)
            return sha256

        except Exception as exc:  # noqa: BLE001
            logger.error("EML upload exception case=%s: %s", case_id, exc)
            return None

    async def download_eml(self, case_id: str) -> Optional[bytes]:
        """
        Download raw .eml bytes from Supabase Storage.

        Returns:
            Raw bytes, or None on failure / not found.
        """
        if not self._enabled:
            return None

        path = _storage_path(case_id)
        url = self._object_url(path)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 404:
                logger.warning("EML not found in storage case=%s", case_id)
                return None
            if resp.status_code != 200:
                logger.error(
                    "EML download failed case=%s status=%s", case_id, resp.status_code
                )
                return None

            return resp.content

        except Exception as exc:  # noqa: BLE001
            logger.error("EML download exception case=%s: %s", case_id, exc)
            return None

    async def verify_eml(self, case_id: str, expected_sha256: str) -> bool:
        """
        Download and verify the stored .eml matches the expected SHA-256.

        Returns True only when download succeeds AND hash matches.
        """
        data = await self.download_eml(case_id)
        if data is None:
            return False
        actual = _sha256(data)
        match = actual == expected_sha256
        if not match:
            logger.error(
                "EML integrity mismatch case=%s expected=%s actual=%s",
                case_id, expected_sha256, actual,
            )
        return match

    def storage_path(self, case_id: str) -> str:
        """Return the canonical storage path for a case."""
        return f"{_BUCKET}/{_storage_path(case_id)}"


# Module-level singleton — import and reuse across requests
eml_storage = EmlStorage()
