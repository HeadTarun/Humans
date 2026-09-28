"""
app/core/security.py

Password hashing and verification utilities.

Uses bcrypt directly (preferred) or passlib[bcrypt] as fallback.
Both bcrypt >= 4.x and passlib 1.7.4 are supported.

passlib 1.7.4 + bcrypt >= 4.x have a known incompatibility
(bcrypt.__about__ attribute removed). This module handles both
transparently using bcrypt's native API when passlib cannot load.

DO NOT fall back to SHA-256 — only bcrypt is acceptable.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Strategy 1: Use bcrypt directly (works with all bcrypt versions)
# ---------------------------------------------------------------------------
try:
    import bcrypt as _bcrypt_module

    def hash_password(password: str) -> str:
        """Hash a plaintext password using bcrypt."""
        pwd_bytes = password.encode("utf-8")
        salt = _bcrypt_module.gensalt(rounds=12)
        return _bcrypt_module.hashpw(pwd_bytes, salt).decode("utf-8")

    def verify_password(plain: str, hashed: str) -> bool:
        """Verify a plaintext password against a stored bcrypt hash."""
        try:
            return _bcrypt_module.checkpw(
                plain.encode("utf-8"),
                hashed.encode("utf-8"),
            )
        except Exception:
            return False

    def passlib_available() -> bool:
        return True  # bcrypt itself is available

    logger.debug("security: using bcrypt native backend")

except ImportError:
    # ---------------------------------------------------------------------------
    # Strategy 2: Try passlib[bcrypt] (works when bcrypt <= 3.x is installed)
    # ---------------------------------------------------------------------------
    try:
        from passlib.context import CryptContext
        _ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

        def hash_password(password: str) -> str:  # type: ignore[misc]
            return _ctx.hash(password)

        def verify_password(plain: str, hashed: str) -> bool:  # type: ignore[misc]
            try:
                return _ctx.verify(plain, hashed)
            except Exception:
                return False

        def passlib_available() -> bool:  # type: ignore[misc]
            return True

        logger.debug("security: using passlib bcrypt backend")

    except Exception:
        # ---------------------------------------------------------------------------
        # Neither bcrypt nor passlib available — hard fail at runtime
        # ---------------------------------------------------------------------------
        logging.getLogger(__name__).critical(
            "SECURITY_FAILURE: Neither bcrypt nor passlib[bcrypt] is installed. "
            "Install: pip install bcrypt>=4"
        )

        def hash_password(password: str) -> str:  # type: ignore[misc]
            raise RuntimeError(
                "bcrypt is required for password hashing. "
                "Install: pip install bcrypt>=4"
            )

        def verify_password(plain: str, hashed: str) -> bool:  # type: ignore[misc]
            raise RuntimeError(
                "bcrypt is required for password verification. "
                "Install: pip install bcrypt>=4"
            )

        def passlib_available() -> bool:  # type: ignore[misc]
            return False
