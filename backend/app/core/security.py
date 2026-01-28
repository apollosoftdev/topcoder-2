"""Security utilities for API authentication."""

import hmac
import hashlib
import logging
from typing import Optional

from fastapi import HTTPException, Header, status

from .config import get_settings

logger = logging.getLogger(__name__)

# Track if we've logged the API key warning to avoid spam
_api_key_warning_logged = False


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """Verify API key if configured."""
    global _api_key_warning_logged
    settings = get_settings()

    if not settings.api_key:
        # No API key configured, allow all requests but warn in production
        if settings.is_production and not _api_key_warning_logged:  # nosemgrep: is-function-without-parentheses
            logger.warning(
                "API_KEY is not configured - all requests are allowed without authentication. "
                "This is a security risk in production. Set the API_KEY environment variable."
            )
            _api_key_warning_logged = True
        return True

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    if not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return True


def verify_github_webhook_signature(
    payload: bytes, signature: str, secret: str
) -> bool:
    """Verify GitHub webhook signature."""
    if not signature or not signature.startswith("sha256="):
        return False

    expected_signature = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)
