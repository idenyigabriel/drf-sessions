"""
Cryptographic utilities for token generation and verification.

This module provides secure random token generation using the secrets
library and one-way hashing for storage. It ensures that raw tokens
only exist in memory momentarily before being hashed.
"""

import hashlib
import secrets
from datetime import timedelta

import jwt
from django.utils import timezone

from drf_sessions.types import TYPE_CHECKING
from drf_sessions.settings import authentify_settings

if TYPE_CHECKING:
    from drf_sessions.base.models import AbstractSession


def _hash_token(token: str) -> str:
    """Hash a token using the configured secure hash algorithm."""
    # Use the name defined in our settings DEFAULTS
    hasher = hashlib.new(authentify_settings.REFRESH_TOKEN_HASH_ALGORITHM)
    hasher.update(token.strip().encode("utf-8"))
    return hasher.hexdigest()


def generate_refresh_token() -> tuple[str, str]:
    """
    Creates a new refresh token with higher entropy than access tokens.

    Returns:
        A tuple of (raw_token, hashed_token).
    """
    raw_token = secrets.token_urlsafe(48)
    return raw_token, _hash_token(raw_token)


def hash_token_string(raw_token: str) -> str:
    """
    Public wrapper to hash an existing raw token for lookup purposes.
    """
    return _hash_token(raw_token)


def _get_verify_key():
    """
    Determines the correct key for verification based on the algorithm.
    Following the principle: HMAC uses Signing Key, RSA/EC uses Verifying Key.
    """
    algo = authentify_settings.JWT_ALGORITHM

    # If the algorithm starts with 'HS', it's HMAC (Symmetric)
    if algo.startswith("HS"):
        return authentify_settings.JWT_SIGNING_KEY

    # For RS/ES/PS (Asymmetric), the Verifying Key (Public) is required
    return authentify_settings.JWT_VERIFYING_KEY


def generate_access_token(session: "AbstractSession", access_ttl: timedelta = None):
    """
    Generates a signed JWT access token.
    """
    now = timezone.now()
    user_id = str(getattr(session.user, authentify_settings.USER_ID_FIELD))

    # Corrected logic to prevent TypeError if access_ttl is None
    ttl = access_ttl or authentify_settings.ACCESS_TOKEN_TTL
    expires_at = now + ttl

    payload = {
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        authentify_settings.USER_ID_CLAIM: user_id,
        authentify_settings.JTI_CLAIM: session.session_id.hex,
        authentify_settings.SESSION_ID_CLAIM: str(session.session_id),
    }

    if authentify_settings.JWT_ISSUER:
        payload["iss"] = authentify_settings.JWT_ISSUER
    if authentify_settings.JWT_AUDIENCE:
        payload["aud"] = authentify_settings.JWT_AUDIENCE

    if authentify_settings.JWT_PAYLOAD_EXTENDER:
        payload.update(authentify_settings.JWT_PAYLOAD_EXTENDER(session))

    headers = authentify_settings.JWT_HEADERS.copy()
    if authentify_settings.JWT_KEY_ID:
        headers["kid"] = authentify_settings.JWT_KEY_ID

    return jwt.encode(
        payload,
        authentify_settings.JWT_SIGNING_KEY,
        algorithm=authentify_settings.JWT_ALGORITHM,
        headers=headers,
        json_encoder=authentify_settings.JWT_JSON_ENCODER,
    )


def verify_access_token(token: str) -> dict:
    """
    Decodes the token using the algorithm-appropriate verification key.
    """
    return jwt.decode(
        token,
        _get_verify_key(),
        issuer=authentify_settings.JWT_ISSUER,
        audience=authentify_settings.JWT_AUDIENCE,
        algorithms=[authentify_settings.JWT_ALGORITHM],
        leeway=authentify_settings.LEEWAY.total_seconds(),
    )
