"""
Orchestration layer for session and token lifecycles.
"""

from datetime import timedelta

from swapper import load_model
from django.db import transaction
from django.utils import timezone

from drf_sessions.types import IssuedSession
from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.models import get_session_model
from drf_sessions.compat import Optional, TYPE_CHECKING
from drf_sessions.settings import drf_sessions_settings
from drf_sessions.utils.tokens import (
    hash_token_string,
    generate_access_token,
    generate_refresh_token,
)

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser


SessionModel = get_session_model()


class SessionService:
    """
    Unified interface for creating and rotating authentication credentials.
    """

    @staticmethod
    def _create_session(
        user,
        transport: str = AUTH_TRANSPORT.ANY,
        context: Optional[dict] = None,
        access_ttl: Optional[timedelta] = None,
        refresh_ttl: Optional[timedelta] = None,
        **kwargs,
    ) -> IssuedSession:
        """Standard entry point for session creation."""
        return SessionModel.objects.create_session(
            user=user,
            transport=transport,
            context=context,
            access_ttl=access_ttl,
            refresh_ttl=refresh_ttl,
            **kwargs,
        )

    @classmethod
    def create_cookie_session(
        cls,
        user,
        context: Optional[dict] = None,
        access_ttl: Optional[timedelta] = None,
        refresh_ttl: Optional[timedelta] = None,
        **kwargs,
    ) -> IssuedSession:
        """Creates a session restricted to HTTP-only cookies."""
        return cls._create_session(
            user,
            transport=AUTH_TRANSPORT.COOKIE,
            context=context,
            access_ttl=access_ttl,
            refresh_ttl=refresh_ttl,
            **kwargs,
        )

    @classmethod
    def create_header_session(
        cls,
        user,
        context: Optional[dict] = None,
        access_ttl: Optional[timedelta] = None,
        refresh_ttl: Optional[timedelta] = None,
        **kwargs,
    ) -> IssuedSession:
        """Creates a session restricted to Authorization headers."""
        return cls._create_session(
            user,
            transport=AUTH_TRANSPORT.HEADER,
            context=context,
            access_ttl=access_ttl,
            refresh_ttl=refresh_ttl,
            **kwargs,
        )

    @classmethod
    def create_session(
        cls,
        user,
        context: Optional[dict] = None,
        access_ttl: Optional[timedelta] = None,
        refresh_ttl: Optional[timedelta] = None,
        **kwargs,
    ) -> IssuedSession:
        """Creates a flexible session valid for any transport method."""
        return cls._create_session(
            user,
            transport=AUTH_TRANSPORT.ANY,
            context=context,
            access_ttl=access_ttl,
            refresh_ttl=refresh_ttl,
            **kwargs,
        )

    @staticmethod
    @transaction.atomic
    def refresh_token(raw_refresh_token: str) -> Optional[IssuedSession]:
        """
        Handles rotation, reuse detection, and sliding window extensions.
        """
        RefreshTokenModel = load_model("drf_sessions", "RefreshToken")

        token_hash = hash_token_string(raw_refresh_token)
        token_instance = (
            RefreshTokenModel.objects.select_related("session")
            .filter(token_hash=token_hash)
            .first()
        )

        if not token_instance:
            return None

        session = token_instance.session
        now = timezone.now()

        # 1. Reuse Detection
        if token_instance.consumed_at is not None:
            if drf_sessions_settings.REVOKE_SESSION_ON_REUSE:
                session.revoke()
            return None

        # 2. Expiry/Revocation Check
        if token_instance.is_expired or session.revoked_at:
            return None

        # 3. Update Activity
        session.last_activity_at = now
        session.save(update_fields=["last_activity_at"])

        # 4. Token Rotation
        if drf_sessions_settings.ROTATE_REFRESH_TOKENS:
            token_instance.consumed_at = now
            token_instance.save(update_fields=["consumed_at"])

            new_raw_refresh, new_hash = generate_refresh_token()
            refresh_ttl = drf_sessions_settings.REFRESH_TOKEN_TTL

            # Handle potential None in absolute_expiry
            new_expiry = now + refresh_ttl
            if session.absolute_expiry:
                new_expiry = min(new_expiry, session.absolute_expiry)

            RefreshTokenModel.objects.create(
                session=session,
                token_hash=new_hash,
                expires_at=new_expiry,
            )
            refresh_token_to_return = new_raw_refresh
        else:
            refresh_token_to_return = raw_refresh_token

        # 6. Issue Access JWT
        new_raw_access = generate_access_token(session)

        return IssuedSession(new_raw_access, refresh_token_to_return, session)

    @staticmethod
    @transaction.atomic
    def revoke_user_sessions(user: "AbstractBaseUser") -> None:
        """Revokes all of users tokens on the platform"""
        SessionModel.objects.filter(user=user).revoke()
