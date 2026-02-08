"""
Database abstraction layer for authentication sessions.
"""

from datetime import timedelta
from typing import Optional

from swapper import load_model
from django.utils import timezone
from django.db import models, transaction
from django.contrib.auth.models import update_last_login

from drf_sessions.settings import authentify_settings
from drf_sessions.types import IssuedSession
from drf_sessions.utils.tokens import generate_access_token, generate_refresh_token


class SessionQuerySet(models.QuerySet):
    """Custom QuerySet for session management."""

    def active(self):
        """Returns sessions that are not revoked and within their absolute lifetime."""
        return self.filter(revoked_at__isnull=True, absolute_expiry__gt=timezone.now())

    def revoke(self) -> int:
        """Mass revokes sessions in the current queryset."""
        return self.update(revoked_at=timezone.now())


class SessionManager(models.Manager):
    """Manager for the Session model."""

    def get_queryset(self) -> SessionQuerySet:
        return SessionQuerySet(self.model, using=self._db)

    def active(self) -> SessionQuerySet:
        return self.get_queryset().active()

    def revoke(self) -> int:
        return self.get_queryset().revoke()

    @transaction.atomic
    def create_session(
        self,
        user,
        transport: str,
        context: Optional[dict] = None,
        access_ttl: Optional[timedelta] = None,
        refresh_ttl: Optional[timedelta] = None,
        **kwargs,
    ) -> IssuedSession:
        now = timezone.now()

        # 1. Update User's last_login if enabled in settings
        if authentify_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)

        # Enforce limits before creating a new one
        self._handle_session_limits(user)

        # Resolve Lifetimes
        refresh_base = refresh_ttl or authentify_settings.REFRESH_TOKEN_TTL
        max_sliding = authentify_settings.SLIDING_SESSION_MAX_LIFETIME

        # Absolute expiry is the hard deadline for the session
        # Use sliding limit if enabled, otherwise fallback to refresh TTL
        expiry_delta = max_sliding if max_sliding else refresh_base
        absolute_expiry = now + expiry_delta

        session = self.create(
            user=user,
            transport=transport,
            context=context or {},
            last_activity_at=now,
            absolute_expiry=absolute_expiry,
            **kwargs,
        )

        raw_refresh = None
        if refresh_base:
            raw_refresh, token_hash = generate_refresh_token()
            # Refresh token cannot outlive the session's wall
            refresh_expires_at = min(now + refresh_base, absolute_expiry)

            # Accessing RefreshToken via swapper
            RefreshTokenModel = load_model("drf_sessions", "RefreshToken")
            RefreshTokenModel.objects.create(
                session=session, token_hash=token_hash, expires_at=refresh_expires_at
            )

        raw_access = generate_access_token(session, access_ttl=access_ttl)
        return IssuedSession(raw_access, raw_refresh, session)

    def _handle_session_limits(self, user) -> None:
        """
        Handles ENFORCE_SINGLE_SESSION and MAX_SESSIONS_PER_USER logic.
        """
        active_sessions = self.active().filter(user=user).order_by("created_at")

        # 1. Single session enforcement
        if authentify_settings.ENFORCE_SINGLE_SESSION:
            self._terminate_sessions(active_sessions)
            return

        # 2. Max sessions enforcement (FIFO)
        max_limit = authentify_settings.MAX_SESSIONS_PER_USER
        if max_limit is not None:
            count = active_sessions.count()
            if count >= max_limit:
                # Identify oldest sessions to remove to make room for the new one
                num_to_remove = (count - max_limit) + 1
                oldest_ids = list(
                    active_sessions.values_list("id", flat=True)[:num_to_remove]
                )
                self._terminate_sessions(self.filter(id__in=oldest_ids))

    def _terminate_sessions(self, queryset) -> None:
        """Determines whether to soft-revoke or hard-delete based on settings."""
        if authentify_settings.RETAIN_EXPIRED_SESSIONS:
            queryset.revoke()
        else:
            queryset.delete()


class RefreshTokenManager(models.Manager):
    """Manager for handling RefreshToken lifecycle."""

    def get_valid_token(self, token_hash: str):
        """
        Retrieves a token only if it is unused and its parent session is active.
        """
        return (
            self.select_related("session", "session__user")
            .filter(
                token_hash=token_hash,
                consumed_at__isnull=True,
                expires_at__gt=timezone.now(),
                session__revoked_at__isnull=True,
                session__absolute_expiry__gt=timezone.now(),
            )
            .first()
        )
