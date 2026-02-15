"""
Database abstraction layer for authentication sessions.
"""

from typing import Optional
from datetime import timedelta

from swapper import load_model
from django.utils import timezone
from django.db import models, transaction
from django.contrib.auth.models import update_last_login

from drf_sessions.types import IssuedSession
from drf_sessions.settings import drf_sessions_settings
from drf_sessions.utils.tokens import generate_access_token, generate_refresh_token


class SessionQuerySet(models.QuerySet):
    """Custom QuerySet for session management."""

    def active(self):
        """Returns sessions that are not revoked and within their absolute lifetime."""
        return self.filter(revoked_at__isnull=True).filter(
            models.Q(absolute_expiry__gt=timezone.now())
            | models.Q(absolute_expiry__isnull=True)
        )

    def revoke(self) -> int:
        """Mass revokes sessions in the current queryset."""
        if drf_sessions_settings.RETAIN_EXPIRED_SESSIONS:
            return self.update(revoked_at=timezone.now())
        else:
            count, __ = self.delete()
            return count


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
        if drf_sessions_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)

        # Enforce limits before creating a new one
        self._handle_session_limits(user)

        # Resolve Lifetimes
        max_sliding = drf_sessions_settings.SLIDING_SESSION_MAX_LIFETIME
        access_base = access_ttl or drf_sessions_settings.ACCESS_TOKEN_TTL
        refresh_base = refresh_ttl or drf_sessions_settings.REFRESH_TOKEN_TTL

        # Absolute expiry is the hard deadline for the session
        # Use sliding limit if enabled, otherwise fallback to refresh TTL
        expiry_delta = max_sliding or refresh_base or access_base
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

            expiry_time = now + refresh_base
            if absolute_expiry:
                refresh_expires_at = min(expiry_time, absolute_expiry)
            else:
                refresh_expires_at = expiry_time

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
        if drf_sessions_settings.ENFORCE_SINGLE_SESSION:
            active_sessions.revoke()
            return

        # 2. Max sessions enforcement (FIFO)
        max_limit = drf_sessions_settings.MAX_SESSIONS_PER_USER
        if max_limit is not None:
            count = active_sessions.count()
            if count >= max_limit:
                # Identify oldest sessions to remove to make room for the new one
                num_to_remove = (count - max_limit) + 1
                oldest_ids = list(
                    active_sessions.values_list("id", flat=True)[:num_to_remove]
                )
                self.filter(id__in=oldest_ids).revoke()
