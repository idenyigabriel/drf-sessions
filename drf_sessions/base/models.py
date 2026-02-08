"""
Core model abstractions for session-based authentication.

This module defines the database schema for persistent authentication sessions.
It supports multiple transport layers, rotating credentials, and stateful
revocation, with optimized indexes for high-concurrency environments.
"""

import uuid

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from drf_sessions.contexts import ContextParams
from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.managers import SessionManager
from drf_sessions.validators import validate_context


class BaseModel(models.Model):
    """
    Base abstraction providing creation timestamps and default ordering.
    """

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]


class AbstractSession(BaseModel):
    """
    A stateful container representing a user's authenticated connection.

    Stores metadata about the connection source (transport, user agent, IP)
    and manages the lifecycle of the session through absolute expiry and
    explicit revocation timestamps.
    """

    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sessions"
    )

    transport = models.CharField(max_length=6, choices=AUTH_TRANSPORT.choices)
    context = models.JSONField(default=dict, blank=True, validators=[validate_context])

    last_activity_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    absolute_expiry = models.DateTimeField(null=True, blank=True, db_index=True)

    objects: SessionManager = SessionManager()

    class Meta(BaseModel.Meta):
        abstract = True
        verbose_name = _("Session")
        verbose_name_plural = _("Sessions")
        indexes = [
            models.Index(fields=["absolute_expiry"], name="session_expiry_idx"),
            models.Index(
                fields=["user", "revoked_at", "created_at"],
                name="user_session_lookup_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.user.get_username()} ({self.session_id})"

    @property
    def context_obj(self) -> ContextParams:
        return ContextParams(self.context)

    @property
    def is_active(self) -> bool:
        return False if self.revoked_at else timezone.now() < self.absolute_expiry
