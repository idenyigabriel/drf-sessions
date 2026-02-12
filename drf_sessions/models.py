"""
Concrete model definitions for authentication sessions and credentials.

This module provides the default implementation for stateful sessions and
rotating refresh tokens. It utilizes the 'swapper' pattern to allow
integrating projects to override the Session model while maintaining
relational integrity.
"""

import swapper
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from drf_sessions.compat import Type
from drf_sessions.base.models import BaseModel, AbstractSession


def get_session_model() -> Type[AbstractSession]:
    """
    Resolves the active Session model class at runtime.

    Used to support Django's swappable model pattern, ensuring the library
    points to the correct database table even if the end-user has
    customized the Session implementation.
    """
    return swapper.load_model("drf_sessions", "Session")


class Session(AbstractSession):
    """
    The default concrete implementation of a user session.
    """

    class Meta(AbstractSession.Meta):
        swappable = swapper.swappable_setting("drf_sessions", "Session")


class RefreshToken(BaseModel):
    """
    A long-lived, rotating credential used to generate new access tokens.
    """

    token_hash = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    session = models.ForeignKey(
        swapper.get_model_name("drf_sessions", "Session"),
        on_delete=models.CASCADE,
        related_name="refresh_tokens",
    )

    class Meta(BaseModel.Meta):
        verbose_name = _("Refresh Token")
        verbose_name_plural = _("Refresh Tokens")
        indexes = [
            models.Index(
                fields=["session", "created_at"], name="token_session_lookup_idx"
            ),
            models.Index(
                fields=["token_hash", "consumed_at", "expires_at"],
                name="token_rotation_val_idx",
            ),
        ]

    def __str__(self) -> str:
        state = (
            "revoked"
            if self.consumed_at
            else ("expired" if self.is_expired else "active")
        )
        return f"Token {self.token_hash[:15]}… ({state})"

    @property
    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at
