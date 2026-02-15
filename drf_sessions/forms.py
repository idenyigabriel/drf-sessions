"""
Django Admin forms for Session and RefreshToken models.

Handles initial value calculations based on session settings and
enforces business logic validation for expiration timestamps.
"""

from django import forms
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from drf_sessions.settings import drf_sessions_settings
from drf_sessions.models import RefreshToken, get_session_model


SessionModel = get_session_model()


class SessionAdminForm(forms.ModelForm):
    """Form for managing Session lifecycle and expiration."""

    class Meta:
        model = SessionModel
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self._set_default_expiry()

    def _set_default_expiry(self):
        """Calculates default expiry based on the most relevant configured TTL."""
        settings = drf_sessions_settings
        delta = (
            settings.SLIDING_SESSION_MAX_LIFETIME
            or settings.REFRESH_TOKEN_TTL
            or settings.ACCESS_TOKEN_TTL
        )
        if delta:
            self.fields["absolute_expiry"].initial = timezone.now() + delta


class RefreshTokenAdminForm(forms.ModelForm):
    """Form for RefreshToken management with strict lifetime validation."""

    class Meta:
        model = RefreshToken
        fields = "__all__"

    def clean(self):
        # Always call super().clean() first to get the current cleaned_data
        cleaned_data = super().clean()

        expires_at = cleaned_data.get("expires_at")
        session = cleaned_data.get("session") or getattr(self.instance, "session", None)

        # Now both are guaranteed to be present if they passed basic validation
        if expires_at and session and session.absolute_expiry:
            if expires_at > session.absolute_expiry:
                # This attaches the error specifically to the 'expires_at' field
                self.add_error(
                    "expires_at",
                    ValidationError(
                        _("Expiry cannot exceed session absolute expiry (%(limit)s)."),
                        params={"limit": session.absolute_expiry},
                    ),
                )

        return cleaned_data
