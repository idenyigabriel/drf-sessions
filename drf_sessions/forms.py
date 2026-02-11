"""
Django Admin form configurations for Session management.
"""

from django import forms
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from drf_sessions.models import get_token_model
from drf_sessions.settings import drf_sessions_settings


Session = get_token_model()


class SessionAdminForm(forms.ModelForm):
    class Meta:
        model = Session
        fields = "__all__"
        exclude = ["session_id", "created_at", "revoked_at", "last_activity_at"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.id:
            delta = (
                drf_sessions_settings.SLIDING_SESSION_MAX_LIFETIME
                or drf_sessions_settings.REFRESH_TOKEN_TTL
                or drf_sessions_settings.ACCESS_TOKEN_TTL
            )
            if delta:
                self.fields["absolute_expiry"].initial = timezone.now() + delta

    def clean_absolute_expiry(self):
        expiry = self.cleaned_data.get("absolute_expiry")
        if expiry and expiry <= timezone.now():
            raise ValidationError(_("Absolute expiry must be in the future."))
        return expiry
