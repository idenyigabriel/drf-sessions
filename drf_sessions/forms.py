"""
Django Admin form configurations for Session management.
"""

from django import forms
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from drf_sessions.models import get_token_model
from drf_sessions.settings import authentify_settings

Session = get_token_model()


class SessionAdminForm(forms.ModelForm):
    """
    Form for manual session creation via Admin.
    """

    # Optional field to issue a refresh token immediately upon creation
    issue_refresh_token = forms.BooleanField(
        required=False,
        initial=True,
        help_text=_(
            "If checked, a refresh token will be generated and displayed once."
        ),
    )

    class Meta:
        model = Session
        fields = ["user", "transport", "absolute_expiry", "context"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            # Set default absolute expiry for new sessions
            delta = (
                authentify_settings.SLIDING_SESSION_MAX_LIFETIME
                or authentify_settings.REFRESH_TOKEN_TTL
            )
            self.fields["absolute_expiry"].initial = timezone.now() + delta

    def clean_absolute_expiry(self):
        expiry = self.cleaned_data.get("absolute_expiry")
        if expiry and expiry <= timezone.now():
            raise ValidationError(_("Absolute expiry must be in the future."))
        return expiry
