"""
Unit tests for drf-sessions Admin forms.
"""

from datetime import timedelta

from django.utils import timezone
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.admin import SessionAdminForm


User = get_user_model()


class SessionAdminFormTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="admin_user", password="password123"
        )
        self.now = timezone.now()

    def test_initial_absolute_expiry_defaults(self):
        """Verify that the form suggests an expiry based on SLIDING_SESSION_MAX_LIFETIME."""
        custom_delta = timedelta(days=15)

        with override_settings(
            DRF_SESSIONS={"SLIDING_SESSION_MAX_LIFETIME": custom_delta}
        ):
            form = SessionAdminForm()
            initial_expiry = form.fields["absolute_expiry"].initial

            # Should be roughly now + 15 days
            expected = self.now + custom_delta
            self.assertAlmostEqual(initial_expiry, expected, delta=timedelta(seconds=2))

    def test_clean_absolute_expiry_future(self):
        """Verify the form rejects an expiry date in the past."""
        data = {
            "user": self.user.id,
            "transport": AUTH_TRANSPORT.HEADER,
            "absolute_expiry": self.now - timedelta(minutes=1),
            "context": {},
        }
        form = SessionAdminForm(data=data)

        self.assertFalse(form.is_valid())
        self.assertIn("absolute_expiry", form.errors)
        self.assertEqual(
            form.errors["absolute_expiry"], ["Absolute expiry must be in the future."]
        )

    def test_clean_absolute_expiry_valid(self):
        """Verify the form accepts a valid future expiry date."""
        data = {
            "user": self.user.id,
            "transport": AUTH_TRANSPORT.HEADER,
            "absolute_expiry": self.now + timedelta(hours=1),
            "context": {},
        }
        form = SessionAdminForm(data=data)
        self.assertTrue(form.is_valid())

    def test_issue_refresh_token_field_initial(self):
        """Ensure the 'issue_refresh_token' checkbox defaults to True."""
        form = SessionAdminForm()
        self.assertTrue(form.fields["issue_refresh_token"].initial)

    @override_settings(
        DRF_SESSIONS={
            "SLIDING_SESSION_MAX_LIFETIME": None,
            "REFRESH_TOKEN_TTL": timedelta(days=5),
        }
    )
    def test_fallback_initial_expiry(self):
        """Verify fallback to REFRESH_TOKEN_TTL when sliding is disabled."""
        form = SessionAdminForm()
        initial_expiry = form.fields["absolute_expiry"].initial

        expected = self.now + timedelta(days=5)
        self.assertAlmostEqual(initial_expiry, expected, delta=timedelta(seconds=2))
