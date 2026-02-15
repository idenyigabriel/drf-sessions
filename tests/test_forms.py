"""
Tests for Session and RefreshToken ModelAdmin forms.
"""

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from drf_sessions.models import get_session_model
from drf_sessions.forms import RefreshTokenAdminForm, SessionAdminForm


User = get_user_model()
SessionModel = get_session_model()


class SessionAdminFormTest(TestCase):
    """Tests ModelAdmin form logic for Session instances."""

    def setUp(self):
        self.user = User.objects.create_user(username="testuser")
        # Valid settings that satisfy internal validation logic
        self.valid_drf_settings = {
            "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=2),
            "REFRESH_TOKEN_TTL": timedelta(days=1),
            "ACCESS_TOKEN_TTL": timedelta(minutes=5),
        }

    def test_initial_expiry_on_add_view(self):
        """Verify absolute_expiry is pre-filled using settings priority."""
        with override_settings(DRF_SESSIONS=self.valid_drf_settings):
            now = timezone.now()
            with patch("django.utils.timezone.now", return_value=now):
                form = SessionAdminForm()

            expected = now + self.valid_drf_settings["SLIDING_SESSION_MAX_LIFETIME"]
            self.assertEqual(form.fields["absolute_expiry"].initial, expected)


class RefreshTokenAdminFormTest(TestCase):
    """Tests ModelAdmin form validation for RefreshToken instances."""

    def setUp(self):
        self.user = User.objects.create_user(username="tokenuser")
        self.session = SessionModel.objects.create(
            user=self.user, absolute_expiry=timezone.now() + timedelta(hours=4)
        )

    def test_validation_error_exceeds_max_lifetime(self):
        """Verify admin validation prevents tokens exceeding sliding window."""
        # 6 hours exceeds the 5-hour session absolute expiry lifetime setting
        data = {
            "session": self.session.pk,
            "token_hash": "some_hash",
            "expires_at": timezone.now() + timedelta(hours=6),
        }
        form = RefreshTokenAdminForm(data=data)

        self.assertFalse(form.is_valid())
        self.assertIn("expires_at", form.errors)
        self.assertIn(
            "Expiry cannot exceed session absolute expiry", form.errors["expires_at"][0]
        )

    def test_validation_passes_within_limit(self):
        """Verify standard expiry values pass validation."""
        valid_date = timezone.now() + timedelta(hours=2)
        data = {
            "session": self.session.pk,
            "token_hash": "some_hash",
            "expires_at": valid_date,
        }
        form = RefreshTokenAdminForm(data=data)
        self.assertTrue(form.is_valid(), form.errors)
