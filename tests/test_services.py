"""
Unit tests for drf-sessions TokenService.
"""

from datetime import timedelta

from django.utils import timezone
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from drf_sessions.models import RefreshToken
from drf_sessions.services import TokenService
from drf_sessions.choices import AUTH_TRANSPORT


User = get_user_model()


class TokenServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="service_user", password="password123"
        )
        # Start with a clean session
        self.issued = TokenService.create_universal_session(self.user)
        self.session = self.issued.session
        self.raw_refresh = self.issued.refresh_token

    def test_create_helpers_set_correct_transport(self):
        """Verify that transport-specific helpers set the correct flags."""
        cookie_session = TokenService.create_cookie_session(self.user).session
        header_session = TokenService.create_header_session(self.user).session

        self.assertEqual(cookie_session.transport, AUTH_TRANSPORT.COOKIE)
        self.assertEqual(header_session.transport, AUTH_TRANSPORT.HEADER)

    def test_rotate_refresh_token_success(self):
        """Verify standard rotation: old token is burned, new one is issued."""
        old_token_instance = RefreshToken.objects.get(session=self.session)

        new_issued = TokenService.rotate_refresh_token(self.raw_refresh)

        self.assertIsNotNone(new_issued)
        self.assertNotEqual(new_issued.refresh_token, self.raw_refresh)

        # Verify state in DB
        old_token_instance.refresh_from_db()
        self.assertIsNotNone(old_token_instance.consumed_at)
        self.assertTrue(
            RefreshToken.objects.filter(
                session=self.session, consumed_at__isnull=True
            ).exists()
        )

    @override_settings(DRF_SESSIONS={"REVOKE_SESSION_ON_REUSE": True})
    def test_reuse_detection_revokes_session(self):
        """Verify that using a consumed token kills the entire session."""
        # Use the token once legitimately
        TokenService.rotate_refresh_token(self.raw_refresh)

        # Attempt to use the SAME token again (Reuse/Attack)
        result = TokenService.rotate_refresh_token(self.raw_refresh)

        self.assertIsNone(result)
        self.session.refresh_from_db()
        self.assertIsNotNone(self.session.revoked_at)
        self.assertFalse(self.session.is_active)

    @override_settings(
        DRF_SESSIONS={
            "ENABLE_SLIDING_SESSION": True,
            "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=30),
        }
    )
    def test_sliding_window_updates_expiry(self):
        """Verify that rotation slides the session absolute expiry forward."""
        # Manually backdate the current expiry to ensure the slide is measurable
        self.session.absolute_expiry = timezone.now() + timedelta(hours=1)
        self.session.save()

        TokenService.rotate_refresh_token(self.raw_refresh)

        self.session.refresh_from_db()
        # Should now be ~30 days from 'now', which is greater than the 1 hour we set
        self.assertGreater(
            self.session.absolute_expiry, timezone.now() + timedelta(days=29)
        )

    @override_settings(DRF_SESSIONS={"ROTATE_REFRESH_TOKENS": False})
    def test_disabled_rotation_returns_same_token(self):
        """Verify that if rotation is disabled, the same refresh token is preserved."""
        new_issued = TokenService.rotate_refresh_token(self.raw_refresh)

        self.assertEqual(new_issued.refresh_token, self.raw_refresh)

        token_instance = RefreshToken.objects.get(session=self.session)
        self.assertIsNone(token_instance.consumed_at)

    def test_rotate_fails_for_expired_token(self):
        """Ensure expired refresh tokens return None and block rotation."""
        token_instance = RefreshToken.objects.get(session=self.session)
        # Use a DateField friendly value (yesterday)
        token_instance.expires_at = timezone.now().date() - timedelta(days=1)
        token_instance.save()

        result = TokenService.rotate_refresh_token(self.raw_refresh)
        self.assertIsNone(result)
