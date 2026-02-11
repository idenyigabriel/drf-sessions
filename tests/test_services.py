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

    def test_refresh_token_slides_within_session_wall(self):
        """
        Verify that rotation slides the Refresh Token lease forward,
        but never exceeds the Session's fixed absolute wall.
        """
        # 1. Set a fixed session wall (e.g., 2 days from now)
        session_wall = timezone.now() + timedelta(days=2)
        self.session.absolute_expiry = session_wall
        self.session.save()

        # 2. Set current refresh token to expire very soon (1 hour)
        old_token = RefreshToken.objects.get(session=self.session)
        old_expiry = timezone.now() + timedelta(hours=1)
        old_token.expires_at = old_expiry
        old_token.save()

        # 3. Rotate with a TTL that WOULD exceed the wall (e.g., 7 days)
        with override_settings(DRF_SESSIONS={"REFRESH_TOKEN_TTL": timedelta(days=7)}):
            TokenService.rotate_refresh_token(self.raw_refresh)

        # 4. Fetch the new token
        new_token = RefreshToken.objects.filter(session=self.session).latest(
            "created_at"
        )

        # The new token's expiry should have slid forward past the old 1-hour expiry
        self.assertGreater(new_token.expires_at, old_expiry)

        # But it must be capped exactly at the Session's absolute_expiry wall
        self.assertEqual(new_token.expires_at, session_wall)

        # And the session wall itself must remain unchanged
        self.session.refresh_from_db()
        self.assertEqual(self.session.absolute_expiry, session_wall)

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
        token_instance.expires_at = timezone.now() - timedelta(days=1)
        token_instance.save()

        result = TokenService.rotate_refresh_token(self.raw_refresh)
        self.assertIsNone(result)
