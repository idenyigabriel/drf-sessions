"""
Unit tests for drf-sessions managers.
"""

from datetime import timedelta
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from drf_sessions.models import Session, RefreshToken
from drf_sessions.choices import AUTH_TRANSPORT

User = get_user_model()


class SessionManagerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="manager_user", password="password123"
        )
        self.transport = AUTH_TRANSPORT.HEADER

    def test_create_session_basic(self):
        """Verify successful session and refresh token creation."""
        issued = Session.objects.create_session(
            user=self.user, transport=self.transport
        )

        self.assertIsNotNone(issued.access_token)
        self.assertIsNotNone(issued.refresh_token)
        self.assertEqual(issued.session.user, self.user)
        self.assertEqual(RefreshToken.objects.filter(session=issued.session).count(), 1)

    def test_last_login_updates(self):
        """Verify that user.last_login is updated upon session creation."""
        old_login = self.user.last_login
        Session.objects.create_session(user=self.user, transport=self.transport)

        self.user.refresh_from_db()
        self.assertNotEqual(self.user.last_login, old_login)

    @override_settings(DRF_SESSIONS={"ENFORCE_SINGLE_SESSION": True})
    def test_enforce_single_session(self):
        """Verify that existing sessions are removed when single session is enforced."""
        # Create first session
        Session.objects.create_session(user=self.user, transport=self.transport)
        self.assertEqual(Session.objects.active().filter(user=self.user).count(), 1)

        # Create second session
        Session.objects.create_session(user=self.user, transport=self.transport)

        # Should still be 1 because the first was terminated
        self.assertEqual(Session.objects.active().filter(user=self.user).count(), 1)

    @override_settings(
        DRF_SESSIONS={"MAX_SESSIONS_PER_USER": 2, "RETAIN_EXPIRED_SESSIONS": False}
    )
    def test_fifo_session_rolling(self):
        """Verify that the oldest session is deleted when max limit is reached."""
        # Create 2 sessions (the limit)
        s1 = Session.objects.create_session(
            user=self.user, transport=self.transport
        ).session
        s2 = Session.objects.create_session(
            user=self.user, transport=self.transport
        ).session

        self.assertEqual(Session.objects.active().count(), 2)

        # Create 3rd session - should trigger FIFO deletion of s1
        s3 = Session.objects.create_session(
            user=self.user, transport=self.transport
        ).session

        active_ids = list(Session.objects.active().values_list("id", flat=True))
        self.assertNotIn(s1.id, active_ids)
        self.assertIn(s2.id, active_ids)
        self.assertIn(s3.id, active_ids)

    @override_settings(
        DRF_SESSIONS={
            "REFRESH_TOKEN_TTL": timedelta(days=7),
            "SLIDING_SESSION_MAX_LIFETIME": None,  # Force fallback to refresh_ttl
        }
    )
    def test_absolute_expiry_calculation_fallback(self):
        """Ensure absolute_expiry falls back to refresh TTL when sliding is disabled."""
        issued = Session.objects.create_session(
            user=self.user, transport=self.transport
        )
        session = issued.session

        expected_expiry = session.created_at + timedelta(days=7)
        self.assertAlmostEqual(
            session.absolute_expiry, expected_expiry, delta=timedelta(seconds=2)
        )

    @override_settings(
        DRF_SESSIONS={
            "REFRESH_TOKEN_TTL": timedelta(days=7),
            "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=30),
        }
    )
    def test_absolute_expiry_calculation_sliding(self):
        """Ensure absolute_expiry uses sliding max lifetime when provided."""
        issued = Session.objects.create_session(
            user=self.user, transport=self.transport
        )
        session = issued.session

        expected_expiry = session.created_at + timedelta(days=30)
        self.assertAlmostEqual(
            session.absolute_expiry, expected_expiry, delta=timedelta(seconds=2)
        )

    def test_mass_revoke_queryset(self):
        """Verify that the queryset revoke method marks sessions as revoked."""
        Session.objects.create_session(user=self.user, transport=self.transport)
        Session.objects.create_session(user=self.user, transport=self.transport)

        Session.objects.active().revoke()
        self.assertEqual(Session.objects.active().count(), 0)


class RefreshTokenManagerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="token_manager", password="password123"
        )
        self.issued = Session.objects.create_session(
            user=self.user, transport=AUTH_TRANSPORT.HEADER
        )
        self.token_hash = "some_unique_hash"

        self.refresh_token = RefreshToken.objects.create(
            session=self.issued.session,
            token_hash=self.token_hash,
            expires_at=timezone.now() + timedelta(days=1),
        )

    def test_get_valid_token_success(self):
        """Verify successful retrieval of a valid token."""
        token = RefreshToken.objects.get_valid_token(self.token_hash)
        self.assertIsNotNone(token)
        self.assertEqual(token.token_hash, self.token_hash)

    def test_get_valid_token_fails_if_consumed(self):
        """Verify that consumed tokens are not returned."""
        self.refresh_token.consumed_at = timezone.now()
        self.refresh_token.save()

        token = RefreshToken.objects.get_valid_token(self.token_hash)
        self.assertIsNone(token)

    def test_get_valid_token_fails_if_session_revoked(self):
        """Verify that tokens from revoked sessions are not returned."""
        self.issued.session.revoked_at = timezone.now()
        self.issued.session.save()

        token = RefreshToken.objects.get_valid_token(self.token_hash)
        self.assertIsNone(token)
