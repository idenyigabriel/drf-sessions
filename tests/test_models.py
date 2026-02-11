"""
Unit tests for drf-sessions models.
"""

import uuid
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model

from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.models import Session, RefreshToken


User = get_user_model()


class SessionModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", password="password123"
        )
        self.now = timezone.now()

    def test_session_active_status(self):
        """Verify that is_active correctly evaluates expiry and revocation."""
        # Case 1: Active session
        session = Session.objects.create(
            user=self.user,
            last_activity_at=self.now,
            transport=AUTH_TRANSPORT.HEADER,
            absolute_expiry=self.now + timedelta(days=1),
        )
        self.assertTrue(session.is_active)

        # Case 2: Expired session
        session.absolute_expiry = self.now - timedelta(seconds=1)
        self.assertFalse(session.is_active)

        # Case 3: Revoked session (even if not expired)
        session.absolute_expiry = self.now + timedelta(days=1)
        session.revoked_at = self.now
        self.assertFalse(session.is_active)

    def test_context_obj_property(self):
        """Ensure context JSON is correctly wrapped in ContextParams."""
        context_data = {"ip": "127.0.0.1", "agent": "Mozilla"}
        session = Session.objects.create(
            user=self.user,
            context=context_data,
            last_activity_at=self.now,
            transport=AUTH_TRANSPORT.COOKIE,
            absolute_expiry=self.now + timedelta(hours=1),
        )
        self.assertEqual(session.context_obj.ip, "127.0.0.1")
        self.assertEqual(session.context_obj.agent, "Mozilla")

    def test_session_id_is_uuid(self):
        """Verify session_id is automatically generated as a UUID."""
        session = Session.objects.create(
            user=self.user,
            last_activity_at=self.now,
            transport=AUTH_TRANSPORT.HEADER,
            absolute_expiry=self.now + timedelta(hours=1),
        )
        self.assertIsInstance(session.session_id, type(uuid.uuid4()))


class RefreshTokenModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="tokenuser", password="password123"
        )
        self.session = Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=timezone.now(),
            absolute_expiry=timezone.now() + timedelta(days=1),
        )

    def test_token_is_expired_property(self):
        """Verify that is_expired correctly compares against current date."""
        today = timezone.now()

        # Case 1: Token valid until tomorrow
        token = RefreshToken.objects.create(
            token_hash="valid_hash",
            expires_at=today + timedelta(days=1),
            session=self.session,
        )
        self.assertFalse(token.is_expired)

        # Case 2: Token expired yesterday
        token.expires_at = today - timedelta(days=1)
        token.save()
        self.assertTrue(token.is_expired)

    def test_token_cascading_deletion(self):
        """Ensure that deleting a session removes all associated refresh tokens."""
        RefreshToken.objects.create(
            token_hash="hash123",
            expires_at=timezone.now() + timedelta(days=1),
            session=self.session,
        )
        self.assertEqual(RefreshToken.objects.count(), 1)

        self.session.delete()
        self.assertEqual(RefreshToken.objects.count(), 0)

    def test_token_uniqueness(self):
        """Ensure duplicate token hashes cannot be stored."""
        shared_hash = "unique_hash_value"
        RefreshToken.objects.create(
            token_hash=shared_hash,
            expires_at=timezone.now() + timedelta(days=1),
            session=self.session,
        )

        with self.assertRaises(Exception):  # IntegrityError
            RefreshToken.objects.create(
                token_hash=shared_hash,
                expires_at=timezone.now() + timedelta(days=1),
                session=self.session,
            )

    def test_consumed_at_behavior(self):
        """Verify consumed_at can be null and then updated."""
        token = RefreshToken.objects.create(
            token_hash="rotate_me",
            expires_at=timezone.now() + timedelta(days=1),
            session=self.session,
        )
        self.assertIsNone(token.consumed_at)

        token.consumed_at = timezone.now()
        token.save()
        self.assertIsNotNone(token.consumed_at)
