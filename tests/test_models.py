"""
Unit tests for drf-sessions models.
"""

from datetime import timedelta

import uuid6
from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model

from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.models import Session, RefreshToken


User = get_user_model()


class SessionModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="user", password="password123")
        self.now = timezone.now()

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
        session = Session.objects.create(
            user=self.user,
            last_activity_at=self.now,
            transport=AUTH_TRANSPORT.HEADER,
            absolute_expiry=self.now + timedelta(hours=1),
        )
        self.assertIsInstance(session.session_id, type(uuid6.uuid7()))

    def test_str_output(self):
        session = Session.objects.create(
            user=self.user,
            last_activity_at=self.now,
            transport=AUTH_TRANSPORT.HEADER,
            absolute_expiry=self.now + timedelta(hours=1),
        )
        self.assertEqual(
            str(session), f"{self.user.get_username()} ({session.session_id})"
        )

    def test_revoke_method(self):
        session = Session.objects.create(
            user=self.user,
            last_activity_at=self.now,
            transport=AUTH_TRANSPORT.HEADER,
            absolute_expiry=self.now + timedelta(hours=1),
        )

        self.assertIsNone(session.revoked_at)
        session.revoke()
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)


class RefreshTokenModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="user", password="password")
        self.session = Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=timezone.now(),
        )

    def test_token_is_expired_property(self):
        """Verify that is_expired correctly compares against current date."""
        now = timezone.now()

        # Case 1: Token valid until tomorrow
        token = RefreshToken.objects.create(
            session=self.session,
            token_hash="valid_hash",
            expires_at=now + timedelta(days=1),
        )
        self.assertFalse(token.is_expired)

        # Case 2: Token expired yesterday
        token.expires_at = now - timedelta(days=1)
        token.save()
        self.assertTrue(token.is_expired)

    def test_token_cascading_deletion(self):
        """Ensure that deleting a session removes all associated refresh tokens."""
        RefreshToken.objects.create(
            token_hash="hash123",
            session=self.session,
            expires_at=timezone.now() + timedelta(days=1),
        )
        self.assertEqual(RefreshToken.objects.count(), 1)

        self.session.delete()
        self.assertEqual(RefreshToken.objects.count(), 0)

    def test_token_uniqueness(self):
        """Ensure duplicate token hashes cannot be stored."""
        shared_hash = "unique_hash_value"
        RefreshToken.objects.create(
            session=self.session,
            token_hash=shared_hash,
            expires_at=timezone.now() + timedelta(days=1),
        )

        with self.assertRaises(Exception):  # IntegrityError
            RefreshToken.objects.create(
                token_hash=shared_hash,
                expires_at=timezone.now() + timedelta(days=1),
                session=self.session,
            )
