"""
Unit tests for drf-sessions Admin interface.
"""

from unittest.mock import patch, MagicMock

from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from django.contrib.admin.sites import AdminSite

from drf_sessions.models import Session
from drf_sessions.types import IssuedSession
from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.admin import SessionAdmin, SessionStatusFilter


User = get_user_model()


class SessionAdminTests(TestCase):
    def setUp(self):
        self.site = AdminSite()
        self.user = User.objects.create_user(
            username="admin_user", password="password123"
        )
        self.factory = RequestFactory()
        self.admin = SessionAdmin(Session, self.site)
        self.now = timezone.now()

    def _get_request_with_messages(self, path="/"):
        """
        Attaches message storage to a fake request.
        We use CookieStorage to avoid the SessionMiddleware dependency
        during unit tests.
        """
        from django.contrib.messages.storage.cookie import CookieStorage

        request = self.factory.get(path)
        setattr(request, "_messages", CookieStorage(request))
        return request

    def test_is_active_display(self):
        """Verify the custom is_active column logic."""
        active_session = Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=self.now,  # Fixed: Add required field
            absolute_expiry=self.now + timezone.timedelta(hours=1),
        )
        expired_session = Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=self.now,  # Fixed: Add required field
            absolute_expiry=self.now - timezone.timedelta(hours=1),
        )

        self.assertTrue(self.admin.is_active(active_session))
        self.assertFalse(self.admin.is_active(expired_session))

    @patch("drf_sessions.admin.TokenService.create_session")
    def test_save_model_creates_tokens_and_notifies(self, mock_create):
        """Verify that adding a session via Admin flashes tokens via messages."""
        mock_issued = IssuedSession(
            access_token="mock_access",
            refresh_token="mock_refresh",
            session=MagicMock(),
        )
        mock_create.return_value = mock_issued

        request = self._get_request_with_messages()
        # Create a transient object (not saved to DB yet)
        obj = Session(user=self.user, transport=AUTH_TRANSPORT.HEADER)

        self.admin.save_model(request, obj, form=None, change=False)

        # Check messages
        storage = getattr(request, "_messages")
        message_texts = [m.message for m in storage]

        self.assertTrue(any("mock_access" in text for text in message_texts))
        self.assertTrue(any("mock_refresh" in text for text in message_texts))

    def test_status_filter_active(self):
        """Verify the custom Status list filter for 'active' sessions."""
        Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=self.now,
            absolute_expiry=self.now + timezone.timedelta(days=1),
        )

        request = self.factory.get("/", {"status": "active"})
        filter_inst = SessionStatusFilter(
            request, {"status": "active"}, Session, self.admin
        )

        qs = filter_inst.queryset(request, Session.objects.all())
        self.assertEqual(qs.count(), 1)

    def test_status_filter_expired(self):
        """Verify the custom Status list filter for 'expired' sessions."""
        Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=self.now,
            absolute_expiry=self.now - timezone.timedelta(days=1),
        )

        request = self.factory.get("/", {"status": "expired"})
        filter_inst = SessionStatusFilter(
            request, {"status": "expired"}, Session, self.admin
        )

        qs = filter_inst.queryset(request, Session.objects.all())
        self.assertEqual(qs.count(), 1)
