from datetime import timedelta

from django.utils import timezone
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from django.contrib.admin.sites import AdminSite
from django.contrib.messages.storage.cookie import CookieStorage

from drf_sessions.models import Session
from drf_sessions.admin import SessionAdmin


User = get_user_model()


class MockRequest:
    pass


class SessionAdminTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="admin", password="password", is_staff=True
        )
        self.site = AdminSite()
        self.admin = SessionAdmin(Session, self.site)
        self.factory = RequestFactory()

    def _get_request_with_messages(self):
        request = self.factory.get("/admin/drf_sessions/session/add/")
        request.user = self.user
        # Use CookieStorage to avoid session middleware requirements in unit tests
        setattr(request, "_messages", CookieStorage(request))
        return request

    def test_save_model_creates_tokens_and_notifies(self):
        """
        Critical: Verify that creating a session via admin triggers
        TokenService and displays raw tokens in messages.
        """
        request = self._get_request_with_messages()
        obj = Session(user=self.user, transport="any")

        # Test creation (change=False)
        self.admin.save_model(request, obj, form=None, change=False)

        # Check messages
        storage = messages.get_messages(request)
        message_list = [m.message for m in storage]

        self.assertTrue(any("Access Token:" in m for m in message_list))
        self.assertTrue(any("Session created successfully" in m for m in message_list))

        # Ensure the session actually exists in DB
        self.assertEqual(Session.objects.filter(user=self.user).count(), 1)

    def test_is_active_boolean_display(self):
        """Ensure the admin's is_active helper correctly reflects session state."""
        now = timezone.now()

        # Active session
        active_session = Session.objects.create(
            user=self.user,
            transport="any",
            last_activity_at=now,
            absolute_expiry=now + timedelta(hours=1),
        )
        self.assertTrue(self.admin.is_active(active_session))

        # Revoked session
        active_session.revoked_at = now
        self.assertFalse(self.admin.is_active(active_session))

    def test_readonly_fields_configuration(self):
        """Check that system-managed fields are read-only to prevent tampering."""
        expected_readonly = [
            "session_id",
            "created_at",
            "revoked_at",
            "last_activity_at",
        ]
        self.assertEqual(list(self.admin.readonly_fields), expected_readonly)
