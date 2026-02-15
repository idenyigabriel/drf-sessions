"""
Tests for Session and RefreshToken Admin configurations.

Covers Admin classes, custom list filters, and ModelAdmin actions.
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory, TestCase

from drf_sessions.models import RefreshToken, get_session_model
from drf_sessions.admin import (
    SessionAdmin,
    RefreshTokenAdmin,
    SessionStatusFilter,
    RefreshTokenStatusFilter,
)


User = get_user_model()
SessionModel = get_session_model()


class AdminTestCase(TestCase):
    """Base class for Admin tests providing authenticated requests."""

    def setUp(self):
        self.site = AdminSite()
        self.factory = RequestFactory()
        self.super_user = User.objects.create_superuser(
            username="admin", password="password", email="admin@example.com"
        )
        # Default expiry for tokens used across tests
        self.default_expiry = timezone.now() + timedelta(days=1)

    def get_request(self, path="/", data=None):
        """Constructs a request with a user and message support."""
        request = self.factory.get(path, data or {})
        request.user = self.super_user
        setattr(request, "_messages", MagicMock())
        return request


class SessionAdminTest(AdminTestCase):
    """Tests logic within the SessionAdmin class."""

    def setUp(self):
        super().setUp()
        self.admin = SessionAdmin(SessionModel, self.site)

    def test_is_active_display(self):
        """Verify is_active identifies active vs revoked sessions."""
        active = SessionModel.objects.create(user=self.super_user)
        revoked = SessionModel.objects.create(
            user=self.super_user, revoked_at=timezone.now()
        )
        self.assertTrue(self.admin.is_active(active))
        self.assertFalse(self.admin.is_active(revoked))

    def test_get_queryset_annotation(self):
        """Verify the queryset includes the refresh_token_count annotation."""
        session = SessionModel.objects.create(user=self.super_user)
        RefreshToken.objects.create(
            session=session, 
            token_hash="h1", 
            expires_at=self.default_expiry
        )
        
        request = self.get_request()
        qs = self.admin.get_queryset(request)
        annotated_obj = qs.get(pk=session.pk)
        
        self.assertEqual(annotated_obj.refresh_token_count, 1)

    def test_view_refresh_tokens_link(self):
        """Ensure the HTML link to refresh tokens is generated correctly."""
        session = SessionModel.objects.create(user=self.super_user)
        session.refresh_token_count = 5
        
        html = self.admin.view_refresh_tokens(session)
        self.assertIn(f"session_id={session.id}", html)
        self.assertIn("View 5 Token(s)", html)

    @patch("drf_sessions.services.SessionService.create_session")
    def test_save_model_uses_service_on_create(self, mock_create):
        """Verify creation uses SessionService and avoids default save."""
        mock_create.return_value = MagicMock(access_token="abc", refresh_token="def")
        obj = SessionModel(user=self.super_user, transport="web")
        
        self.admin.save_model(self.get_request(), obj, form=None, change=False)
        mock_create.assert_called_once()


class RefreshTokenAdminTest(AdminTestCase):
    """Tests logic within the RefreshTokenAdmin class."""

    def setUp(self):
        super().setUp()
        self.admin = RefreshTokenAdmin(RefreshToken, self.site)
        self.session = SessionModel.objects.create(user=self.super_user)

    def test_token_hash_truncation(self):
        """Verify token hash truncation uses the horizontal ellipsis character."""
        token = RefreshToken(
            token_hash="a" * 50, 
            session=self.session, 
            expires_at=self.default_expiry
        )
        display_html = self.admin._token_hash(token)
        self.assertIn("aaaaaaaaaaaaaa…", display_html)

    def test_changelist_view_extra_context(self):
        """Verify 'Back to Session' link appears when filtering by session."""
        request = self.get_request("/", {"session_id": str(self.session.id)})
        response = self.admin.changelist_view(request)
        
        self.assertIn("back_to_session_link", response.context_data)
        self.assertIn(str(self.session.id), response.context_data["back_to_session_link"])

    def test_expire_tokens_action(self):
        """Verify admin action expires tokens immediately."""
        token = RefreshToken.objects.create(
            session=self.session, 
            token_hash="h", 
            expires_at=self.default_expiry
        )
        queryset = RefreshToken.objects.filter(pk=token.pk)
        
        self.admin.expire_tokens(self.get_request(), queryset)
        token.refresh_from_db()
        self.assertLessEqual(token.expires_at, timezone.now())


class AdminFiltersTest(AdminTestCase):
    """Tests the custom filter logic for Sessions and Tokens."""

    def test_session_status_filter_active(self):
        """Verify 'active' session filter logic."""
        now = timezone.now()
        active = SessionModel.objects.create(user=self.super_user)
        SessionModel.objects.create(user=self.super_user, revoked_at=now)
        
        request = self.get_request("/", {"status": "active"})
        f = SessionStatusFilter(request, {"status": "active"}, SessionModel, SessionAdmin)
        qs = f.queryset(request, SessionModel.objects.all())
        
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), active)

    def test_refresh_token_status_filter_consumed(self):
        """Verify 'consumed' token filter logic."""
        session = SessionModel.objects.create(user=self.super_user)
        consumed = RefreshToken.objects.create(
            session=session,
            token_hash="h1",
            expires_at=self.default_expiry,
            consumed_at=timezone.now()
        )
        active = RefreshToken.objects.create(
            session=session,
            token_hash="h2",
            expires_at=self.default_expiry
        )
        
        request = self.get_request("/", {"status": "consumed"})
        f = RefreshTokenStatusFilter(request, {"status": "consumed"}, RefreshToken, RefreshTokenAdmin)
        qs = f.queryset(request, RefreshToken.objects.all())
        
        self.assertIn(consumed, qs)
        self.assertNotIn(active, qs)