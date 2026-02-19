"""
Unit tests for drf-sessions authentication classes.
Updated to verify silent failures (returning None) for compatibility with AllowAny.
"""

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory

from drf_sessions.models import Session
from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.auth import BearerAuthentication, CookieAuthentication


User = get_user_model()


class AuthenticationTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(username="auth_user", is_active=True)
        self.now = timezone.now()

        # Create a valid session in the DB
        self.session = Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=self.now,
            absolute_expiry=self.now + timedelta(hours=1),
        )
        self.valid_token = "valid.test.token"
        self.mock_payload = {"sid": str(self.session.session_id)}

    @patch("drf_sessions.base.auth.verify_access_token")
    def test_bearer_auth_success(self, mock_verify):
        """Verify successful header-based authentication."""
        mock_verify.return_value = self.mock_payload

        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.valid_token}")
        auth = BearerAuthentication()

        result = auth.authenticate(request)
        self.assertIsNotNone(result)

        user, session = result
        self.assertEqual(user, self.user)
        self.assertEqual(session.session_id, self.session.session_id)

    @patch("drf_sessions.base.auth.verify_access_token")
    def test_cookie_auth_success(self, mock_verify):
        """Verify successful cookie-based authentication."""
        self.session.transport = AUTH_TRANSPORT.COOKIE
        self.session.save()
        mock_verify.return_value = self.mock_payload

        request = self.factory.get("/")
        request.COOKIES["token"] = self.valid_token

        auth = CookieAuthentication()
        result = auth.authenticate(request)

        self.assertIsNotNone(result)
        user, _ = result
        self.assertEqual(user, self.user)

    @patch("drf_sessions.base.auth.verify_access_token")
    def test_authentication_returns_none_if_session_revoked(self, mock_verify):
        """Verify that a revoked session returns None rather than raising an error."""
        mock_verify.return_value = self.mock_payload
        self.session.revoked_at = timezone.now()
        self.session.save()

        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.valid_token}")
        auth = BearerAuthentication()

        # Should return None to allow guest access/other auth classes
        self.assertIsNone(auth.authenticate(request))

    @override_settings(DRF_SESSIONS={"ENFORCE_SESSION_TRANSPORT": True})
    @patch("drf_sessions.base.auth.verify_access_token")
    def test_transport_binding_mismatch_returns_none(self, mock_verify):
        """Verify that transport mismatch returns None."""
        self.session.transport = AUTH_TRANSPORT.COOKIE
        self.session.save()
        mock_verify.return_value = self.mock_payload

        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.valid_token}")
        auth = BearerAuthentication()

        self.assertIsNone(auth.authenticate(request))

    @patch("drf_sessions.base.auth.verify_access_token")
    def test_inactive_user_returns_none(self, mock_verify):
        """Verify that inactive user account results in None."""
        mock_verify.return_value = self.mock_payload
        self.user.is_active = False
        self.user.save()

        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.valid_token}")
        auth = BearerAuthentication()

        self.assertIsNone(auth.authenticate(request))

    @patch("drf_sessions.base.auth.verify_access_token")
    def test_expired_token_returns_none(self, mock_verify):
        """Verify that expired tokens return None (silent failure)."""
        import jwt

        mock_verify.side_effect = jwt.ExpiredSignatureError

        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.valid_token}")
        auth = BearerAuthentication()

        self.assertIsNone(auth.authenticate(request))

    def test_extract_token_bearer_invalid_format(self):
        """Test edge cases for Header extraction."""
        auth = BearerAuthentication()

        # Missing prefix
        request = self.factory.get("/", HTTP_AUTHORIZATION=self.valid_token)
        self.assertIsNone(auth.extract_token(request))

        # Wrong prefix
        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Basic {self.valid_token}")
        self.assertIsNone(auth.extract_token(request))

    @override_settings(
        DRF_SESSIONS={"SESSION_VALIDATOR_HOOK": "tests.test_auth.failing_validator"}
    )
    @patch("drf_sessions.base.auth.verify_access_token")
    def test_validator_hook_failure_returns_none(self, mock_verify):
        """Verify that the SESSION_VALIDATOR_HOOK rejection returns None."""
        mock_verify.return_value = self.mock_payload
        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.valid_token}")
        auth = BearerAuthentication()

        self.assertIsNone(auth.authenticate(request))


def failing_validator(session, request):
    """Sample validator for testing failure."""
    return False
