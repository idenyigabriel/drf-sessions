"""
Unit tests for drf-sessions cryptographic utilities.
"""

from datetime import timedelta

import jwt
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from drf_sessions.models import Session
from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.utils.tokens import (
    hash_token_string,
    verify_access_token,
    generate_access_token,
    generate_refresh_token,
)


User = get_user_model()


# This function must exist at the module level so it can be
# imported by the settings validator via a string path.
def sample_payload_extender(session):
    """
    Test hook to extend JWT payload.
    """
    return {"email": session.user.username + "@example.com"}


class CryptoUtilsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="user", password="password123")
        self.session = Session.objects.create(
            user=self.user,
            transport=AUTH_TRANSPORT.HEADER,
            last_activity_at=timezone.now(),
        )

    def test_refresh_token_generation_and_hashing(self):
        """Verify refresh tokens are random and hashing is deterministic."""
        raw, hashed = generate_refresh_token()

        # Ensure raw token is high entropy (secrets.token_urlsafe(48))
        self.assertTrue(len(raw) > 32)
        self.assertNotEqual(raw, hashed)

        # Ensure hashing the same raw string produces the same hash
        self.assertEqual(hash_token_string(raw), hashed)

        # Ensure two generations produce different tokens
        raw2, _ = generate_refresh_token()
        self.assertNotEqual(raw, raw2)

    def test_access_token_payload_contents(self):
        """Verify the JWT payload contains the required session and user claims."""
        token = generate_access_token(self.session)
        payload = verify_access_token(token)

        # Claims defined in settings: sub (user) and sid (session)
        self.assertEqual(payload["sub"], str(self.user.id))
        self.assertEqual(payload["sid"], str(self.session.session_id))
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)

    def test_access_token_expiry(self):
        """Verify that a custom TTL is respected in the JWT."""
        custom_ttl = timedelta(seconds=60)
        token = generate_access_token(self.session, access_ttl=custom_ttl)
        payload = verify_access_token(token)

        # Expiry should be roughly now + 60s
        expected_exp = int((timezone.now() + custom_ttl).timestamp())
        self.assertAlmostEqual(payload["exp"], expected_exp, delta=2)

    @override_settings(
        DRF_SESSIONS={"JWT_ISSUER": "test-issuer", "JWT_AUDIENCE": "test-audience"}
    )
    def test_jwt_issuer_and_audience(self):
        """Verify that issuer and audience claims are handled correctly."""
        token = generate_access_token(self.session)
        payload = verify_access_token(token)

        self.assertEqual(payload["iss"], "test-issuer")
        self.assertEqual(payload["aud"], "test-audience")

    def test_verify_access_token_expired(self):
        """Verify that an expired JWT raises the correct exception."""
        # Create a token that expired 1 hour ago
        past_ttl = timedelta(hours=-1)
        token = generate_access_token(self.session, access_ttl=past_ttl)

        with self.assertRaises(jwt.ExpiredSignatureError):
            verify_access_token(token)

    def test_verify_access_token_invalid_signature(self):
        """Verify that tampering with the token causes verification failure."""
        token = generate_access_token(self.session)
        tampered_token = token[:-5] + "aaaaa"  # Corrupt the signature

        with self.assertRaises(jwt.InvalidTokenError):
            verify_access_token(tampered_token)

    @override_settings(
        DRF_SESSIONS={
            # Pass the dotted string path, not the function itself
            "JWT_PAYLOAD_EXTENDER": "tests.utils.test_tokens.sample_payload_extender"
        }
    )
    def test_payload_extender_hook(self):
        """Verify that the JWT_PAYLOAD_EXTENDER successfully adds custom claims."""
        token = generate_access_token(self.session)
        payload = verify_access_token(token)

        self.assertEqual(payload["email"], "user@example.com")

    @override_settings(DRF_SESSIONS={"JWT_ALGORITHM": "HS512"})
    def test_verify_key_selection_hmac(self):
        """Verify that standard HS algorithms (Symmetric) pass the settings validator."""
        # HS512 is a real algorithm supported by PyJWT
        token = generate_access_token(self.session)
        payload = verify_access_token(token)
        self.assertEqual(payload["sid"], str(self.session.session_id))
