from datetime import timedelta

from django.test import SimpleTestCase
from django.core.exceptions import ImproperlyConfigured

from drf_sessions.settings import DRFSessionsSettings, DEFAULTS


class SettingsTests(SimpleTestCase):
    def test_default_values_are_loaded(self):
        settings = DRFSessionsSettings(user_settings={})
        self.assertEqual(settings.ACCESS_TOKEN_TTL, DEFAULTS["ACCESS_TOKEN_TTL"])
        self.assertEqual(settings.JWT_ALGORITHM, "HS256")

    def test_user_settings_override_defaults(self):
        user_settings = {"ACCESS_TOKEN_TTL": timedelta(minutes=5)}
        settings = DRFSessionsSettings(user_settings=user_settings)
        self.assertEqual(settings.ACCESS_TOKEN_TTL, timedelta(minutes=5))

    def test_invalid_type_raises_error(self):
        user_settings = {"MAX_SESSIONS_PER_USER": "not-an-int"}
        with self.assertRaisesRegex(ImproperlyConfigured, "invalid type"):
            DRFSessionsSettings(user_settings=user_settings)

    def test_ttl_logic_validation(self):
        # Test: Refresh must be > Access
        invalid_ttl = {
            "ACCESS_TOKEN_TTL": timedelta(minutes=60),
            "REFRESH_TOKEN_TTL": timedelta(minutes=30),
        }
        with self.assertRaisesRegex(
            ImproperlyConfigured, "must exceed ACCESS_TOKEN_TTL"
        ):
            DRFSessionsSettings(user_settings=invalid_ttl)

        # Test: Sliding Max must be > Refresh
        invalid_sliding = {
            "ENABLE_SLIDING_SESSION": True,
            "REFRESH_TOKEN_TTL": timedelta(days=7),
            "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=5),
        }
        with self.assertRaisesRegex(
            ImproperlyConfigured, "must exceed REFRESH_TOKEN_TTL"
        ):
            DRFSessionsSettings(user_settings=invalid_sliding)

    def test_asymmetric_key_requirement(self):
        user_settings = {
            "JWT_ALGORITHM": "RS256",
            "JWT_VERIFYING_KEY": None,  # Missing
        }
        with self.assertRaisesRegex(
            ImproperlyConfigured, "JWT_VERIFYING_KEY is required"
        ):
            DRFSessionsSettings(user_settings=user_settings)

    def test_sliding_session_dependencies(self):
        user_settings = {"REFRESH_TOKEN_TTL": None, "ENABLE_SLIDING_SESSION": True}
        with self.assertRaisesRegex(
            ImproperlyConfigured, "requires: REFRESH_TOKEN_TTL"
        ):
            DRFSessionsSettings(user_settings=user_settings)

    def test_reload_clears_cache(self):
        settings = DRFSessionsSettings(user_settings={"MAX_SESSIONS_PER_USER": 5})
        self.assertEqual(settings.MAX_SESSIONS_PER_USER, 5)

        settings.reload(new_user_settings={"MAX_SESSIONS_PER_USER": 100})
        self.assertEqual(settings.MAX_SESSIONS_PER_USER, 100)

    def test_attribute_error_on_invalid_setting(self):
        settings = DRFSessionsSettings(user_settings={})
        with self.assertRaises(AttributeError):
            _ = settings.NON_EXISTENT_SETTING
