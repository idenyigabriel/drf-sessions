"""
Configuration management for DRF Sessions.

This module handles the loading, validation, and caching of library settings.
It enforces logical constraints (e.g., TTL relationships) and synchronizes
swappable model settings with the Django runtime.
"""

import jwt
import hashlib
from datetime import timedelta

from django.conf import settings
from django.test.signals import setting_changed
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ImproperlyConfigured


DEFAULTS = {
    # Session Lifecycle
    "ACCESS_TOKEN_TTL": timedelta(minutes=15),
    "REFRESH_TOKEN_TTL": timedelta(days=7),
    "SESSION_MODEL": "drf_sessions.Session",
    "ENFORCE_SINGLE_SESSION": False,
    "MAX_SESSIONS_PER_USER": 10,
    "UPDATE_LAST_LOGIN": True,
    "RETAIN_EXPIRED_SESSIONS": False,
    # Sliding Window Logic
    "ENABLE_SLIDING_SESSION": False,
    "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=30),
    # Security Policy
    "AUTH_COOKIE_NAMES": ("token",),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ENFORCE_SESSION_TRANSPORT": True,
    "ROTATE_REFRESH_TOKENS": True,
    "REVOKE_SESSION_ON_REUSE": True,
    "REFRESH_TOKEN_HASH_ALGORITHM": "sha256",
    "LEEWAY": timedelta(seconds=0),
    "RAISE_ON_MISSING_CONTEXT_ATTR": False,
    # JWT Configuration
    "JWT_ALGORITHM": "HS256",
    "JWT_SIGNING_KEY": settings.SECRET_KEY,
    "JWT_VERIFYING_KEY": None,
    "JWT_KEY_ID": None,
    "JWT_AUDIENCE": None,
    "JWT_ISSUER": None,
    "JWT_JSON_ENCODER": None,
    "JWT_HEADERS": {},
    # Claims Mapping
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",
    "SESSION_ID_CLAIM": "sid",
    "JTI_CLAIM": "jti",
    # Extensibility Hooks (Dotted paths to callables)
    "JWT_PAYLOAD_EXTENDER": None,
    "SESSION_VALIDATOR_HOOK": None,
    "POST_AUTHENTICATED_HOOK": None,
}

IMPORT_STRINGS = (
    "JWT_PAYLOAD_EXTENDER",
    "SESSION_VALIDATOR_HOOK",
    "POST_AUTHENTICATED_HOOK",
)

REMOVED_SETTINGS = ()

TYPE_VALIDATORS = {
    "ACCESS_TOKEN_TTL": timedelta,
    "REFRESH_TOKEN_TTL": (timedelta, type(None)),
    "SESSION_MODEL": str,
    "AUTH_COOKIE_NAMES": (list, tuple),
    "AUTH_HEADER_TYPES": (list, tuple),
    "ENFORCE_SINGLE_SESSION": bool,
    "MAX_SESSIONS_PER_USER": (int, type(None)),
    "UPDATE_LAST_LOGIN": bool,
    "RETAIN_EXPIRED_SESSIONS": bool,
    "ENABLE_SLIDING_SESSION": bool,
    "SLIDING_SESSION_MAX_LIFETIME": (timedelta, type(None)),
    "ENFORCE_SESSION_TRANSPORT": bool,
    "ROTATE_REFRESH_TOKENS": bool,
    "REVOKE_SESSION_ON_REUSE": bool,
    "REFRESH_TOKEN_HASH_ALGORITHM": str,
    "LEEWAY": timedelta,
    "RAISE_ON_MISSING_CONTEXT_ATTR": bool,
    "JWT_ALGORITHM": str,
    "JWT_SIGNING_KEY": str,
    "JWT_VERIFYING_KEY": (str, type(None)),
    "JWT_KEY_ID": (str, type(None)),
    "JWT_AUDIENCE": (str, type(None)),
    "JWT_ISSUER": (str, type(None)),
    "JWT_JSON_ENCODER": (str, type(None)),
    "JWT_HEADERS": dict,
    "USER_ID_FIELD": str,
    "USER_ID_CLAIM": str,
    "SESSION_ID_CLAIM": str,
    "JTI_CLAIM": str,
}


class DRFSessionsSettings:
    """
    Lazy settings container for DRF Sessions.
    """

    __slots__ = ("_user_settings", "_cache")

    def __init__(self, user_settings=None):
        self._user_settings = user_settings or {}
        self._cache = {}
        self._validate_all()
        self._sync_swapper()

    def _get_setting(self, setting_name: str):
        return self._user_settings.get(setting_name, DEFAULTS[setting_name])

    def __getattr__(self, setting_name: str):
        if setting_name not in DEFAULTS:
            if setting_name in REMOVED_SETTINGS:
                raise AttributeError(_(f"'{setting_name}' has been removed."))
            raise AttributeError(_(f"Invalid setting: '{setting_name}'."))

        if setting_name in self._cache:
            return self._cache[setting_name]

        value = self._get_setting(setting_name)

        if setting_name in IMPORT_STRINGS and isinstance(value, str):
            value = self._import_from_string(setting_name, value)

        self._cache[setting_name] = value
        return value

    def _import_from_string(self, setting_name: str, path: str):
        try:
            return import_string(path)
        except ImportError as exc:
            raise ImproperlyConfigured(
                _(f"Could not import '{path}' for '{setting_name}'.")
            ) from exc

    def _validate_all(self):
        self._validate_removed_settings()
        self._validate_primitive_types()
        self._validate_business_logic()

    def _validate_removed_settings(self):
        for setting_name in REMOVED_SETTINGS:
            if setting_name in self._user_settings:
                raise ImproperlyConfigured(
                    _(f"'{setting_name}' is no longer supported.")
                )

    def _validate_primitive_types(self):
        for setting_name, expected_types in TYPE_VALIDATORS.items():
            value = self._get_setting(setting_name)
            if not isinstance(value, expected_types):
                raise ImproperlyConfigured(_(f"'{setting_name}' has invalid type."))

    def _validate_business_logic(self):
        self._validate_ttl_settings()
        self._validate_hash_algorithm()
        self._validate_asymmetric_keys()
        self._validate_sliding_session_dependencies()

    def _validate_ttl_settings(self):
        access_ttl = self._get_setting("ACCESS_TOKEN_TTL")
        refresh_ttl = self._get_setting("REFRESH_TOKEN_TTL")
        sliding_max = self._get_setting("SLIDING_SESSION_MAX_LIFETIME")

        if access_ttl and access_ttl <= timedelta(0):
            raise ImproperlyConfigured(_("ACCESS_TOKEN_TTL must be positive."))

        if (refresh_ttl and access_ttl) and (refresh_ttl <= access_ttl):
            raise ImproperlyConfigured(
                _("REFRESH_TOKEN_TTL must exceed ACCESS_TOKEN_TTL.")
            )

        if (refresh_ttl and sliding_max) and (refresh_ttl >= sliding_max):
            raise ImproperlyConfigured(
                _("SLIDING_SESSION_MAX_LIFETIME must exceed REFRESH_TOKEN_TTL.")
            )

    def _validate_hash_algorithm(self):
        jwt_algo = self._get_setting("JWT_ALGORITHM")
        ref_hash_algo = self._get_setting("REFRESH_TOKEN_HASH_ALGORITHM")

        if ref_hash_algo not in hashlib.algorithms_available:
            raise ImproperlyConfigured(_(f"'{ref_hash_algo}' is unsupported."))

        if jwt_algo not in jwt.algorithms.get_default_algorithms():
            raise ImproperlyConfigured(
                _(f"'{jwt_algo}' is an unsupported JWT algorithm.")
            )

    def _validate_asymmetric_keys(self):
        algo = self._get_setting("JWT_ALGORITHM")
        if not algo.startswith("HS"):
            if self._get_setting("JWT_VERIFYING_KEY") is None:
                raise ImproperlyConfigured(
                    _(
                        f"JWT_VERIFYING_KEY is required for asymmetric algorithm '{algo}'."
                    )
                )

    def _validate_sliding_session_dependencies(self):
        if not self._get_setting("ENABLE_SLIDING_SESSION"):
            return
        required = ["REFRESH_TOKEN_TTL", "SLIDING_SESSION_MAX_LIFETIME"]
        missing = [name for name in required if self._get_setting(name) is None]
        if missing:
            raise ImproperlyConfigured(
                _(f"ENABLE_SLIDING_SESSION requires: {', '.join(missing)}.")
            )

    def _sync_swapper(self):
        session_model = self._get_setting("SESSION_MODEL")
        setattr(settings, "DRF_SESSIONS_SESSION_MODEL", session_model)

    def reload(self, new_user_settings=None):
        self._user_settings = new_user_settings or {}
        self._cache.clear()
        self._validate_all()
        self._sync_swapper()


drf_sessions_settings = DRFSessionsSettings(getattr(settings, "DRF_SESSIONS", None))


def reload_drf_sessions_settings(*args, **kwargs):
    if kwargs.get("setting") == "DRF_SESSIONS":
        drf_sessions_settings.reload(kwargs.get("value"))


setting_changed.connect(reload_drf_sessions_settings)
