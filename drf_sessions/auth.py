"""
Concrete authentication classes for DRF Sessions.

This module provides ready-to-use implementations for common transport
layers, utilizing configurable header types and cookie names.
"""

from rest_framework.request import Request
from rest_framework.authentication import get_authorization_header

from drf_sessions.compat import Optional
from drf_sessions.settings import authentify_settings
from drf_sessions.base.auth import BaseCookieAuthentication, BaseHeaderAuthentication


class BearerAuthentication(BaseHeaderAuthentication):
    """
    Concrete implementation for header-based sessions.

    Checks the 'Authorization' header against a list of allowed prefixes
    defined in AUTH_HEADER_TYPES.
    """

    def extract_token(self, request: Request) -> Optional[str]:
        auth = get_authorization_header(request).split()
        allowed_types = authentify_settings.AUTH_HEADER_TYPES

        if not auth:
            return None

        # Check if the prefix (e.g., Bearer, JWT, Token) is in our allowed list
        prefix = auth[0].decode("utf-8").lower()
        allowed_prefixes = [t.lower() for t in allowed_types]

        if prefix not in allowed_prefixes:
            return None

        if len(auth) == 1:
            return None

        if len(auth) > 2:
            return None

        return auth[1].decode("utf-8")


class CookieAuthentication(BaseCookieAuthentication):
    """
    Concrete implementation for HTTP-only cookie-based sessions.

    Checks multiple possible cookie names defined in AUTH_COOKIE_NAMES.
    """

    def extract_token(self, request: Request) -> Optional[str]:
        # Iterate through allowed names; return the first one found
        cookie_names = authentify_settings.AUTH_COOKIE_NAMES

        for name in cookie_names:
            token = request.COOKIES.get(name)
            if token:
                return token

        return None
