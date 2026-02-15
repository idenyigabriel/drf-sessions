"""
Abstract base authentication classes for DRF Sessions.

Integrates session-bound JWT verification into the DRF request lifecycle.
Provides extensible base classes for different transport layers (Headers/Cookies)
and enforces stateful validation against the database.
"""

import jwt
from rest_framework.request import Request
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication

from drf_sessions.choices import AUTH_TRANSPORT
from drf_sessions.models import get_session_model
from drf_sessions.settings import drf_sessions_settings
from drf_sessions.utils.tokens import verify_access_token
from drf_sessions.compat import TYPE_CHECKING, Tuple, Optional

if TYPE_CHECKING:
    from drf_sessions.base.models import AbstractSession
    from django.contrib.auth.models import AbstractBaseUser


class BaseSessionAuthentication(BaseAuthentication):
    """
    Core template for session-backed JWT authentication.
    """

    transport: str = None

    def authenticate(
        self, request: Request
    ) -> Optional[Tuple["AbstractBaseUser", "AbstractSession"]]:
        token_str = self.extract_token(request)
        if not token_str:
            return None

        try:
            payload = verify_access_token(token_str)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed(_("Access token has expired."))
        except jwt.InvalidTokenError:
            raise AuthenticationFailed(_("Invalid access token."))

        return self.authenticate_credentials(request, payload)

    def authenticate_credentials(
        self, request: Request, payload: dict
    ) -> Tuple["AbstractBaseUser", "AbstractSession"]:
        """
        Verifies the session state in the database.
        """
        Session = get_session_model()
        session_id = payload.get(drf_sessions_settings.SESSION_ID_CLAIM)

        if not session_id:
            raise AuthenticationFailed(_("Token missing session identifier."))

        # Hit the database for a stateful check.
        session = (
            Session.objects.select_related("user")
            .active()
            .filter(session_id=session_id)
            .first()
        )

        if not session:
            raise AuthenticationFailed(_("Session is invalid or has been revoked."))

        if not session.user or not session.user.is_active:
            raise AuthenticationFailed(_("User account is inactive or deleted."))

        # Enforce Transport Security: Prevents session hijacking across transports
        if drf_sessions_settings.ENFORCE_SESSION_TRANSPORT:
            if (
                session.transport != AUTH_TRANSPORT.ANY
                and session.transport != self.transport
            ):
                raise AuthenticationFailed(
                    _("This session is restricted to {0} transport.").format(
                        session.transport
                    )
                )

        # Hook for IP consistency or other security policies
        if drf_sessions_settings.SESSION_VALIDATOR_HOOK:
            if not drf_sessions_settings.SESSION_VALIDATOR_HOOK(session, request):
                raise AuthenticationFailed(_("Session failed security policy."))

        # Final hook for updates and other custom user logic
        user, session = self.run_post_auth_hook(session.user, session, request)

        return (user, session)

    def run_post_auth_hook(
        self, user: "AbstractSession", session: "AbstractSession", request: Request
    ) -> Tuple:
        hook = drf_sessions_settings.POST_AUTHENTICATED_HOOK
        if hook:
            result = hook(user=user, session=session, request=request)
            if result:
                return result
        return user, session

    def extract_token(self, request: Request) -> Optional[str]:
        raise NotImplementedError


class BaseHeaderAuthentication(BaseSessionAuthentication):
    """Base class for Authorization Header schemes (e.g., Bearer)."""

    transport = AUTH_TRANSPORT.HEADER

    def authenticate_header(self, request: Request) -> str:
        # We could use a setting here for 'Bearer', but 'Bearer' is the boring standard.
        return 'Bearer realm="api"'


class BaseCookieAuthentication(BaseSessionAuthentication):
    """Base class for HTTP-only Cookie schemes."""

    transport = AUTH_TRANSPORT.COOKIE

    def authenticate_header(self, request: Request) -> str:
        # Informs the client that a session cookie is expected
        return 'Session realm="api"'
