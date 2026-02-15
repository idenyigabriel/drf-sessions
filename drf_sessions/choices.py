"""
Constants for session transport constraints.

This module defines the authorized delivery mechanisms for authentication
credentials. It enables security policies that bind a session to a specific
transport layer (e.g., ensuring a session created for 'Cookies' cannot be
hijacked via 'Authorization' headers).
"""

from django.db import models
from django.utils.translation import gettext_lazy as _


class AUTH_TRANSPORT(models.TextChoices):
    """
    Authorized transport methods for session identification.

    Attributes:
        ANY: The session is not restricted to a specific delivery channel.
        COOKIE: The session credentials must be transmitted via HTTP-only cookies.
        HEADER: The session credentials must be transmitted via the 'Authorization' header.
    """

    ANY = "any", _("Any")
    COOKIE = "cookie", _("Cookie")
    HEADER = "header", _("Header")
