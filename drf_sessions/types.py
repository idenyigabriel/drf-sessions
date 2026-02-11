"""
Data structures for authentication session issuance.

This module defines the containers used to transport newly generated
credentials and their associated session metadata across library layers.
"""

from drf_sessions.compat import Optional, NamedTuple, TYPE_CHECKING

if TYPE_CHECKING:
    from drf_sessions.base.models import AbstractSession


class IssuedSession(NamedTuple):
    """
    Container for newly issued credentials and their parent session.

    This tuple bundles raw (unhashed) token strings with the saved session
    instance. This allows the view layer to transmit secrets to the client
    while retaining access to the session metadata for further processing.
    """

    access_token: str
    refresh_token: Optional[str]
    session: "AbstractSession"
