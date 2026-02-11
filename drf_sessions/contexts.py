"""
Context parameter container for dot-notation access to authentication metadata.

This module provides a memory-efficient wrapper for metadata dictionaries,
enabling clean attribute-style access while enforcing immutability
through the dot-notation interface.
"""

from drf_sessions.compat import Any, Dict
from drf_sessions.settings import drf_sessions_settings


class ContextParams:
    """
    Provides immutable dot-notation access to context dictionary.

    Attributes can be accessed via dot-notation (e.g., context.user_id).
    Modification is blocked via __setattr__ to ensure the wrapper remains read-only.
    """

    __slots__ = ("_data",)

    def __init__(self, data: Dict[str, Any]) -> None:
        """
        Initialize context wrapper.

        Args:
            data: Dictionary of context parameters.

        Raises:
            TypeError: If data is not a dictionary.
        """
        if not isinstance(data, dict):
            raise TypeError(
                f"{self.__class__.__name__} requires a dict, got {type(data).__name__}"
            )

        # Using object.__setattr__ to bypass the custom __setattr__
        # which otherwise blocks all assignments.
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name: str) -> Any:
        """
        Get attribute via dot notation.

        Handles missing attributes according to the library's
        RAISE_ON_MISSING_CONTEXT_ATTR setting.
        """
        # Protect internal slot attributes from being accessed as data keys.
        if name.startswith("_"):
            raise AttributeError(
                f"'{self.__class__.__name__}' has no attribute '{name}'"
            )

        if name in self._data:
            return self._data[name]

        if drf_sessions_settings.RAISE_ON_MISSING_CONTEXT_ATTR:
            raise AttributeError(f"Context has no parameter '{name}'")

        return None

    def __setattr__(self, name: str, value: Any) -> None:
        """Blocks attribute assignment to enforce a read-only dot-notation interface."""
        raise TypeError(f"{self.__class__.__name__} does not support item assignment")

    def __delattr__(self, name: str) -> None:
        """Blocks attribute deletion to enforce a read-only dot-notation interface."""
        raise TypeError(f"{self.__class__.__name__} does not support item deletion")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._data!r})"
