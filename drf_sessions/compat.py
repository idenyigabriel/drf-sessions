"""
Type hinting compatibility and utility abstractions.

This module centralizes type-related imports to handle version-specific
differences (e.g., 'Self' type) and provides a single entry point for
the library's type hinting needs.
"""

import sys
from typing import (
    Any,
    Type,
    Dict,
    Union,
    Tuple,
    Optional,
    Callable,
    NamedTuple,
    TYPE_CHECKING,
)

# Handle the 'Self' type introduced in PEP 673.
# Python 3.11+ includes 'Self' in the standard library.
# For older versions, the library requires 'typing_extensions' as a dependency.
if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

# Explicitly defining __all__ ensures that IDEs and static analysis tools
# treat this module as a clean public API for typing, preventing
# "unexpected export" warnings.
__all__ = [
    "Any",
    "Self",
    "Type",
    "Dict",
    "Union",
    "Tuple",
    "Callable",
    "Optional",
    "NamedTuple",
    "TYPE_CHECKING",
]
