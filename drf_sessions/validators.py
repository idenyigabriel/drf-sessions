"""
Validation logic for authentication metadata.

This module provides data integrity checks for token contextual
metadata, ensuring that JSON storage remains consistent with
the library's expected data structures.
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_context(value):
    """
    Ensures that the token context is a valid dictionary.

    This validator is used at the model level for JSONField to prevent
    incorrect data types (like lists or strings) from being persisted,
    which would otherwise break the 'ContextParams' wrapper logic.
    """
    if not isinstance(value, dict):
        raise ValidationError(
            _("Context must be a dictionary."), code="invalid_context_type"
        )
