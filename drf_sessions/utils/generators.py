"""Utility functions for generating unique identifiers across the application.

Functions in this module are wrapped to provide a stable interface for
database defaults, allowing logic changes (e.g., switching UUID versions)
without triggering schema migrations.
"""

import uuid6


def generate_session_id() -> uuid6.UUID:
    """Generates a time-ordered UUID v7 for database session fields.

    Wrapped in a function to allow future logic updates without
    modifying database migration files.
    """
    return uuid6.uuid7()
