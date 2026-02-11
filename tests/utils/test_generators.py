import uuid6

from django.test import SimpleTestCase

from drf_sessions.utils.generators import generate_session_id


class TestSessionIdentifier(SimpleTestCase):
    def test_returns_correct_uuid_type(self):
        """Ensure the generated ID is a valid uuid6.UUID instance."""
        session_id = generate_session_id()
        self.assertIsInstance(session_id, uuid6.UUID)

    def test_ids_are_unique(self):
        """Ensure subsequent calls do not produce the same identifier."""
        id_one = generate_session_id()
        id_two = generate_session_id()
        self.assertNotEqual(id_one, id_two)

    def test_ids_are_chronologically_ordered(self):
        """Confirm UUID v7 property: later IDs are greater than earlier IDs."""
        id_early = generate_session_id()
        id_later = generate_session_id()

        # UUID v7 is lexicographically sortable by time
        self.assertLess(id_early, id_later)
