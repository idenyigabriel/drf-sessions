import uuid6
from django.test import SimpleTestCase

from drf_sessions.utils.generators import generate_session_id


class TestSessionIdentifier(SimpleTestCase):
    def test_returns_correct_uuid_type(self):
        session_id = generate_session_id()
        self.assertIsInstance(session_id, uuid6.UUID)

    def test_ids_are_unique(self):
        id_one = generate_session_id()
        id_two = generate_session_id()
        self.assertNotEqual(id_one, id_two)

    def test_ids_are_chronologically_ordered(self):
        id_early = generate_session_id()
        id_later = generate_session_id()

        # UUID v7 is lexicographically sortable by time
        self.assertLess(id_early, id_later)
