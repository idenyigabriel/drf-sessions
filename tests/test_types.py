from unittest.mock import MagicMock

from django.test import SimpleTestCase

from drf_sessions.types import IssuedSession
from drf_sessions.base.models import AbstractSession


class IssuedSessionTest(SimpleTestCase):
    def setUp(self):
        self.mock_session = MagicMock(spec=AbstractSession)

    def test_initialization_with_all_fields(self):
        issued = IssuedSession(
            access_token="access", refresh_token="refresh", session=self.mock_session
        )
        self.assertEqual(issued.access_token, "access")
        self.assertEqual(issued.refresh_token, "refresh")
        self.assertEqual(issued.session, self.mock_session)

    def test_initialization_with_optional_refresh_token(self):
        issued = IssuedSession(
            access_token="access", refresh_token=None, session=self.mock_session
        )
        self.assertIsNone(issued.refresh_token)
        self.assertEqual(issued.access_token, "access")
        self.assertEqual(issued.session, self.mock_session)
