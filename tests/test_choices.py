from django.db import models
from django.test import SimpleTestCase

from drf_sessions.choices import AUTH_TRANSPORT


class AuthTransportChoicesTests(SimpleTestCase):
    def test_member_attributes_count(self):
        self.assertEqual(len(AUTH_TRANSPORT.values), 3)

    def test_member_attributes(self):
        self.assertEqual(AUTH_TRANSPORT.ANY, "any")
        self.assertEqual(AUTH_TRANSPORT.HEADER, "header")
        self.assertEqual(AUTH_TRANSPORT.COOKIE, "cookie")

    def test_database_values(self):
        expected_values = {"any", "cookie", "header"}
        self.assertEqual(set(AUTH_TRANSPORT.values), expected_values)

    def test_human_readable_labels(self):
        expected_labels = {"Any", "Cookie", "Header"}
        self.assertEqual(set(AUTH_TRANSPORT.labels), expected_labels)

    def test_choices_tuple(self):
        expected_choices = {("any", "Any"), ("cookie", "Cookie"), ("header", "Header")}
        self.assertEqual(set(AUTH_TRANSPORT.choices), expected_choices)

    def test_parent_instance(self):
        self.assertTrue(issubclass(AUTH_TRANSPORT, models.TextChoices))
