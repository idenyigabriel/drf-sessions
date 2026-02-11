from django.test import SimpleTestCase
from django.core.exceptions import ValidationError

from drf_sessions.validators import validate_context


class ContextValidatorTest(SimpleTestCase):

    def test_valid_context_passes(self):
        try:
            validate_context({"ip": "127.0.0.1", "user_agent": "Mozilla/5.0"})
        except ValidationError:
            self.fail("validate_context raised ValidationError unexpectedly!")

    def test_invalid_types_raise_error(self):
        invalid_inputs = ["string", (1, 2), True, ["list", "item"], 123, None]

        for value in invalid_inputs:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError) as cm:
                    validate_context(value)

                self.assertEqual(cm.exception.code, "invalid_context_type")
