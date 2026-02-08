import sys

from django.test import SimpleTestCase

from drf_sessions import compat as authentify_typing


class TypingCompatibilityTests(SimpleTestCase):
    def test_expected_types_are_exported(self):
        """Ensure all required types are present in the __all__ declaration."""
        expected_exports = {
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
        }

        # Check that __all__ matches our expected list
        self.assertEqual(set(authentify_typing.__all__), expected_exports)

        # Verify each export is actually reachable on the module
        for name in expected_exports:
            with self.subTest(type_name=name):
                self.assertTrue(hasattr(authentify_typing, name))

    def test_self_type_resolution(self):
        """Verify Self is imported from the correct source based on Python version."""
        if sys.version_info >= (3, 11):
            # In 3.11+, it should come from the standard typing module
            import typing

            self.assertIs(authentify_typing.Self, typing.Self)
        else:
            # Below 3.11, it must come from typing_extensions
            from typing_extensions import Self as TE_Self

            self.assertIs(authentify_typing.Self, TE_Self)
