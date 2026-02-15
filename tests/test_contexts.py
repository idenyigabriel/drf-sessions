from django.test import SimpleTestCase, override_settings

from drf_sessions.contexts import ContextParams


class ContextParamsTests(SimpleTestCase):

    def test_initialization_with_valid_dict(self):
        context = ContextParams({"user_id": 1, "scope": "read"})
        self.assertEqual(context.user_id, 1)
        self.assertEqual(context.scope, "read")

    def test_initialization_raises_type_error(self):
        for data in ["string", 123, (1, 2, 4), [1, 2, 3], None]:
            with self.assertRaises(TypeError):
                ContextParams(data)

    def test_immutability_enforced(self):
        context = ContextParams({"key": "value"})

        with self.assertRaises(TypeError):
            context.key = "new_value"

        with self.assertRaises(TypeError):
            del context.key

    def test_slots_usage(self):
        context = ContextParams({"a": 1})
        self.assertFalse(hasattr(context, "__dict__"))

        # Verify only _data is allowed
        self.assertEqual(context.__slots__, ("_data",))

    @override_settings(DRF_SESSIONS={"RAISE_ON_MISSING_CONTEXT_ATTR": True})
    def test_missing_attribute_raises_error(self):
        context = ContextParams({"existing": "val"})
        with self.assertRaisesMessage(
            AttributeError, "Context has no parameter 'missing'"
        ):
            context.missing

    @override_settings(DRF_SESSIONS={"RAISE_ON_MISSING_CONTEXT_ATTR": False})
    def test_missing_attribute_returns_none(self):
        context = ContextParams({"existing": "val"})
        self.assertIsNone(context.missing)

    def test_internal_attribute_protection(self):
        # '_hidden' is not a slot, so it will trigger __getattr__
        context = ContextParams({"_hidden": "secret", "normal": "public"})

        # This SHOULD raise AttributeError because of your 'name.startswith("_")' check
        with self.assertRaises(AttributeError):
            context._hidden

        self.assertEqual(context.normal, "public")

    def test_slot_is_accessible(self):
        data = {"id": 1}
        context = ContextParams(data)
        self.assertEqual(context._data, data)

    def test_repr_output(self):
        data = {"id": 123}
        context = ContextParams(data)
        self.assertEqual(repr(context), f"ContextParams({data!r})")
