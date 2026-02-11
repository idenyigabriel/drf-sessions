from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model

from drf_sessions.forms import SessionAdminForm


User = get_user_model()


class SessionAdminFormTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", password="password123"
        )

    def test_initial_absolute_expiry_is_set(self):
        """Ensure a default expiry is calculated for new sessions."""
        form = SessionAdminForm()
        self.assertIn("absolute_expiry", form.fields)
        self.assertIsNotNone(form.fields["absolute_expiry"].initial)
        self.assertTrue(form.fields["absolute_expiry"].initial > timezone.now())

    def test_clean_absolute_expiry_past_fails(self):
        """Validation should prevent setting an expiry in the past."""
        past_date = timezone.now() - timedelta(days=1)
        data = {
            "user": self.user.id,
            "transport": "any",
            "absolute_expiry": past_date,
            "context": {},
        }
        form = SessionAdminForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn("absolute_expiry", form.errors)

    def test_form_excludes_security_fields(self):
        """Internal lifecycle fields should not be in the form fields/html."""
        form = SessionAdminForm()
        protected = ["session_id", "created_at", "revoked_at", "last_activity_at"]
        for field in protected:
            self.assertNotIn(field, form.fields)
