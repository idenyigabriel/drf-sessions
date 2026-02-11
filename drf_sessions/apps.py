from django.apps import AppConfig


class DrfSessionsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "drf_sessions"

    def ready(self):
        import drf_sessions.checks
