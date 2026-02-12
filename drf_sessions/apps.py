from django.apps import AppConfig


class DrfSessionsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "drf_sessions"

    def ready(self):
        # run extra user configuration checks
        import drf_sessions.checks  # noqa: F401

        # register admin if none has been registered by the user
        # by loading this here, we ensure all admin.py files have been loaded first
        # and so user custom defined admin should be better detected, and
        # we should have to worry about the order in which the app appears
        # in INSTALLED_APPS
        from django.contrib import admin
        from drf_sessions.admin import SessionAdmin, RefreshTokenAdmin
        from drf_sessions.models import get_session_model, RefreshToken

        SessionModel = get_session_model()

        if not admin.site.is_registered(SessionAdmin):
            admin.site.register(SessionModel, SessionAdmin)

        if not admin.site.is_registered(RefreshToken):
            admin.site.register(RefreshToken, RefreshTokenAdmin)
