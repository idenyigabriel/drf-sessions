from django.core.checks import Error, register
from drf_sessions.settings import drf_sessions_settings


@register()
def check_cryptography_installed(app_configs, **kwargs):
    errors = []
    algo = drf_sessions_settings.JWT_ALGORITHM

    if algo.startswith(("RS", "ES", "PS")):
        try:
            import cryptography
        except ImportError:
            errors.append(
                Error(
                    f"The algorithm '{algo}' requires the 'cryptography' library.",
                    hint="Install it with 'pip install drf-sessions[crypto]'.",
                    obj="settings.DRF_SESSIONS['JWT_ALGORITHM']",
                    id="drf_sessions.E001",
                )
            )
    return errors
