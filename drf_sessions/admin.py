"""
Django Admin interface for authentication sessions.
"""

from swapper import load_model
from django.contrib import admin
from django.utils import timezone
from django.contrib import messages
from django.utils.translation import gettext_lazy as _

from drf_sessions.services import SessionService
from drf_sessions.models import get_token_model
from drf_sessions.forms import SessionAdminForm

Session = get_token_model()
RefreshToken = load_model("drf_sessions", "RefreshToken")


class RefreshTokenInline(admin.TabularInline):
    """Allows viewing refresh tokens directly inside the Session admin."""

    extra = 0
    can_delete = True
    model = RefreshToken
    readonly_fields = ["token_hash", "created_at", "consumed_at", "expires_at"]

    def has_add_permission(self, request, obj=None):
        return False  # Tokens should be created via Service/Rotation logic


class SessionStatusFilter(admin.SimpleListFilter):
    title = _("Status")
    parameter_name = "status"

    def lookups(self, request, model_admin):
        return [
            ("active", _("Active")),
            ("revoked", _("Revoked")),
            ("expired", _("Expired")),
        ]

    def queryset(self, request, queryset):
        if self.value() == "active":
            return queryset.active()
        if self.value() == "revoked":
            return queryset.filter(revoked_at__isnull=False)
        if self.value() == "expired":
            return queryset.filter(
                absolute_expiry__isnull=False,
                absolute_expiry__lte=timezone.now(),
            )
        return queryset


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    form = SessionAdminForm
    list_display = [
        "session_id",
        "user",
        "transport",
        "is_active",
        "created_at",
        "absolute_expiry",
    ]
    list_filter = [SessionStatusFilter, "transport", "created_at"]
    search_fields = ["user__username", "user__email", "session_id"]
    raw_id_fields = ["user"]
    inlines = [RefreshTokenInline]
    readonly_fields = ["session_id", "created_at", "revoked_at", "last_activity_at"]
    actions = ["revoke_sessions"]

    def is_active(self, obj):
        if obj.revoked_at:
            return False
        return obj.absolute_expiry is None or obj.absolute_expiry > timezone.now()

    is_active.boolean = True

    @admin.action(description=_("Revoke selected sessions"))
    def revoke_sessions(self, request, queryset):
        count = queryset.revoke()
        self.message_user(request, _(f"{count} sessions were successfully revoked."))

    def save_model(self, request, obj, form, change):
        if not change:
            # We use the form's cleaned data for absolute_expiry if manually set
            issued = SessionService.create_session(
                user=obj.user,
                transport=obj.transport,
                context=obj.context,
                # Note: SessionManager will calculate its own expiry,
                # but you could pass form.cleaned_data['absolute_expiry'] if desired.
            )

            messages.success(request, _("Session created successfully."))
            messages.info(request, f"🗝 Access Token: {issued.access_token}")
            if issued.refresh_token:
                messages.info(request, f"🔄 Refresh Token: {issued.refresh_token}")

            # Prevent the default save because create_session already created it
            return
        super().save_model(request, obj, form, change)
