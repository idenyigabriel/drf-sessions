"""
Django Admin interface for authentication sessions.
"""

from swapper import load_model
from django.contrib import admin
from django.utils import timezone
from django.contrib import messages
from django.utils.translation import gettext_lazy as _

from drf_sessions.models import get_token_model
from drf_sessions.forms import SessionAdminForm
from drf_sessions.services import TokenService

Session = get_token_model()
RefreshToken = load_model("drf_sessions", "RefreshToken")


class RefreshTokenInline(admin.TabularInline):
    """Allows viewing refresh tokens directly inside the Session admin."""

    model = RefreshToken
    extra = 0
    readonly_fields = ["token_hash", "created_at", "consumed_at", "expires_at"]
    can_delete = True

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
            return queryset.filter(absolute_expiry__lte=timezone.now())
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
    readonly_fields = ["last_activity_at"]

    def is_active(self, obj):
        return obj.revoked_at is None and obj.absolute_expiry > timezone.now()

    is_active.boolean = True
    is_active.short_description = _("Active")

    def save_model(self, request, obj, form, change):
        """
        If creating a session, use TokenService to generate initial tokens.
        """
        if not change:
            # Use the service to handle the "FIFO" limits and token generation
            issued = TokenService.create_session(
                user=obj.user,
                transport=obj.transport,
                context=obj.context,
                # absolute_expiry is handled by the form/manager
            )

            # Display tokens to admin once
            messages.success(request, _("Session created successfully."))
            messages.info(request, f"🗝 Access Token: {issued.access_token}")
            if issued.refresh_token:
                messages.info(request, f"🔄 Refresh Token: {issued.refresh_token}")
        else:
            super().save_model(request, obj, form, change)


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    """Separate admin for deep-diving into specific refresh tokens."""

    list_display = [
        "token_hash",
        "session_user",
        "is_valid",
        "expires_at",
        "consumed_at",
    ]
    readonly_fields = ["session", "token_hash", "created_at"]
    list_filter = ["consumed_at", "created_at"]

    def session_user(self, obj):
        return obj.session.user

    def is_valid(self, obj):
        return obj.consumed_at is None and obj.expires_at > timezone.now()

    is_valid.boolean = True
