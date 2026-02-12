"""
Django Admin configurations for session management and refresh tokens.

Provides filtered views for monitoring session health, manual revocation
capabilities, and direct links between sessions and their related tokens.
"""

from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.http import HttpRequest
from django.db.models import QuerySet
from django.utils.html import format_html
from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.template.defaultfilters import truncatechars

from drf_sessions.services import SessionService
from drf_sessions.utils.tokens import generate_refresh_token
from drf_sessions.models import RefreshToken, get_session_model
from drf_sessions.forms import RefreshTokenAdminForm, SessionAdminForm


SessionModel = get_session_model()


class SessionStatusFilter(admin.SimpleListFilter):
    """Filters sessions by their current lifecycle state."""

    title = _("Status")
    parameter_name = "status"

    def lookups(self, request, model_admin):
        return [
            ("active", _("Active")),
            ("revoked", _("Revoked")),
            ("expired", _("Expired")),
        ]

    def queryset(self, request, queryset):
        now = timezone.now()
        if self.value() == "active":
            return queryset.active()
        if self.value() == "revoked":
            return queryset.filter(revoked_at__isnull=False)
        if self.value() == "expired":
            return queryset.filter(absolute_expiry__lte=now)
        return queryset


class RefreshTokenStatusFilter(admin.SimpleListFilter):
    """Filters refresh tokens based on usage and expiration."""

    title = _("Status")
    parameter_name = "status"

    def lookups(self, request, model_admin):
        return [
            ("active", _("Active")),
            ("expired", _("Expired")),
            ("consumed", _("Consumed")),
        ]

    def queryset(self, request, queryset):
        now = timezone.now()
        if self.value() == "active":
            return queryset.filter(expires_at__gt=now, consumed_at__isnull=True)
        if self.value() == "expired":
            return queryset.filter(expires_at__lte=now)
        if self.value() == "consumed":
            return queryset.filter(consumed_at__isnull=False)
        return queryset


class SessionAdmin(admin.ModelAdmin):
    form = SessionAdminForm
    raw_id_fields = ["user"]
    actions = ["revoke_sessions"]
    readonly_fields = ["session_id", "created_at"]
    search_fields = (f"user__{get_user_model().USERNAME_FIELD}",)
    list_filter = [SessionStatusFilter, "transport", "created_at"]
    list_display = (
        "session_id",
        "user",
        "transport",
        "is_active",
        "created_at",
        "absolute_expiry",
        "revoked_at",
        "view_refresh_tokens",
    )

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("user")
            .annotate(refresh_token_count=models.Count("refresh_tokens"))
        )

    @admin.display(boolean=True, description=_("Is Active"))
    def is_active(self, obj):
        return obj.revoked_at is None and (
            obj.absolute_expiry is None or obj.absolute_expiry > timezone.now()
        )

    @admin.display(description=_("Refresh Tokens"))
    def view_refresh_tokens(self, obj):
        if not obj or not obj.id:
            return "-"

        opts = RefreshToken._meta
        url = reverse(f"admin:{opts.app_label}_{opts.model_name}_changelist")
        query_url = f"{url}?session_id={obj.id}"
        count = getattr(obj, "refresh_token_count", 0)

        return format_html(
            '<a class="button" href="{}">🔍 View {} Token(s)</a>', query_url, count
        )

    @admin.action(description=_("Revoke selected sessions"))
    def revoke_sessions(self, request, queryset):
        count = queryset.revoke()
        self.message_user(request, _(f"{count} sessions were successfully revoked."))

    def save_model(self, request, obj, form, change):
        if not change:
            # Creation is handled by the service to ensure logic consistency
            issued = SessionService.create_session(
                user=obj.user, transport=obj.transport, context=obj.context
            )
            messages.info(request, f"🗝 Access Token: {issued.access_token}")
            if issued.refresh_token:
                messages.info(request, f"🔄 Refresh Token: {issued.refresh_token}")

            # This is needed for save and continue to add redirect feature.
            obj.pk = issued.session.id

            # since service create_session, creates the actual session
            # we return here to skip another save logic from running.
            return

        super().save_model(request, obj, form, change)


class RefreshTokenAdmin(admin.ModelAdmin):
    form = RefreshTokenAdminForm
    readonly_fields = ["token_hash"]
    autocomplete_fields = ["session"]
    actions = ["expire_tokens", "consume_tokens"]
    list_filter = [RefreshTokenStatusFilter, "created_at"]
    list_display = ["_token_hash", "session", "created_at", "consumed_at", "expires_at"]

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("session", "session__user")

    @admin.display(description=_("Token Hash"), ordering="token_hash")
    def _token_hash(self, obj):
        return format_html(
            '<span title="{}">{}</span>',
            obj.token_hash,
            truncatechars(obj.token_hash, 15),
        )

    @admin.action(description=_("Revoke selected Refresh Tokens"))
    def expire_tokens(self, request: HttpRequest, queryset: QuerySet):
        count = queryset.update(expires_at=timezone.now())
        self.message_user(request, _(f"{count} tokens were successfully revoked."))

    @admin.action(description=_("Consume selected Refresh Tokens"))
    def consume_tokens(self, request: HttpRequest, queryset: QuerySet):
        count = queryset.update(consumed_at=timezone.now())
        self.message_user(request, _(f"{count} tokens were successfully consumed."))

    def changelist_view(self, request, extra_context=None):
        """Adds a navigation link when filtered by a specific session."""
        extra_context = extra_context or {}
        session_id = request.GET.get("session_id")

        if session_id:
            opts = SessionModel._meta
            url = reverse(
                f"admin:{opts.app_label}_{opts.model_name}_change", args=[session_id]
            )
            extra_context["back_to_session_link"] = format_html(
                '<a class="historylink" href="{}">⬅ Back to Session</a>', url
            )

        return super().changelist_view(request, extra_context=extra_context)

    def save_model(self, request, obj, form, change):
        if not change:
            raw, hashed = generate_refresh_token()
            obj.token_hash = hashed
            messages.info(request, f"🔄 Refresh Token: {raw}")
        super().save_model(request, obj, form, change)
