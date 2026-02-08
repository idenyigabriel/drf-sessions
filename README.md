Here is the complete, production-ready `README.md` for **drf-sessions**. It incorporates the full architecture we've built—from transport binding to stateful session management.

---

```markdown
# drf-sessions

**Enterprise-grade stateful session management for Django REST Framework.**

`drf-sessions` bridges the gap between the portability of **JWTs** and the security of **Stateful Sessions**. It provides a robust architecture for issuing tokens that are cryptographically signed but strictly bound to a database-backed session, allowing for instant revocation, sliding windows, and transport-level security.



---

## 🚀 Key Features

* **Stateful JWTs**: Instant server-side revocation of access tokens via session IDs.
* **Refresh Token Rotation (RTR)**: Every refresh issues a new pair and "burns" the old one, preventing replay attacks.
* **Transport Binding**: Enforce that tokens issued for Cookies cannot be used in Headers (and vice-versa).
* **Session Limits**: Configurable `MAX_SESSIONS_PER_USER` with automatic FIFO (First-In-First-Out) cleanup.
* **Sliding Windows**: Sessions stay alive based on activity, up to a hard absolute "expiry wall."
* **Admin-Ready**: Full Django Admin integration with session history and manual revocation.

---

## 📦 Installation

```bash
pip install drf-sessions

```

Add to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    "drf_sessions",
    "rest_framework",
]

```

---

## 🛠 Configuration

`drf-sessions` follows a "boring and predictable" configuration pattern. Define your settings in `settings.py`:

```python
DRF_SESSIONS = {
    "ACCESS_TOKEN_TTL": timedelta(minutes=15),
    "REFRESH_TOKEN_TTL": timedelta(days=7),
    "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=30),
    "MAX_SESSIONS_PER_USER": 5,
    "ENFORCE_SESSION_TRANSPORT": True,  # Prevent Cookie hijacking in Headers
    "AUTH_COOKIE_NAMES": ("access_token",),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "JWT_ALGORITHM": "HS256",
    "JWT_SIGNING_KEY": settings.SECRET_KEY,
}

```

---

## 🔐 Authentication Usage

Register the authentication classes in your `REST_FRAMEWORK` settings. These classes perform both a cryptographic check and a database state check.

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "drf_sessions.authentication.BearerAuthentication", # For Mobile/Third-party Apps
        "drf_sessions.authentication.CookieAuthentication", # For Web/SPA (HTTP-only)
    ]
}

```

---

## 🎮 View Examples

### 1. The Login View (Issuing Sessions)

The `TokenService` provides human-readable methods for different transport layers.

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_sessions.services import TokenService

class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        user = my_auth_logic(request.data) # Your custom user validation
        
        # Scenario: Web SPA using Secure HTTP-only Cookies
        issued = TokenService.create_cookie_session(user)
        
        response = Response({"detail": "Login successful"})
        response.set_cookie(
            key="access_token",
            value=issued.access_token,
            httponly=True,
            secure=True,
            samesite='Lax'
        )
        return response

```

### 2. Token Refresh (Rotation)

Refresh tokens are one-time use. Rotating a token returns a fresh Access/Refresh pair and updates the session activity.

```python
class TokenRefreshView(APIView):
    permission_classes = []

    def post(self, request):
        raw_refresh = request.data.get("refresh")
        
        # Service handles 'burning' the old token and checking session validity
        new_issued = TokenService.rotate_refresh_token(raw_refresh)
        
        if not new_issued:
            return Response({"error": "Invalid or reused refresh token"}, status=401)

        return Response({
            "access": new_issued.access_token,
            "refresh": new_issued.refresh_token
        })

```

### 3. Logout (Instant Revocation)

Since tokens are stateful, logging out immediately invalidates the JWT across all devices (or just the current one).

```python
class LogoutView(APIView):
    def post(self, request):
        # request.auth is the Session model instance
        session = request.auth 
        session.revoked_at = timezone.now()
        session.save()
        
        return Response(status=204)

```

---

## 🛡 Security Principles

### Transport Binding

If a session is created via `create_cookie_session`, its transport is locked to `COOKIE`. If an attacker steals that JWT and attempts to use it in an `Authorization: Bearer` header, the system will reject it, even if the cryptographic signature is valid. This prevents cross-site token leakage.

### Absolute Expiry Wall

Unlike traditional sliding sessions that could theoretically last forever, `drf-sessions` enforces an `absolute_expiry`. Once the `SLIDING_SESSION_MAX_LIFETIME` is reached from the initial login, the user must re-authenticate.

### FIFO Session Rolling

To prevent database bloat and security risks from stale devices, the `MAX_SESSIONS_PER_USER` setting ensures that when a user logs into a 6th device (if limit is 5), the oldest session is automatically revoked.

---

## 📜 Principles

* **Simple over Complex**: Logic is linear and readable. No "magic" meta-programming.
* **Boring Code**: Follows standard Django and DRF patterns for maximum maintainability.
* **Human Readable**: Explicit naming conventions (e.g., `create_universal_session`) over clever shorthand.

---

## 🏛 Admin Interface

The included Django Admin provides a dashboard to monitor active sessions, view refresh history via Inlines, and manually revoke sessions with a single click.

---

```

### How to use this:
1. Copy the block above into a file named `README.md`.
2. Ensure your directory structure matches the imports (e.g., `drf_sessions.services`).
3. You're ready for PyPI!

Would you like me to help with the `setup.py` or `pyproject.toml` to make it officially installable?

```