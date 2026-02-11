# `drf-sessions` Documentation

`drf-sessions` bridges the gap between stateless JWT authentication and stateful session management. Unlike pure JWT solutions, `drf-sessions` maintains a persistent record of each authentication session in your database, enabling instant revocation, session limits, activity tracking, and comprehensive audit trails—all while leveraging the performance benefits of JWT for request authentication.

### Why DRF Sessions?

**Traditional JWT Problems:**
- Cannot revoke tokens before expiration
- No centralized session management
- Limited user context tracking
- No per-user session limits

**DRF Sessions Solutions:**
- ✅ Instant session revocation
- ✅ Database-backed session lifecycle management
- ✅ Flexible context metadata storage
- ✅ Per-user session limits with FIFO eviction
- ✅ Multiple transport layers (Headers/Cookies)
- ✅ Rotating refresh tokens with optional reuse detection
- ✅ Sliding session windows
- ✅ Built-in Django Admin integration
- ✅ Easy customization and feature extensions.

## Requirements

- Python 3.9+
- Django 4.2+
- Django Rest Framework 3.14+
- PyJWT 2.10.0+
- django-swapper 1.3+
- uuid6-python 2025.0.1+

## Installation

```bash
pip install drf-sessions
```

### Cryptographic Dependencies (Optional)

if you are planning on encoding or decoding jwt tokens using certain digital signature algorithms (like RSA or ECDSA), you will need to install the cryptography library. This can be installed explicitly, or as a required extra in the `drf-sessions` requirement:


```bash
pip install drf-sessions[crypto]
```

Add to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'drf_sessions',
    # ...
]
```

Run migrations:

```bash
python manage.py migrate drf_sessions
```

---

## Quick Start

### 1. Configure Settings

Add to your `settings.py`:

```python
from datetime import timedelta

DRF_SESSIONS = {
    'ACCESS_TOKEN_TTL': timedelta(minutes=15),
    'REFRESH_TOKEN_TTL': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'ENFORCE_SINGLE_SESSION': False,
    'MAX_SESSIONS_PER_USER': 5,
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_sessions.auth.BearerAuthentication',
    ),
}
```

### 2. Create a Login View

```python
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from drf_sessions.services import TokenService


class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(username=username, password=password)
        if not user:
            return Response({'error': 'Invalid credentials'}, status=401)
        
        # Create a new header session
        issued = TokenService.create_header_session(
            user=user,
            context={
                'ip_address': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT'),
            }
        )
        
        return Response({
            'access_token': issued.access_token,
            'refresh_token': issued.refresh_token,
        })
```

### 3. Create a Refresh View

```python
class RefreshView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response({'error': 'Refresh token required'}, status=400)
        
        issued = TokenService.rotate_refresh_token(refresh_token)
        
        if not issued:
            return Response({'error': 'Invalid or expired token'}, status=401)
        
        return Response({
            'access_token': issued.access_token,
            'refresh_token': issued.refresh_token,
        })
```

### 4. Protected Endpoint Example

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # request.user contains the authenticated user
        # request.auth contains the session instance
        return Response({
            'username': request.user.username,
            'session_id': str(request.auth.session_id),
            'created_at': request.auth.created_at,
        })
```

---

## Configuration

### Core Settings

All settings are configured in your Django `settings.py` under the `DRF_SESSIONS` dictionary:

```python
DRF_SESSIONS = {
    # Session Lifecycle
    "ACCESS_TOKEN_TTL": timedelta(minutes=15),
    "REFRESH_TOKEN_TTL": timedelta(days=7),
    "SESSION_MODEL": "drf_sessions.Session",
    "ENFORCE_SINGLE_SESSION": False,
    "MAX_SESSIONS_PER_USER": 10,
    "UPDATE_LAST_LOGIN": True,
    "RETAIN_EXPIRED_SESSIONS": False,
    # Sliding Window Logic
    "ENABLE_SLIDING_SESSION": False,
    "SLIDING_SESSION_MAX_LIFETIME": timedelta(days=30),
    # Security Policy
    "AUTH_COOKIE_NAMES": ("token",),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ENFORCE_SESSION_TRANSPORT": True,
    "ROTATE_REFRESH_TOKENS": True,
    "REVOKE_SESSION_ON_REUSE": True,
    "REFRESH_TOKEN_HASH_ALGORITHM": "sha256",
    "LEEWAY": timedelta(seconds=0),
    "RAISE_ON_MISSING_CONTEXT_ATTR": False,
    # JWT Configuration
    "JWT_ALGORITHM": "HS256",
    "JWT_SIGNING_KEY": settings.SECRET_KEY,
    "JWT_VERIFYING_KEY": None,
    "JWT_KEY_ID": None,
    "JWT_AUDIENCE": None,
    "JWT_ISSUER": None,
    "JWT_JSON_ENCODER": None,
    "JWT_HEADERS": {},
    # Claims Mapping
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "sub",
    "SESSION_ID_CLAIM": "sid",
    "JTI_CLAIM": "jti",
    # Extensibility Hooks (Dotted paths to callables)
    "JWT_PAYLOAD_EXTENDER": None,
    "SESSION_VALIDATOR_HOOK": None,
    "POST_AUTHENTICATED_HOOK": None,
}
```

Above, the default values for these settings are shown.

### Session Lifecycle

#### `ACCESS_TOKEN_TTL`
**Type**: `timedelta` or `None`  
**Default**: `timedelta(minutes=15)`

How long access tokens remain valid. Short lifetimes improve security.

```python
DRF_SESSIONS = {
    'ACCESS_TOKEN_TTL': timedelta(minutes=5),
}
```

#### `REFRESH_TOKEN_TTL`
**Type**: `timedelta` or `None`  
**Default**: `timedelta(days=7)`

How long refresh tokens remain valid. Must be longer than `ACCESS_TOKEN_TTL`.

```python
DRF_SESSIONS = {
    'REFRESH_TOKEN_TTL': timedelta(days=7),
}
```

#### `ENFORCE_SINGLE_SESSION`
**Type**: `bool`  
**Default**: `False`

If `True`, only one active session per user is allowed. Creating a new session revokes all previous sessions.

```python
DRF_SESSIONS = {
    'ENFORCE_SINGLE_SESSION': True,  # Force logout from other devices
}
```

#### `MAX_SESSIONS_PER_USER`
**Type**: `int` or `None`  
**Default**: `10`

Maximum number of concurrent sessions per user. Oldest sessions are removed when limit is reached (FIFO). Set to `None` for unlimited sessions.

```python
DRF_SESSIONS = {
    'MAX_SESSIONS_PER_USER': 3,
}
```

#### `UPDATE_LAST_LOGIN`
**Type**: `bool`  
**Default**: `True`

Whether to update the user's `last_login` field when creating a session.

```python
DRF_SESSIONS = {
    'UPDATE_LAST_LOGIN': True,
}
```

#### `RETAIN_EXPIRED_SESSIONS`
**Type**: `bool`  
**Default**: `False`

If `True`, expired sessions are soft-deleted (revoked) for audit purposes. If `False`, they are permanently deleted.

```python
DRF_SESSIONS = {
    'RETAIN_EXPIRED_SESSIONS': True,  # Keep history
}
```

### Sliding Session Window

#### `ENABLE_SLIDING_SESSION`
**Type**: `bool`  
**Default**: `False`

Enable sliding session windows. When enabled, sessions extend their lifetime on each activity. Each refresh token expiry will be extended until the `SLIDING_SESSION_MAX_LIFETIME` is reached.

```python
DRF_SESSIONS = {
    'ENABLE_SLIDING_SESSION': True,
}
```

#### `SLIDING_SESSION_MAX_LIFETIME`
**Type**: `timedelta` or `None`  
**Default**: `timedelta(days=30)`

Maximum lifetime for sliding sessions. Required when `ENABLE_SLIDING_SESSION` is `True`. Must be greater than `REFRESH_TOKEN_TTL`.

```python
DRF_SESSIONS = {
    'ENABLE_SLIDING_SESSION': True,
    'SLIDING_SESSION_MAX_LIFETIME': timedelta(days=90),
}
```

### Security Settings

#### `ENFORCE_SESSION_TRANSPORT`
**Type**: `bool`  
**Default**: `True`

If `True`, sessions created for a specific transport (cookie/header) cannot be used with a different transport. Prevents session hijacking across transport layers.

```python
DRF_SESSIONS = {
    'ENFORCE_SESSION_TRANSPORT': True,
}
```

#### `ROTATE_REFRESH_TOKENS`
**Type**: `bool`  
**Default**: `True`

If `True`, refresh tokens are one-time-use and automatically rotated on each refresh request.

```python
DRF_SESSIONS = {
    'ROTATE_REFRESH_TOKENS': True,
}
```

#### `REVOKE_SESSION_ON_REUSE`
**Type**: `bool`  
**Default**: `True`

If `True`, attempting to reuse a consumed refresh token immediately revokes the entire session. Critical for detecting token theft.

```python
DRF_SESSIONS = {
    'REVOKE_SESSION_ON_REUSE': True,
}
```

#### `REFRESH_TOKEN_HASH_ALGORITHM`
**Type**: `str`  
**Default**: `"sha256"`

Hashing algorithm for refresh tokens. Must be available in Python's `hashlib`.

```python
DRF_SESSIONS = {
    'REFRESH_TOKEN_HASH_ALGORITHM': 'sha256',
}
```

#### `LEEWAY`
**Type**: `timedelta`  
**Default**: `timedelta(seconds=0)`

Clock skew tolerance for JWT validation.

```python
DRF_SESSIONS = {
    'LEEWAY': timedelta(seconds=10),
}
```

#### `AUTH_HEADER_TYPES`
**Type**: `tuple` or `list`  
**Default**: `("Bearer",)`

Accepted authorization header prefixes.

```python
DRF_SESSIONS = {
    'AUTH_HEADER_TYPES': ('Bearer', 'JWT', 'Token'),
}
```

#### `AUTH_COOKIE_NAMES`
**Type**: `tuple` or `list`  
**Default**: `("token",)`

Cookie names to check for authentication tokens.

```python
DRF_SESSIONS = {
    'AUTH_COOKIE_NAMES': ('token', 'access_token', 'auth_token'),
}
```

### JWT Configuration

#### `JWT_ALGORITHM`
**Type**: `str`  
**Default**: `"HS256"`

JWT signing algorithm. Supported: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.

```python
DRF_SESSIONS = {
    'JWT_ALGORITHM': 'RS256',
}
```

#### `JWT_SIGNING_KEY`
**Type**: `str`  
**Default**: `settings.SECRET_KEY`

Secret key for signing JWTs (HMAC) or private key (RSA/ECDSA).

```python
DRF_SESSIONS = {
    'JWT_SIGNING_KEY': 'your-secret-key-here',
}
```

#### `JWT_VERIFYING_KEY`
**Type**: `str` or `None`  
**Default**: `None`

Public key for asymmetric algorithms (RS256, ES256, etc.). Required for asymmetric algorithms.

```python
DRF_SESSIONS = {
    'JWT_ALGORITHM': 'RS256',
    'JWT_VERIFYING_KEY': """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----""",
}
```

#### `JWT_AUDIENCE`
**Type**: `str` or `None`  
**Default**: `None`

JWT audience claim (`aud`).

```python
DRF_SESSIONS = {
    'JWT_AUDIENCE': 'my-api',
}
```

#### `JWT_ISSUER`
**Type**: `str` or `None`  
**Default**: `None`

JWT issuer claim (`iss`).

```python
DRF_SESSIONS = {
    'JWT_ISSUER': 'https://myapp.com',
}
```

#### `JWT_KEY_ID`
**Type**: `str` or `None`  
**Default**: `None`

JWT key identifier header (`kid`).

```python
DRF_SESSIONS = {
    'JWT_KEY_ID': 'key-2024-01',
}
```

#### `JWT_HEADERS`
**Type**: `dict`  
**Default**: `{}`

Additional JWT headers.

```python
DRF_SESSIONS = {
    'JWT_HEADERS': {'typ': 'JWT'},
}
```

#### Claims Mapping

##### `USER_ID_FIELD`
**Type**: `str`  
**Default**: `"id"`

User model field to use as the user identifier.

```python
DRF_SESSIONS = {
    'USER_ID_FIELD': 'uuid',  # If using UUID primary keys
}
```

##### `USER_ID_CLAIM`
**Type**: `str`  
**Default**: `"sub"`

JWT claim name for user identifier.

##### `SESSION_ID_CLAIM`
**Type**: `str`  
**Default**: `"sid"`

JWT claim name for session identifier.

##### `JTI_CLAIM`
**Type**: `str`  
**Default**: `"jti"`

JWT claim name for JWT ID.

### Extensibility Hooks

#### `JWT_PAYLOAD_EXTENDER`
**Type**: `str` (dotted path) or `None`  
**Default**: `None`

Callable to add custom claims to JWT payload.

```python
# myapp/auth.py
def add_custom_claims(session):
    return {
        'role': session.user.role,
        'department': session.user.department,
    }

# settings.py
DRF_SESSIONS = {
    'JWT_PAYLOAD_EXTENDER': 'myapp.auth.add_custom_claims',
}
```

**Function Signature:**
```python
def custom_extender(session: AbstractSession) -> dict:
    """
    Args:
        session: The session instance being encoded
    
    Returns:
        Dictionary of additional claims to include
    """
    pass
```

#### `SESSION_VALIDATOR_HOOK`
**Type**: `str` (dotted path) or `None`  
**Default**: `None`

Callable to validate sessions during authentication. Return `False` to reject.

```python
# myapp/auth.py
def validate_ip_address(session, request):
    """Ensure IP address hasn't changed."""
    stored_ip = session.context_obj.ip_address
    current_ip = request.META.get('REMOTE_ADDR')
    return stored_ip == current_ip

# settings.py
DRF_SESSIONS = {
    'SESSION_VALIDATOR_HOOK': 'myapp.auth.validate_ip_address',
}
```

**Function Signature:**
```python
def custom_validator(session: AbstractSession, request: Request) -> bool:
    """
    Args:
        session: The session being authenticated
        request: The DRF request object
    
    Returns:
        True if session is valid, False to reject authentication
    """
    pass
```

#### `POST_AUTHENTICATED_HOOK`
**Type**: `str` (dotted path) or `None`  
**Default**: `None`

Callable executed after successful authentication. Can modify user or session.

```python
# myapp/auth.py
def update_activity(user, session, request):
    """Update last activity timestamp."""
    session.last_activity_at = timezone.now()
    session.save(update_fields=['last_activity_at'])
    return user, session

# settings.py
DRF_SESSIONS = {
    'POST_AUTHENTICATED_HOOK': 'myapp.auth.update_activity',
}
```

**Function Signature:**
```python
def post_auth_hook(
    user: AbstractBaseUser,
    session: AbstractSession,
    request: Request
) -> Tuple[AbstractBaseUser, AbstractSession]:
    """
    Args:
        user: The authenticated user
        session: The session instance
        request: The DRF request object
    
    Returns:
        Tuple of (user, session) - can return modified instances
    """
    pass
```

#### `RAISE_ON_MISSING_CONTEXT_ATTR`
**Type**: `bool`  
**Default**: `False`

If `True`, accessing missing context attributes raises `AttributeError`. If `False`, returns `None`.

```python
DRF_SESSIONS = {
    'RAISE_ON_MISSING_CONTEXT_ATTR': True,
}

# With True:
session.context_obj.nonexistent  # Raises AttributeError

# With False:
session.context_obj.nonexistent  # Returns None
```

---

## Authentication Classes

DRF Sessions provides two ready-to-use authentication classes:

### BearerAuthentication

Extracts tokens from the `Authorization` header.

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_sessions.auth.BearerAuthentication',
    ),
}
```

**Request Example:**
```
GET /api/profile HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### CookieAuthentication

Extracts tokens from HTTP-only cookies.

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_sessions.auth.CookieAuthentication',
    ),
}
```

**Setting Cookie in Response:**
```python
response = Response({'message': 'Logged in'})
response.set_cookie(
    key='token',
    value=issued.access_token,
    httponly=True,
    secure=True,
    samesite='Strict',
)
```

### Using Both

You can combine both authentication methods:

```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_sessions.auth.BearerAuthentication',
        'drf_sessions.auth.CookieAuthentication',
    ),
}
```

### Custom Authentication Classes

Create custom authentication by subclassing base classes:

```python
from drf_sessions.base.auth import BaseHeaderAuthentication

class CustomHeaderAuth(BaseHeaderAuthentication):
    def extract_token(self, request):
        # Custom extraction logic
        return request.META.get('HTTP_X_AUTH_TOKEN')
```

---

## Session Management

### Creating Sessions

#### Using TokenService

The `TokenService` provides a high-level API for session creation:

```python
from drf_sessions.services import TokenService
from drf_sessions.choices import AUTH_TRANSPORT

# Generic session (works with any transport)
issued = TokenService.create_session(
    user=user,
    context={'device': 'mobile'},
)

# Header-only session
issued = TokenService.create_header_session(
    user=user,
    context={'platform': 'ios'},
)

# Cookie-only session
issued = TokenService.create_cookie_session(
    user=user,
    context={'browser': 'chrome'},
)

# Universal session (explicitly any transport)
issued = TokenService.create_universal_session(
    user=user,
)
```

#### Using Session Manager Directly

```python
from drf_sessions.models import get_token_model

Session = get_token_model()

issued = Session.objects.create_session(
    user=user,
    transport='header',
    context={'ip': request.META.get('REMOTE_ADDR')},
)
```

#### Custom TTLs

Override default token lifetimes per session:

```python
from datetime import timedelta

issued = TokenService.create_session(
    user=user,
    access_ttl=timedelta(minutes=30),
    refresh_ttl=timedelta(days=14),
)
```

### Token Rotation

Refresh tokens to obtain new access tokens:

```python
from drf_sessions.services import TokenService

# In your refresh view
refresh_token = request.data.get('refresh_token')
issued = TokenService.rotate_refresh_token(refresh_token)

if not issued:
    return Response({'error': 'Invalid token'}, status=401)

return Response({
    'access_token': issued.access_token,
    'refresh_token': issued.refresh_token,
})
```

**Rotation Behavior:**

With `ROTATE_REFRESH_TOKENS=True` (default):
- Old refresh token is consumed (marked as used)
- New refresh token is generated and returned
- Attempting to reuse old token triggers reuse detection

With `ROTATE_REFRESH_TOKENS=False`:
- Same refresh token can be used multiple times
- Less secure but simpler for some use cases

### Session Revocation

#### Revoke Single Session

```python
# In a logout view
from drf_sessions.models import get_token_model

Session = get_token_model()

# Revoke current session
request.auth.revoked_at = timezone.now()
request.auth.save()

# Or use QuerySet method
Session.objects.filter(id=request.auth.id).revoke()
```

#### Revoke All User Sessions

```python
# Logout from all devices
Session.objects.filter(user=request.user).active().revoke()
```

#### Revoke Specific Session

```python
# Admin revokes a specific session
session_id = request.data.get('session_id')
Session.objects.filter(session_id=session_id).revoke()
```

#### Query Active Sessions

```python
# Get all active sessions for a user
active_sessions = Session.objects.active().filter(user=request.user)

for session in active_sessions:
    print(f"Session: {session.session_id}")
    print(f"Created: {session.created_at}")
    print(f"Transport: {session.transport}")
    print(f"Device: {session.context_obj.user_agent}")
```

---

## Context Metadata

Store arbitrary metadata with each session using the `context` field:

### Setting Context on Creation

```python
issued = TokenService.create_session(
    user=user,
    context={
        'ip_address': request.META.get('REMOTE_ADDR'),
        'user_agent': request.META.get('HTTP_USER_AGENT'),
        'device_id': request.data.get('device_id'),
        'platform': 'web',
        'location': 'San Francisco',
    }
)
```

### Accessing Context

Context data is available via dot notation through the `context_obj` property:

```python
# In a view
session = request.auth

# Access via dot notation
ip = session.context_obj.ip_address
device = session.context_obj.device_id
platform = session.context_obj.platform

# Missing attributes return None (or raise AttributeError if configured)
missing = session.context_obj.nonexistent  # None

# Raw dict access
raw_context = session.context
```

### Context Validation

The library validates that context is always a dictionary:

```python
# ✅ Valid
context = {'key': 'value', 'nested': {'data': 123}}

# ❌ Invalid - will raise ValidationError
context = ['list', 'not', 'allowed']
context = "string not allowed"
```

### Best Practices

**Security-Sensitive Data:**
```python
context = {
    'ip_address': request.META.get('REMOTE_ADDR'),
    'user_agent': request.META.get('HTTP_USER_AGENT')[:200],  # Truncate
    'device_fingerprint': compute_fingerprint(request),
}
```

**Session Validator Using Context:**
```python
def ip_consistency_validator(session, request):
    """Reject if IP address changed."""
    original_ip = session.context_obj.ip_address
    current_ip = request.META.get('REMOTE_ADDR')
    return original_ip == current_ip

DRF_SESSIONS = {
    'SESSION_VALIDATOR_HOOK': 'myapp.validators.ip_consistency_validator',
}
```

---

## Transport Enforcement

Transport enforcement prevents session hijacking across different delivery methods.

### How It Works

When `ENFORCE_SESSION_TRANSPORT=True` (default), sessions are bound to their creation transport:

```python
# Session created for header transport
issued = TokenService.create_header_session(user=user)

# ✅ Works: Using Authorization header
GET /api/profile
Authorization: Bearer <token>

# ❌ Fails: Trying to use same token in cookie
GET /api/profile
Cookie: token=<same-token>
# AuthenticationFailed: This session is restricted to header transport
```

### Transport Types

```python
from drf_sessions.choices import AUTH_TRANSPORT

# ANY - works with both headers and cookies
AUTH_TRANSPORT.ANY      # 'any'

# HEADER - only Authorization header
AUTH_TRANSPORT.HEADER   # 'header'

# COOKIE - only HTTP cookies
AUTH_TRANSPORT.COOKIE   # 'cookie'
```

### Use Cases

**Mobile Apps (Header-only):**
```python
issued = TokenService.create_header_session(user=user)
# Prevents token theft if attacker gains access to web session
```

**Web Apps (Cookie-only):**
```python
issued = TokenService.create_cookie_session(user=user)
# Prevents XSS attacks from stealing tokens
```

**Hybrid (Flexible):**
```python
issued = TokenService.create_universal_session(user=user)
# Allow same session across web and mobile
```

### Disabling Enforcement

```python
DRF_SESSIONS = {
    'ENFORCE_SESSION_TRANSPORT': False,
}
# Sessions work with any transport, regardless of creation method
```

---

## Django Admin Integration

DRF Sessions includes a comprehensive Django Admin interface for session management.

### Features

- View all sessions with filtering and search
- Inline refresh token display
- Bulk session revocation
- Session status indicators (active/revoked/expired)
- Manual session creation with token display
- Filter by transport, status, and creation date

### Accessing Admin

Navigate to `/admin/drf_sessions/session/` in your Django admin.

### Session List View

**Columns:**
- Session ID
- User
- Transport (header/cookie/any)
- Active status (boolean indicator)
- Created at
- Absolute expiry

**Filters:**
- Status (Active/Revoked/Expired)
- Transport type
- Creation date

**Search:**
- Username
- Email
- Session ID

### Session Detail View

**Read-only Fields:**
- Session ID (UUID)
- Created at
- Revoked at
- Last activity

**Editable Fields:**
- User
- Transport
- Context (JSON editor)
- Absolute expiry

**Inline Tables:**
- Refresh Tokens (with consumption status)

### Bulk Actions

**Revoke Selected Sessions:**
Select multiple sessions and choose "Revoke selected sessions" from the action dropdown.

### Creating Sessions via Admin

1. Click "Add Session"
2. Select user
3. Choose transport type
4. Add context metadata (optional)
5. Save

Upon save:
- Session is created via `TokenService`
- Access token displayed in green message
- Refresh token displayed in blue message (if configured)
- Copy tokens immediately (they won't be shown again)

### RefreshToken Admin

Separate admin interface for deep-diving into refresh tokens:

Navigate to `/admin/drf_sessions/refreshtoken/`

**Columns:**
- Token hash
- Session user
- Valid status (boolean)
- Expires at
- Consumed at

---

## Custom Session Models

DRF Sessions uses Django Swapper to allow custom session models.

### Creating a Custom Model

```python
# myapp/models.py
from drf_sessions.base.models import AbstractSession

class CustomSession(AbstractSession):
    # Add custom fields
    device_name = models.CharField(max_length=100, blank=True)
    is_trusted = models.BooleanField(default=False)
    
    class Meta(AbstractSession.Meta):
        swappable = 'drf_sessions.Session'
```

### Configuring Swapper

```python
# settings.py
DRF_SESSIONS = {
    'SESSION_MODEL': 'myapp.CustomSession',
}
```

### Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Using Custom Model

```python
from drf_sessions.models import get_token_model

Session = get_token_model()  # Returns your CustomSession

# Create session with custom fields
issued = Session.objects.create_session(
    user=user,
    device_name='iPhone 13',
    is_trusted=True,
)

# Access custom fields
session = request.auth
if session.is_trusted:
    # Allow sensitive operations
    pass
```

### RefreshToken Foreign Key

The `RefreshToken` model automatically uses the swapped session model:

```python
# In RefreshToken model
session = models.ForeignKey(
    swapper.get_model_name('drf_sessions', 'Session'),
    on_delete=models.CASCADE,
)
```

---

## Advanced Usage

### Sliding Sessions

Extend session lifetime on each activity:

```python
DRF_SESSIONS = {
    'ENABLE_SLIDING_SESSION': True,
    'REFRESH_TOKEN_TTL': timedelta(days=7),
    'SLIDING_SESSION_MAX_LIFETIME': timedelta(days=30),
}
```

**How it works:**
1. Session created with `absolute_expiry` = now + 30 days
2. User refreshes token after 5 days
3. New refresh token expires in 7 days (capped at absolute_expiry)
4. Session remains valid until absolute_expiry (30 days from creation)

### Reuse Detection

Detect stolen refresh tokens:

```python
DRF_SESSIONS = {
    'ROTATE_REFRESH_TOKENS': True,
    'REVOKE_SESSION_ON_REUSE': True,
}
```

**Scenario:**
1. User refreshes token → gets new token A
2. Attacker steals old token and tries to use it
3. System detects reuse → revokes entire session
4. Both user and attacker are logged out
5. User must re-authenticate

### Custom JWT Claims

Add custom data to access tokens:

```python
# myapp/auth.py
def add_permissions(session):
    user = session.user
    return {
        'permissions': list(user.get_all_permissions()),
        'is_superuser': user.is_superuser,
        'groups': [g.name for g in user.groups.all()],
    }

# settings.py
DRF_SESSIONS = {
    'JWT_PAYLOAD_EXTENDER': 'myapp.auth.add_permissions',
}
```

**Accessing in Views:**
```python
import jwt

def my_view(request):
    # Decode JWT from request (already verified by authentication)
    auth_header = request.META.get('HTTP_AUTHORIZATION', '').split()
    token = auth_header[1] if len(auth_header) == 2 else None
    
    # Get claims (verification already done by DRF)
    claims = jwt.decode(
        token,
        options={"verify_signature": False}  # Already verified
    )
    
    permissions = claims.get('permissions', [])
```

### IP Address Validation

Enforce IP consistency:

```python
# myapp/validators.py
def validate_ip(session, request):
    stored_ip = session.context_obj.ip_address
    current_ip = request.META.get('REMOTE_ADDR')
    
    if not stored_ip:
        return True  # No IP stored, allow
    
    return stored_ip == current_ip

# settings.py
DRF_SESSIONS = {
    'SESSION_VALIDATOR_HOOK': 'myapp.validators.validate_ip',
}

# In your login view, store IP
issued = TokenService.create_session(
    user=user,
    context={'ip_address': request.META.get('REMOTE_ADDR')}
)
```

### Device Fingerprinting

```python
# myapp/utils.py
import hashlib

def compute_fingerprint(request):
    components = [
        request.META.get('HTTP_USER_AGENT', ''),
        request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        request.META.get('HTTP_ACCEPT_ENCODING', ''),
    ]
    raw = '|'.join(components)
    return hashlib.sha256(raw.encode()).hexdigest()

# In your login view
issued = TokenService.create_session(
    user=user,
    context={
        'fingerprint': compute_fingerprint(request),
        'user_agent': request.META.get('HTTP_USER_AGENT'),
    }
)

# Validator
def validate_fingerprint(session, request):
    stored = session.context_obj.fingerprint
    current = compute_fingerprint(request)
    return stored == current
```

### Activity Tracking

Update last activity on each request:

```python
# myapp/middleware.py
from django.utils import timezone

class ActivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Update session activity if authenticated
        if hasattr(request, 'auth') and request.auth:
            request.auth.last_activity_at = timezone.now()
            request.auth.save(update_fields=['last_activity_at'])
        
        return response

# settings.py
MIDDLEWARE = [
    # ...
    'myapp.middleware.ActivityMiddleware',
]
```

### Asymmetric JWT (RS256)

```python
# Generate keys (example using cryptography library)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# settings.py
DRF_SESSIONS = {
    'JWT_ALGORITHM': 'RS256',
    'JWT_SIGNING_KEY': private_pem.decode('utf-8'),
    'JWT_VERIFYING_KEY': public_pem.decode('utf-8'),
}
```

---

## Security Considerations

### Token Storage

**Never store tokens in:**
- localStorage (vulnerable to XSS)
- sessionStorage (vulnerable to XSS)
- Unencrypted databases

**Best practices:**
- Use HTTP-only cookies for web apps
- Store in secure keychain/keystore for mobile apps
- Use `secure=True` and `samesite='Strict'` for cookies

### Token Lifetimes

**Recommendations:**
```python
DRF_SESSIONS = {
    'ACCESS_TOKEN_TTL': timedelta(minutes=15),   # Short-lived
    'REFRESH_TOKEN_TTL': timedelta(days=7),      # Medium-lived
    'SLIDING_SESSION_MAX_LIFETIME': timedelta(days=30),  # Hard limit
}
```

### Transport Security

**Always use HTTPS in production:**
```python
# settings.py (production)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
```

### Refresh Token Rotation

**Always enable rotation:**
```python
DRF_SESSIONS = {
    'ROTATE_REFRESH_TOKENS': True,
    'REVOKE_SESSION_ON_REUSE': True,
}
```

### Session Limits

Prevent session exhaustion attacks:
```python
DRF_SESSIONS = {
    'MAX_SESSIONS_PER_USER': 5,  # Reasonable limit
}
```

### Context Sanitization

**Never store sensitive data in context:**
```python
# ❌ Bad
context = {
    'password': user.password,  # Never!
    'credit_card': '1234-5678-9012-3456',  # Never!
}

# ✅ Good
context = {
    'ip_address': request.META.get('REMOTE_ADDR'),
    'user_agent': request.META.get('HTTP_USER_AGENT')[:200],
    'device_type': 'mobile',
}
```

### Validator Performance

Keep validators fast to avoid request latency:
```python
# ❌ Slow - database queries
def slow_validator(session, request):
    # Avoid heavy database operations
    user_status = UserStatus.objects.get(user=session.user)
    return user_status.is_active

# ✅ Fast - in-memory checks
def fast_validator(session, request):
    # Use cached/in-memory data
    return session.user.is_active
```

---

## API Reference

### TokenService

#### `create_session(user, transport='any', context=None, access_ttl=None, refresh_ttl=None)`

Creates a new authentication session.

**Parameters:**
- `user` (User): The user to authenticate
- `transport` (str): Transport type ('any', 'header', 'cookie')
- `context` (dict): Metadata to store with session
- `access_ttl` (timedelta): Override default access token TTL
- `refresh_ttl` (timedelta): Override default refresh token TTL

**Returns:** `IssuedSession(access_token, refresh_token, session)`

#### `create_header_session(user, context=None, access_ttl=None, refresh_ttl=None)`

Creates a header-only session. Shortcut for `create_session` with `transport='header'`.

#### `create_cookie_session(user, context=None, access_ttl=None, refresh_ttl=None)`

Creates a cookie-only session. Shortcut for `create_session` with `transport='cookie'`.

#### `create_universal_session(user, context=None, access_ttl=None, refresh_ttl=None)`

Creates a universal session. Shortcut for `create_session` with `transport='any'`.

#### `rotate_refresh_token(raw_refresh_token)`

Exchanges a refresh token for new credentials.

**Parameters:**
- `raw_refresh_token` (str): The refresh token to rotate

**Returns:** `IssuedSession` or `None` if invalid/expired

### SessionManager

#### `create_session(user, transport, context=None, access_ttl=None, refresh_ttl=None, **kwargs)`

Low-level session creation. See `TokenService.create_session`.

#### `active()`

Returns QuerySet of active (non-revoked, non-expired) sessions.

```python
Session.objects.active()
```

#### `revoke()`

Revokes all sessions in the QuerySet.

```python
Session.objects.filter(user=user).revoke()
```

### Session Model

#### Properties

##### `session_id`
UUID v7 unique identifier

##### `user`
ForeignKey to User model

##### `transport`
String: 'any', 'header', or 'cookie'

##### `context`
JSONField for metadata storage

##### `context_obj`
ContextParams wrapper for dot-notation access

##### `last_activity_at`
DateTime of last token refresh

##### `revoked_at`
DateTime of revocation (None if active)

##### `absolute_expiry`
DateTime of hard expiration (None if no limit)

##### `is_active`
Boolean property: True if not revoked and not expired

#### Methods

##### `__str__()`
Returns: `"username (session-id)"`

### RefreshToken Model

#### Properties

##### `token_hash`
SHA-256 hash of the raw token

##### `session`
ForeignKey to Session

##### `expires_at`
DateTime when token expires

##### `consumed_at`
DateTime when token was used (None if unused)

##### `is_expired`
Boolean property: True if past expires_at

### ContextParams

#### Methods

##### `__getattr__(name)`
Dot-notation access to context data

```python
session.context_obj.ip_address  # Returns value or None
```

##### `__repr__()`
Returns string representation of context

### IssuedSession

NamedTuple containing new session credentials.

**Fields:**
- `access_token` (str): JWT access token
- `refresh_token` (str | None): Refresh token (None if REFRESH_TOKEN_TTL is None)
- `session` (AbstractSession): The database session instance

---

## Migration Guide

### From Simple JWT

DRF Sessions is designed to complement or replace django-rest-framework-simplejwt.

**Key Differences:**

| Feature | Simple JWT | DRF Sessions |
|---------|-----------|--------------|
| Storage | Stateless | Database-backed |
| Revocation | Token blacklist | Session revocation |
| Session Limits | None | FIFO session limits |
| Context Storage | None | JSON metadata |
| Transport Binding | None | Enforced transport types |
| Admin Interface | Minimal | Full-featured |

**Migration Steps:**

1. **Install DRF Sessions:**
```bash
pip install drf-sessions
```

2. **Update Settings:**
```python
# Before (Simple JWT)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
}

# After (DRF Sessions)
DRF_SESSIONS = {
    'ACCESS_TOKEN_TTL': timedelta(minutes=5),
    'REFRESH_TOKEN_TTL': timedelta(days=1),
}
```

3. **Update Authentication Classes:**
```python
# Before
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

# After
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_sessions.auth.BearerAuthentication',
    ),
}
```

4. **Update Views:**
```python
# Before (Simple JWT)
from rest_framework_simplejwt.views import TokenObtainPairView

# After (DRF Sessions)
from drf_sessions.services import TokenService

class LoginView(APIView):
    def post(self, request):
        user = authenticate(...)
        issued = TokenService.create_session(user=user)
        return Response({
            'access': issued.access_token,
            'refresh': issued.refresh_token,
        })
```

5. **Run Migrations:**
```bash
python manage.py migrate drf_sessions
```

### From Session Authentication

If migrating from DRF's built-in session authentication:

**Advantages of DRF Sessions:**
- No CSRF tokens needed (JWT-based)
- Works seamlessly with mobile apps
- Better horizontal scaling (stateless access tokens)
- Explicit session lifecycle management

**Migration Steps:**

1. **Dual Authentication (Transition Period):**
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drf_sessions.auth.BearerAuthentication',
        'rest_framework.authentication.SessionAuthentication',  # Keep temporarily
    ),
}
```

2. **Create Migration Endpoint:**
```python
class MigrateSessionView(APIView):
    """Allow users to convert session auth to JWT."""
    authentication_classes = [SessionAuthentication]
    
    def post(self, request):
        issued = TokenService.create_session(user=request.user)
        return Response({
            'access_token': issued.access_token,
            'refresh_token': issued.refresh_token,
        })
```

3. **Update Frontend:**
- Store tokens in secure storage
- Add Authorization header to requests
- Implement token refresh logic

4. **Remove Old Authentication:**
Once all clients migrated, remove SessionAuthentication.

---

## Troubleshooting

### Common Issues

#### "Invalid access token"

**Cause:** Token expired or signature invalid

**Solutions:**
- Check `ACCESS_TOKEN_TTL` setting
- Verify `JWT_SIGNING_KEY` hasn't changed
- Implement token refresh flow

#### "Session is invalid or has been revoked"

**Cause:** Session deleted or explicitly revoked

**Solutions:**
- Check session still exists in database
- Verify `revoked_at` is None
- Check `absolute_expiry` hasn't passed

#### "Token missing session identifier"

**Cause:** JWT doesn't contain session ID claim

**Solutions:**
- Verify token was created by DRF Sessions
- Check `SESSION_ID_CLAIM` setting matches token

#### Import Error: "Cannot import name 'Session'"

**Cause:** Swapper configuration issue

**Solutions:**
```python
# Use get_token_model() instead of direct import
from drf_sessions.models import get_token_model

Session = get_token_model()
```

#### "This session is restricted to X transport"

**Cause:** Transport enforcement preventing cross-transport usage

**Solutions:**
- Use correct authentication class for session type
- Or set `ENFORCE_SESSION_TRANSPORT=False`
- Or create universal sessions with `create_universal_session()`

### Performance Optimization

#### Database Queries

Add select_related for better query performance:

```python
session = Session.objects.select_related('user').get(session_id=sid)
```

#### Indexing

DRF Sessions includes optimized indexes. Ensure migrations are applied:

```bash
python manage.py migrate drf_sessions
```

#### Cleanup Old Sessions

Create periodic task to delete expired sessions:

```python
from django.utils import timezone
from drf_sessions.models import get_token_model

Session = get_token_model()

# Delete expired sessions
Session.objects.filter(
    absolute_expiry__lt=timezone.now()
).delete()

# Or revoke instead of delete
Session.objects.filter(
    absolute_expiry__lt=timezone.now(),
    revoked_at__isnull=True
).revoke()
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/drf-sessions.git
cd drf-sessions
pip install -e ".[dev]"
python manage.py migrate
python manage.py test
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- Inspired by [django-rest-framework-simplejwt](https://github.com/jazzband/djangorestframework-simplejwt)
- Built on [Django Rest Framework](https://www.django-rest-framework.org/)
- Uses [PyJWT](https://pyjwt.readthedocs.io/) for JWT handling
- UUID v7 support via [uuid6-python](https://github.com/oittaa/uuid6-python)

---

## Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/drf-sessions/issues)
- **Documentation:** [Read the Docs](https://drf-sessions.readthedocs.io/)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/drf-sessions/discussions)

---

## Changelog

### Version 1.0.0 (2024-XX-XX)

Initial release with:
- Database-backed session management
- JWT access tokens with rotating refresh tokens
- Multiple transport layer support (headers/cookies)
- Transport enforcement for security
- Session limits and FIFO eviction
- Context metadata storage
- Sliding session windows
- Reuse detection
- Django Admin integration
- Swappable session models
- Extensibility hooks
- Comprehensive test coverage