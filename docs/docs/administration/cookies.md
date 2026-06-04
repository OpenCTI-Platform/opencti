# Cookies

This page describes how OpenCTI uses browser cookies, what each cookie does, how to configure them, and when they are removed.

## What are cookies used for?

OpenCTI uses cookies exclusively for browser-based interactive sessions.
They are **not** used for API token-based access (e.g., from the Python client `pycti` or the worker, which rely on the `Authorization` header with a bearer token).

Two cookies are used by the platform:

| Cookie name       | Purpose                                                         | Default lifetime                   |
|:------------------|:----------------------------------------------------------------|:-----------------------------------|
| `opencti_session` | Maintains the authenticated user session                        | Configurable (default: 20 minutes) |
| `opencti_flash`   | Displays transient error messages after authentication failures | 10 seconds                         |

## Session cookie (`opencti_session`)

The session cookie is the primary authentication mechanism for browser users.
It is set after a successful login (local credentials, SAML, OpenID Connect, LDAP, or header-based authentication).

### How it works

1. The user authenticates via any configured provider.
1. The server creates a session (stored in Redis or in-memory) and sends the `opencti_session` cookie to the browser.
1. On every subsequent request, the browser sends the cookie back, and the server validates the session.
1. The session lifetime is **rolling** — each request resets the expiry timer.

### Configuration

| Parameter                        | Environment variable               | Default value      | Description                                                                                                                          |
|:---------------------------------|:-----------------------------------|:-------------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| `app:session_timeout`            | `APP__SESSION_TIMEOUT`             | `1200000` (20 min) | Session duration in milliseconds. The session expires after this period of inactivity.                                               |
| `app:session_idle_timeout`       | `APP__SESSION_IDLE_TIMEOUT`        | `0` (disabled)     | Idle timeout in milliseconds. When set to a value greater than 0, the session expires if no activity is detected within this window. |
| `app:session_cookie`             | `APP__SESSION_COOKIE`              | `false`            | When `true`, the cookie has no fixed expiry and is removed when the browser is closed (browser session cookie).                      |
| `app:https_cert:cookie_secure`   | `APP__HTTPS_CERT__COOKIE_SECURE`   | `false`            | When `true`, the cookie is only sent over HTTPS connections. **Set to `true` in production with TLS.**                               |
| `app:https_cert:cookie_samesite` | `APP__HTTPS_CERT__COOKIE_SAMESITE` | `lax`              | Controls the `SameSite` attribute of the cookie. Accepted values: `strict`, `lax`, `none`.                                           |

!!! warning "Production deployment"

    Always set `APP__HTTPS_CERT__COOKIE_SECURE=true` when OpenCTI is served over HTTPS. This prevents the session cookie from being sent over unencrypted connections.

### Example configuration (Docker environment variables)

```bash
APP__SESSION_TIMEOUT=3600000           # 1 hour
APP__SESSION_COOKIE=false
APP__HTTPS_CERT__COOKIE_SECURE=true
APP__HTTPS_CERT__COOKIE_SAMESITE=lax
```

## When are cookies removed?

Cookies are removed in the following scenarios:

- **User logout**: when the user clicks the logout button, the server destroys the session and instructs the browser to delete the cookie.

- **Session expiry**: Once the server-side session is gone, the cookie is effectively invalid — the next request returns an authentication error and the frontend redirects to the login page.

- **Administrative session kill**: administrators can forcefully terminate user sessions from the platform UI or API. This destroys the server-side session, making the cookie invalid on the next request.

- **Browser window or tab closed**: when the `session_cookie: true` configuration is enabled, the cookie is only removed when the user closes the browser window or tab.

## What's next?

- [Configuration](../deployment/configuration.md) — Full platform configuration reference.
- [Authentication](../deployment/authentication.md) — Configure authentication providers.
- [Clustering](../deployment/advanced/clustering.md) — Deploy OpenCTI in a clustered setup (requires `session_manager: shared`).
- [Authentication Strategies](../deployment/authentication.md) — Choose how users log in.
