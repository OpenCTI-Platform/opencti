# SMTP configuration

## What is it?

The SMTP configuration page (Settings > Security > SMTP configuration) lets platform administrators configure outbound email sending directly from the OpenCTI interface — without editing backend configuration files or restarting the platform.

## Why use it?

Configuring SMTP from the interface has several advantages:

- Changes take effect immediately, without a deployment restart.
- Credentials are encrypted and stored securely in the database.
- Supports both Basic and OAuth2 authentication.

The interface configuration takes priority over the backend JSON/environment-variable configuration when the **Use configuration in interface** toggle is enabled.

## Page states

The page has three possible states depending on the platform configuration.

### Interface configuration disabled by the administrator

When the `smtp:forced_sender_email` backend parameter is set, the platform administrator has locked the SMTP sender address at the infrastructure level. In this case:

- The configuration table is displayed in read-only (greyed out).
- The **Update** button is not available.
- A warning message is displayed: *Your platform administrator has disabled this feature. You cannot configure a new SMTP configuration within the interface.*

To re-enable interface configuration, remove `smtp:forced_sender_email` from the backend configuration and restart the platform.

### Interface configuration not yet activated (`Use configuration in interface` disabled)

When `smtp:forced_sender_email` is not set but the **Use configuration in interface** toggle is disabled, the platform is using the backend JSON/env configuration. In this case:

- An info message is displayed: *Currently, the SMTP is configured via a backend configuration. To change your configuration, simply enable the usage of the Interface configuration & define your SMTP configuration in this screen.*
- The **Update** button is available. Open it to enable the toggle and fill in your SMTP settings.

### Interface configuration active (`Use configuration in interface` enabled)

When the interface configuration is active, the table displays all current SMTP settings and the following buttons are available:

- **Update** — open the configuration drawer to edit the settings.
- **Test** — send a test email to verify the configuration.

## Configuration fields

| Field | Description |
|:------|:------------|
| SMTP enabled | Globally enables or disables outbound email sending |
| Use configuration in interface | When enabled, the interface configuration overrides the backend config |
| Sender email address | The `From:` address used for all outbound emails |
| Hostname | SMTP server hostname |
| Port | SMTP server port |
| Use SSL/TLS | Enable SSL/TLS encryption |
| Reject unauthorized certificates | Reject connections with invalid TLS certificates |
| Authentication type | `basic` (username/password) or `oauth2` |
| Username | SMTP username — Basic auth only |
| Password | SMTP password — Basic auth only (stored encrypted) |
| OAuth user | Email address of the SMTP mailbox — OAuth2 only |
| OAuth client ID | OAuth2 client ID — stored encrypted |
| OAuth issuer | OIDC issuer URL used for token discovery and refresh |
| Refresh token expiration date | Expiry date of the OAuth2 refresh token |

!!! warning "Port 25 is blocked"

    Port 25 is not allowed in the interface configuration. Use port 465 (SSL/TLS) or 587 (STARTTLS) instead.

!!! note "OAuth2 authentication"

    The OAuth2 flow uses the **Refresh Token Grant**. OpenCTI automatically refreshes the access token before each email is sent. Refer to [SMTP Service configuration](../deployment/configuration.md#smtp-service) for provider-specific notes (Microsoft 365, Google Workspace, etc.).

## What's next?

- [SMTP Service — backend configuration parameters](../deployment/configuration.md#smtp-service)
- [Notifiers](notifiers.md) — configure notification channels that use SMTP
- [Email templates](email-templates.md) — customize the email content sent by the platform
