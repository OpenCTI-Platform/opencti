# Focus on security configuration for your deployment

For an easy first user experience or to avoid breaking changes, OpenCTI is configured with a default security configuration that is not strict.
However, for production deployment, it is recommended to review and adapt the security configuration of your platform.

The full list of configuration can be found in the [configuration page](../configuration.md).

## Rate limiting

OpenCTI includes a built-in rate limiting mechanism to protect the platform from abuse and ensure fair usage.
If there is no component in your infrastructure to handle rate limiting, consider using the built-in mechanism of OpenCTI to protect your platform.

More information about rate limiting configuration can be found in the [dedicated documentation page](rate-limiting.md).

## Public dashboards authorized domains

To prevent your public dashboards from being embedded in unauthorized websites, you can configure the list of authorized domains (`app:public_dashboard_authorized_domains`).

## Unsecure HTTP resources

For a fully secure platform, you should disable the loading of unsecure (HTTP) resources by setting `app:allow_unsecure_http_resources` to `false`.

## Session timeout

To ensure that user sessions are not kept alive indefinitely, you should configure a session timeout (`app:session_timeout`) that matches your security policy.

More information can be found in the [dedicated documentation](../../administration/cookies.md).

## Logs redaction

To avoid leaking sensitive information in your logs, you can configure the list of GraphQL input fields that should be redacted (`app:app_logs:logs_redacted_inputs`).

More information can be found in the [configuration page](../configuration.md#errors).

## Audit request headers

To enhance your audit logs, you can specify a list of HTTP headers to be included in the trace (`app:audit_logs:trace_request_headers`).

More information can be found in the [configuration page](../configuration.md#audit).

## Ingestion URL filtering

To protect your platform against SSRF (Server-Side Request Forgery), you can define a list of URIs that should be blocked for all ingestion feeds (`ingestion_manager:uri_deny_list`).

More information can be found in the [advanced feed configuration page](../../usage/import/advanced-feed-configuration.md).

## Artifact encryption password

When handling potentially malicious files (artifacts), OpenCTI uses an encrypted ZIP format. You can change the password used for these archives (`app:artifact_zip_password`).

More information can be found in the [configuration page](../configuration.md#functional-customization).
