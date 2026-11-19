# Proxy Support

## Overview

XTM Composer can use a proxy for outgoing network calls. Proxy settings are defined for each platform, under `opencti` or `openaev`, and apply only when `with_proxy` is `true`.

### YAML configuration

```yaml
opencti:
  with_proxy: true
  http_proxy: http://proxy.example.com:8080
  https_proxy: http://proxy.example.com:8080
  no_proxy: localhost,127.0.0.1,.example.com
```

### Environment variable configuration

```bash
export OPENCTI__WITH_PROXY="true"
export OPENCTI__HTTP_PROXY="http://proxy.example.com:8080"
export OPENCTI__HTTPS_PROXY="http://proxy.example.com:8080"
export OPENCTI__NO_PROXY="localhost,127.0.0.1,.example.com"
```

When enabled, XTM Composer forwards these proxy settings to managed connector containers as `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.

The settings apply differently to XTM Composer and to the connectors:

- **Requests of XTM Composer to the platform** go through `http_proxy` and `https_proxy`. When neither is set, XTM Composer uses the standard `HTTP_PROXY` and `HTTPS_PROXY` environment variables of its own process. `no_proxy` does not apply to these requests.
- **Deployed connectors** receive `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`. Each one comes from the matching key (`http_proxy`, `https_proxy`, `no_proxy`) or, when that key is not set, from the same variable in the environment of XTM Composer (uppercase, then lowercase).

When `with_proxy` is `false`, XTM Composer ignores every proxy setting, including these environment variables, and passes none to the connectors.

For OpenAEV, use the same keys under `openaev` (for example `OPENAEV__HTTP_PROXY`). See the [Configuration reference](configuration.md#proxy-configuration) for the full list.

## HTTPS Proxy Certificate Support (optional)

Some environments use HTTPS proxies with TLS interception (for example, corporate proxies or debugging proxies like Burp).
In these cases, additional certificate settings may be required.

These settings apply only to the deployed connectors: XTM Composer mounts the CA bundle in them and sets the matching environment variables (see [Automatic Injection](#automatic-injection)). The requests of XTM Composer itself ignore them; for these requests, only `unsecured_certificate` changes certificate validation.

### YAML configuration

```yaml
opencti:
  with_proxy: true
  https_proxy: http://proxy.example.com:8080
  https_proxy_ca:
    - /path/to/proxy-ca.pem
    - |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
  https_proxy_reject_unauthorized: true
```

### Environment variables

```bash
export OPENCTI__HTTPS_PROXY_CA='["/path/to/proxy-ca.pem", "-----BEGIN CERTIFICATE-----"]'
export OPENCTI__HTTPS_PROXY_REJECT_UNAUTHORIZED="false"
```

- `OPENCTI__HTTPS_PROXY_CA` — JSON array of CA certificate paths and/or PEM blocks used to validate the proxy certificate (for example: `["/path/to/proxy-ca.pem"]`). XTM Composer reads the files itself, so the paths must exist where XTM Composer runs (in its container, for a Docker or Kubernetes deployment).
- `OPENCTI__HTTPS_PROXY_REJECT_UNAUTHORIZED` — defaults to `true`. If set to `false`, Composer injects `NODE_TLS_REJECT_UNAUTHORIZED=0` into connector containers.

## Certificate Separation

⚠️ **Important**: Proxy certificates are separate from OpenCTI server certificates. These settings must not be mixed.

| Purpose | Configuration Keys | Used For |
|---------|-------------------|----------|
| **Proxy certificates** (deployed connectors) | `https_proxy_ca`<br>`https_proxy_reject_unauthorized` | Validating HTTPS connections of the connectors **through the proxy** |
| **OpenCTI server certificates** (OpenCTI platform) | `app:https_cert:ca`<br>`app:https_cert:reject_unauthorized` | TLS for the OpenCTI web server itself |

---

## Connector integration

### Automatic Injection

When proxy is enabled, XTM Composer automatically injects these environment variables into all managed connector containers:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `NO_PROXY`
- `SSL_CERT_FILE` (when `https_proxy_ca` is configured)
- `REQUESTS_CA_BUNDLE` (when `https_proxy_ca` is configured)
- `NODE_EXTRA_CA_CERTS` (when `https_proxy_ca` is configured)
- `CURL_CA_BUNDLE` (when `https_proxy_ca` is configured)
- `NODE_TLS_REJECT_UNAUTHORIZED` (set to `0` when `https_proxy_reject_unauthorized: false`)

The four CA variables point to `/etc/ssl/certs/xtm-proxy-ca.crt`, where XTM Composer mounts the bundle of the `https_proxy_ca` certificates.

### Verification

XTM Composer adds these variables when it deploys a connector: they are not stored in the connector configuration in OpenCTI. To check them:

- Set `manager:debug:show_env_vars` to `true` (see [Configuration reference](configuration.md#debug)). When XTM Composer starts a connector, it logs a `Starting connector` message with the connector environment variables. `HTTP_PROXY` and `HTTPS_PROXY` are masked unless `manager:debug:show_sensitive_env_vars` is also `true`.
- Or read the environment of the connector container, for example with `docker inspect <container-name>` (`Config.Env`) or `kubectl describe deployment <deployment-name>`.

See also: [Private Registry Authentication](registry-authentication.md)
