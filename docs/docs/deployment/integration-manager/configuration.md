# Configuration reference

XTM Composer uses a layered configuration system with support for YAML files and environment variables. Environment variables override file-based configuration.

## Configuration priority

1. Environment variables (highest priority)
2. Environment-specific config file (e.g., `production.yaml`)
3. Default config file (`default.yaml`)

## Environment variable format

All environment variables use double underscores (`__`) to separate nested configuration levels.

Example: `manager.logger.level` becomes `MANAGER__LOGGER__LEVEL`

## Platform

### Manager

#### Basic parameters

| Parameter                          | Environment variable                    | Default value               | Description                                                                                                              |
|:-----------------------------------|:----------------------------------------|:----------------------------|:-------------------------------------------------------------------------------------------------------------------------|
| manager:id                         | MANAGER__ID                             | default-manager-id          | Unique identifier for this manager instance                                                                              |
| manager:name                       | MANAGER__NAME                           | Filigran integration manager | Human-readable name for the manager                                                                                      |
| manager:execute_schedule           | MANAGER__EXECUTE_SCHEDULE               | 10                          | Interval in seconds between execution cycles                                                                             |
| manager:ping_alive_schedule        | MANAGER__PING_ALIVE_SCHEDULE            | 60                          | Interval in seconds between alive ping messages                                                                          |
| manager:credentials_key            | MANAGER__CREDENTIALS_KEY                |                             | RSA private key content (4096-bit recommended). Use for direct key embedding. One of `credentials_key` or `credentials_key_filepath` is required |
| manager:credentials_key_filepath   | MANAGER__CREDENTIALS_KEY_FILEPATH       |                             | Path to RSA private key file. Takes priority over `credentials_key` if both are set. One of `credentials_key` or `credentials_key_filepath` is required |

#### Logging

| Parameter                   | Environment variable            | Default value | Description                                                      |
|:----------------------------|:--------------------------------|:--------------|:-----------------------------------------------------------------|
| manager:logger:level        | MANAGER__LOGGER__LEVEL          | info          | Logging verbosity level (`trace`, `debug`, `info`, `warn`, `error`) |
| manager:logger:format       | MANAGER__LOGGER__FORMAT         | json          | Log output format (`json`, `pretty`)                             |
| manager:logger:directory    | MANAGER__LOGGER__DIRECTORY      | `true`        | Enable logging to directory/file                                 |
| manager:logger:console      | MANAGER__LOGGER__CONSOLE        | `true`        | Enable logging to console/stdout                                 |

!!! note "Log file location"

    `manager:logger:directory` is an on/off switch, not a path. When the log file is enabled, XTM Composer writes it to a `logs` folder next to its executable: `/usr/local/bin/logs/xtm-composer.log` in the Docker image, `target/release/logs/xtm-composer.log` when you build from source. The file rotates daily and always uses the JSON format, whatever the value of `manager:logger:format`.

#### Debug

| Parameter                              | Environment variable                      | Default value | Description                                                           |
|:---------------------------------------|:------------------------------------------|:--------------|:----------------------------------------------------------------------|
| manager:debug:show_env_vars            | MANAGER__DEBUG__SHOW_ENV_VARS            | `false`       | Display environment variables at startup (excludes sensitive data)    |
| manager:debug:show_sensitive_env_vars  | MANAGER__DEBUG__SHOW_SENSITIVE_ENV_VARS  | `false`       | Display sensitive environment variables at startup (tokens, keys, etc.) |

### Dependencies

#### OpenCTI

| Parameter                       | Environment variable             | Default value                  | Description                                          |
|:--------------------------------|:---------------------------------|:-------------------------------|:-----------------------------------------------------|
| opencti:enable                 | OPENCTI__ENABLE                  | `true`                         | Enable OpenCTI integration                           |
| opencti:url                    | OPENCTI__URL                     | http://host.docker.internal:4000 | OpenCTI platform URL                                 |
| opencti:token                  | OPENCTI__TOKEN                   | ChangeMe                       | OpenCTI API authentication token                     |
| opencti:unsecured_certificate  | OPENCTI__UNSECURED_CERTIFICATE   | `false`                        | Allow self-signed SSL certificates                   |
| opencti:with_proxy             | OPENCTI__WITH_PROXY              | `false`                        | Use a proxy, and pass it to the deployed connectors (see [Proxy configuration](#proxy-configuration)) |
| opencti:logs_schedule          | OPENCTI__LOGS_SCHEDULE           | 10                             | Interval in seconds between two log reports for each connector. It is checked at each execution cycle (`manager:execute_schedule`) |

#### Proxy configuration

Proxy settings are defined for each platform, under `opencti` or `openaev`, and apply only when `with_proxy` is `true`. They are used in two places:

- **Requests of XTM Composer to the platform**: XTM Composer uses `http_proxy` and `https_proxy`. When neither is set, it uses the standard `HTTP_PROXY` and `HTTPS_PROXY` environment variables of its own process. `no_proxy` does not apply to these requests.
- **Deployed connectors**: XTM Composer sets `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in each connector. Each one comes from the matching key (`http_proxy`, `https_proxy`, `no_proxy`) or, when that key is not set, from the same variable in the environment of XTM Composer (uppercase, then lowercase).

See [Proxy support](proxy-configuration.md) for examples.

| Parameter                                           | Environment variable                                   | Default value | Description                                                                                       |
|:----------------------------------------------------|:-------------------------------------------------------|:--------------|:--------------------------------------------------------------------------------------------------|
| `{opencti\|openaev}`:http_proxy                      | `{OPENCTI\|OPENAEV}`__HTTP_PROXY                        |               | Proxy URL for HTTP requests (e.g., `http://proxy:8080`), also passed to the deployed connectors as `HTTP_PROXY` |
| `{opencti\|openaev}`:https_proxy                     | `{OPENCTI\|OPENAEV}`__HTTPS_PROXY                       |               | Proxy URL for HTTPS requests (e.g., `http://proxy:8080`), also passed to the deployed connectors as `HTTPS_PROXY` |
| `{opencti\|openaev}`:no_proxy                        | `{OPENCTI\|OPENAEV}`__NO_PROXY                          |               | Comma-separated list of hosts excluded from the proxy (e.g., `localhost,127.0.0.1,internal.domain`). Used only by the deployed connectors, as `NO_PROXY` |
| `{opencti\|openaev}`:https_proxy_ca                  | `{OPENCTI\|OPENAEV}`__HTTPS_PROXY_CA                    |               | CA certificates of the proxy (file paths or inline PEM blocks), mounted in the deployed connectors. Not used by XTM Composer for its own requests |
| `{opencti\|openaev}`:https_proxy_reject_unauthorized | `{OPENCTI\|OPENAEV}`__HTTPS_PROXY_REJECT_UNAUTHORIZED   | `true`        | When `false`, XTM Composer sets `NODE_TLS_REJECT_UNAUTHORIZED=0` in the deployed connectors. Not used by XTM Composer for its own requests |

!!! note "Proxy certificate separation"

    Proxy TLS certificates are **independent** from OpenCTI HTTPS server certificates.

    - For the proxy connections of the deployed connectors → use `https_proxy_ca` and `https_proxy_reject_unauthorized`
    - For OpenCTI platform HTTPS → use `app:https_cert:*` variables in the main OpenCTI configuration

### Registry authentication

| Parameter                                       | Environment variable                               | Default value | Description                                                                 |
|:------------------------------------------------|:---------------------------------------------------|:--------------|:----------------------------------------------------------------------------|
| `{opencti\|openaev}`:daemon:registry:server      | `{OPENCTI\|OPENAEV}`__DAEMON__REGISTRY__SERVER      |               | Registry server (e.g., `registry.example.com`), prepended to the connector image names |
| `{opencti\|openaev}`:daemon:registry:username    | `{OPENCTI\|OPENAEV}`__DAEMON__REGISTRY__USERNAME    |               | Username for registry authentication                                        |
| `{opencti\|openaev}`:daemon:registry:password    | `{OPENCTI\|OPENAEV}`__DAEMON__REGISTRY__PASSWORD    |               | Password or token for registry authentication                               |
| `{opencti\|openaev}`:daemon:registry:email       | `{OPENCTI\|OPENAEV}`__DAEMON__REGISTRY__EMAIL       |               | Email sent with the credentials (optional)                                  |

!!! warning "OpenAEV registry"

    Currently, only the `docker` and `podman` orchestrators read `openaev:daemon:registry` for OpenAEV. The `kubernetes`, `swarm` and `portainer` orchestrators always use `opencti:daemon:registry`, for OpenCTI and for OpenAEV.

See [Private registry](registry-authentication.md) for the required fields and the Kubernetes behavior.

#### OpenAEV

When `openaev:enable` is `true`, XTM Composer registers with the OpenAEV platform at `openaev:url` and deploys its collectors and injectors, in the same way as the OpenCTI connectors. The proxy and orchestration settings on this page apply to OpenAEV under the `openaev` prefix. For the registry settings, see the [OpenAEV registry warning](#registry-authentication).

| Parameter                        | Environment variable              | Default value                       | Description                                      |
|:---------------------------------|:----------------------------------|:------------------------------------|:-------------------------------------------------|
| openaev:enable                   | OPENAEV__ENABLE                   | `false`                             | Enable OpenAEV integration                       |
| openaev:url                      | OPENAEV__URL                      | http://host.docker.internal:4000    | OpenAEV platform URL                             |
| openaev:token                    | OPENAEV__TOKEN                    | ChangeMe                            | OpenAEV API authentication token                 |
| openaev:unsecured_certificate    | OPENAEV__UNSECURED_CERTIFICATE    | `false`                             | Allow self-signed SSL certificates               |
| openaev:with_proxy               | OPENAEV__WITH_PROXY               | `false`                             | Use a proxy, and pass it to the deployed collectors and injectors (see [Proxy configuration](#proxy-configuration)) |
| openaev:logs_schedule            | OPENAEV__LOGS_SCHEDULE            | 10                                  | Interval in seconds between two log reports for each collector or injector. It is checked at each execution cycle (`manager:execute_schedule`) |

### Orchestration

#### General settings

| Parameter                                        | Environment variable                                 | Default value | Description                                                        |
|:-------------------------------------------------|:-----------------------------------------------------|:--------------|:-------------------------------------------------------------------|
| `{opencti\|openaev}`:daemon:selector             | `{OPENCTI\|OPENAEV}`__DAEMON__SELECTOR               | kubernetes    | Container orchestration platform (`kubernetes`, `docker`, `podman`, `swarm`, `portainer`) |

#### Kubernetes

| Parameter                                                    | Environment variable                                                | Default value | Description                                               |
|:-------------------------------------------------------------|:--------------------------------------------------------------------|:--------------|:----------------------------------------------------------|
| `{opencti\|openaev}`:daemon:kubernetes:image_pull_policy     | `{OPENCTI\|OPENAEV}`__DAEMON__KUBERNETES__IMAGE_PULL_POLICY         | IfNotPresent  | Image pull policy (`Always`, `IfNotPresent`, `Never`)     |
| `{opencti\|openaev}`:daemon:kubernetes:base_deployment       | Not supported for complex objects                                   |               | Base Kubernetes Deployment manifest template              |
| `{opencti\|openaev}`:daemon:kubernetes:base_deployment_json  | `{OPENCTI\|OPENAEV}`__DAEMON__KUBERNETES__BASE_DEPLOYMENT_JSON      |               | Base Deployment manifest as JSON string                   |

#### Docker

| Parameter                                              | Environment variable                                          | Default value | Description                                                    |
|:-------------------------------------------------------|:--------------------------------------------------------------|:--------------|:---------------------------------------------------------------|
| `{opencti\|openaev}`:daemon:docker:network_mode        | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__NETWORK_MODE            | bridge        | Docker network mode (`bridge`, `host`, `none`, or custom)      |
| `{opencti\|openaev}`:daemon:docker:extra_hosts         | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__EXTRA_HOSTS             |               | Additional hosts entries for containers (array)                |
| `{opencti\|openaev}`:daemon:docker:dns                 | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__DNS                     |               | Custom DNS servers for containers (array)                      |
| `{opencti\|openaev}`:daemon:docker:privileged          | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__PRIVILEGED              | `false`       | Run containers in privileged mode                              |
| `{opencti\|openaev}`:daemon:docker:cap_add             | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__CAP_ADD                 |               | Linux capabilities to add (array)                              |
| `{opencti\|openaev}`:daemon:docker:cap_drop            | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__CAP_DROP                |               | Linux capabilities to drop (array)                             |
| `{opencti\|openaev}`:daemon:docker:shm_size            | `{OPENCTI\|OPENAEV}`__DAEMON__DOCKER__SHM_SIZE                |               | Shared memory size in bytes                                    |

#### Portainer

| Parameter                                              | Environment variable                                          | Default value                    | Description                                          |
|:-------------------------------------------------------|:--------------------------------------------------------------|:---------------------------------|:-----------------------------------------------------|
| `{opencti\|openaev}`:daemon:portainer:api              | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__API                  | https://host.docker.internal:9443 | Portainer API endpoint URL                           |
| `{opencti\|openaev}`:daemon:portainer:api_key          | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__API_KEY              | ChangeMe                         | Portainer API authentication key                     |
| `{opencti\|openaev}`:daemon:portainer:env_id           | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__ENV_ID               | 3                                | Portainer environment ID                             |
| `{opencti\|openaev}`:daemon:portainer:env_type         | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__ENV_TYPE             | docker                           | Portainer environment type (`docker`, `kubernetes`)   |
| `{opencti\|openaev}`:daemon:portainer:api_version      | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__API_VERSION          | v1.41                            | Docker API version for Portainer                     |
| `{opencti\|openaev}`:daemon:portainer:stack            | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__STACK                |                                  | Portainer stack name for deployment                  |
| `{opencti\|openaev}`:daemon:portainer:network_mode     | `{OPENCTI\|OPENAEV}`__DAEMON__PORTAINER__NETWORK_MODE         |                                  | Network mode for Portainer-managed containers        |

## Environment configuration

| Parameter | Environment variable | Default value | Description                                                                    |
|:----------|:---------------------|:--------------|:-------------------------------------------------------------------------------|
| -         | COMPOSER_ENV         | production    | Specifies which configuration file to load (e.g., `development`, `production`) |

## Complete configuration example

```yaml
# config/production.yaml
manager:
  id: prod-manager-001
  name: Production XTM Manager
  execute_schedule: 10
  ping_alive_schedule: 60
  credentials_key_filepath: /keys/private_key_4096.pem
  logger:
    level: info
    format: json
    directory: true
    console: true

opencti:
  enable: true
  url: https://opencti.example.com
  token: ${OPENCTI_TOKEN}  # Reference env variable
  unsecured_certificate: false
  with_proxy: false
  logs_schedule: 10
  daemon:
    selector: kubernetes
    kubernetes:
      image_pull_policy: IfNotPresent

openaev:
  enable: false  # Set to true to manage OpenAEV collectors and injectors
```

## Security best practices

1. **Never commit credentials**: Use environment variables or secure secret management
2. **Use file-based keys**: Prefer `credentials_key_filepath` over embedding keys
3. **Restrict file permissions**: Set key files to `600` permissions
4. **Rotate tokens regularly**: Update API tokens periodically
5. **Use TLS/SSL**: Always use HTTPS in production
6. **Limit debug output**: Disable `show_sensitive_env_vars` in production
