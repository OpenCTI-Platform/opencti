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
| opencti:with_proxy             | OPENCTI__WITH_PROXY              | `false`                        | Use system proxy settings for connection             |
| opencti:logs_schedule          | OPENCTI__LOGS_SCHEDULE           | 10                             | Maximum interval in seconds between log reports      |

#### Proxy configuration

| Parameter                         | Environment variable             | Default value | Description                                                                                       |
|:----------------------------------|:---------------------------------|:--------------|:--------------------------------------------------------------------------------------------------|
| http_proxy                        | HTTP_PROXY                       |               | Proxy URL for HTTP requests (e.g., `http://proxy:8080`)                                           |
| https_proxy                       | HTTPS_PROXY                      |               | Proxy URL for HTTPS requests (e.g., `http://proxy:8080`)                                          |
| no_proxy                          | NO_PROXY                         |               | Comma-separated list of hosts excluded from proxy (e.g., `localhost,127.0.0.1,internal.domain`)   |
| https_proxy_ca                    | HTTPS_PROXY_CA                   |               | CA certificates used to validate HTTPS proxy connections                                          |
| https_proxy_reject_unauthorized   | HTTPS_PROXY_REJECT_UNAUTHORIZED  | `false`       | If not false, validates the proxy certificate against the provided CA list                        |

!!! note "Proxy certificate separation"

    Proxy TLS certificates are **independent** from OpenCTI HTTPS server certificates.

    - For proxy connections → use `https_proxy_ca` and `https_proxy_reject_unauthorized`
    - For OpenCTI platform HTTPS → use `app:https_cert:*` variables in the main OpenCTI configuration

### Registry authentication

| Parameter                     | Environment variable         | Default value | Description                                                                 |
|:------------------------------|:------------------------------|:--------------|:----------------------------------------------------------------------------|
| registry:enable               | REGISTRY__ENABLE              | `false`       | Enable authentication to a container registry                               |
| registry:url                  | REGISTRY__URL                 |               | Registry endpoint (e.g., `https://registry.hub.docker.com`)                 |
| registry:username             | REGISTRY__USERNAME            |               | Username for registry authentication                                        |
| registry:password             | REGISTRY__PASSWORD            |               | Password or token for registry authentication                               |
| registry:cache_ttl            | REGISTRY__CACHE_TTL           | 3600          | Time (in seconds) for caching registry authorization tokens                  |

!!! note "Authentication cache"

    Composer caches registry authentication tokens to reduce the number of login requests.  
    Tokens are refreshed automatically when expired.

#### OpenBAS (Coming Soon)

!!! note "OpenBAS Integration"
    
    OpenBAS module is not yet implemented. These configuration options are reserved for future use.

| Parameter                       | Environment variable             | Default value                  | Description                                          |
|:--------------------------------|:---------------------------------|:-------------------------------|:-----------------------------------------------------|
| openbas:enable                 | OPENBAS__ENABLE                  | `false`                        | Enable OpenBAS integration (Coming Soon)             |
| openbas:url                    | OPENBAS__URL                     | http://host.docker.internal:4000 | OpenBAS platform URL (Coming Soon)                   |
| openbas:token                  | OPENBAS__TOKEN                   | ChangeMe                       | OpenBAS API authentication token (Coming Soon)       |
| openbas:unsecured_certificate  | OPENBAS__UNSECURED_CERTIFICATE   | `false`                        | Allow self-signed SSL certificates (Coming Soon)     |
| openbas:with_proxy             | OPENBAS__WITH_PROXY              | `false`                        | Use system proxy settings (Coming Soon)              |
| openbas:logs_schedule          | OPENBAS__LOGS_SCHEDULE           | 10                             | Log report interval in seconds (Coming Soon)         |

### Orchestration

#### General settings

| Parameter                                        | Environment variable                                | Default value | Description                                                        |
|:-------------------------------------------------|:----------------------------------------------------|:--------------|:-------------------------------------------------------------------|
| `{opencti\|openbas}`:daemon:selector             | `{OPENCTI\|OPENBAS}`__DAEMON__SELECTOR             | kubernetes    | Container orchestration platform (`kubernetes`, `docker`, `portainer`) |

#### Kubernetes

| Parameter                                                    | Environment variable                                               | Default value | Description                                               |
|:-------------------------------------------------------------|:-------------------------------------------------------------------|:--------------|:----------------------------------------------------------|
| `{opencti\|openbas}`:daemon:kubernetes:image_pull_policy     | `{OPENCTI\|OPENBAS}`__DAEMON__KUBERNETES__IMAGE_PULL_POLICY       | IfNotPresent  | Image pull policy (`Always`, `IfNotPresent`, `Never`)     |
| `{opencti\|openbas}`:daemon:kubernetes:base_deployment       | Not supported for complex objects                                  |               | Base Kubernetes Deployment manifest template              |
| `{opencti\|openbas}`:daemon:kubernetes:base_deployment_json  | `{OPENCTI\|OPENBAS}`__DAEMON__KUBERNETES__BASE_DEPLOYMENT_JSON    |               | Base Deployment manifest as JSON string                   |

#### Docker

| Parameter                                              | Environment variable                                         | Default value | Description                                                    |
|:-------------------------------------------------------|:-------------------------------------------------------------|:--------------|:---------------------------------------------------------------|
| `{opencti\|openbas}`:daemon:docker:network_mode        | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__NETWORK_MODE          | bridge        | Docker network mode (`bridge`, `host`, `none`, or custom)      |
| `{opencti\|openbas}`:daemon:docker:extra_hosts         | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__EXTRA_HOSTS           |               | Additional hosts entries for containers (array)                |
| `{opencti\|openbas}`:daemon:docker:dns                 | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__DNS                   |               | Custom DNS servers for containers (array)                      |
| `{opencti\|openbas}`:daemon:docker:privileged          | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__PRIVILEGED            | `false`       | Run containers in privileged mode                              |
| `{opencti\|openbas}`:daemon:docker:cap_add             | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__CAP_ADD               |               | Linux capabilities to add (array)                              |
| `{opencti\|openbas}`:daemon:docker:cap_drop            | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__CAP_DROP              |               | Linux capabilities to drop (array)                             |
| `{opencti\|openbas}`:daemon:docker:shm_size            | `{OPENCTI\|OPENBAS}`__DAEMON__DOCKER__SHM_SIZE              |               | Shared memory size in bytes                                    |

#### Portainer

| Parameter                                              | Environment variable                                         | Default value                    | Description                                          |
|:-------------------------------------------------------|:-------------------------------------------------------------|:---------------------------------|:-----------------------------------------------------|
| `{opencti\|openbas}`:daemon:portainer:api              | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__API                | https://host.docker.internal:9443 | Portainer API endpoint URL                           |
| `{opencti\|openbas}`:daemon:portainer:api_key          | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__API_KEY            | ChangeMe                         | Portainer API authentication key                     |
| `{opencti\|openbas}`:daemon:portainer:env_id           | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__ENV_ID             | 3                                | Portainer environment ID                             |
| `{opencti\|openbas}`:daemon:portainer:env_type         | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__ENV_TYPE           | docker                           | Portainer environment type (`docker`, `kubernetes`)   |
| `{opencti\|openbas}`:daemon:portainer:api_version      | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__API_VERSION        | v1.41                            | Docker API version for Portainer                     |
| `{opencti\|openbas}`:daemon:portainer:stack            | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__STACK              |                                  | Portainer stack name for deployment                  |
| `{opencti\|openbas}`:daemon:portainer:network_mode     | `{OPENCTI\|OPENBAS}`__DAEMON__PORTAINER__NETWORK_MODE       |                                  | Network mode for Portainer-managed containers        |

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
    console: false

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

openbas:
  enable: false  # Coming Soon
```

## Security best practices

1. **Never commit credentials**: Use environment variables or secure secret management
2. **Use file-based keys**: Prefer `credentials_key_filepath` over embedding keys
3. **Restrict file permissions**: Set key files to `600` permissions
4. **Rotate tokens regularly**: Update API tokens periodically
5. **Use TLS/SSL**: Always use HTTPS in production
6. **Limit debug output**: Disable `show_sensitive_env_vars` in production
