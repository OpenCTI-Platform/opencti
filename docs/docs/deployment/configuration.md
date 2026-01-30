# Configuration

The purpose of this section is to learn how to configure OpenCTI to have it tailored for your production and development needs. It is possible to check all default parameters implemented in the platform in the [`default.json` file](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/config/default.json).
 
Here are the configuration keys, for both containers (environment variables) and manual deployment.

!!! note "Parameters equivalence"
    
    The equivalent of a config variable in environment variables is the usage of a double underscores (`__`) for a level of config.

    For example:
    ```json
    "providers": {
      "ldap": {
        "strategy": "LdapStrategy"
      }
    }
    ```

    will become:
    ```bash
    PROVIDERS__LDAP__STRATEGY=LdapStrategy
    ```

    If you need to put a list of elements for the key, it must have a special formatting. Here is an example for redirect URIs for OpenID config:
    ```bash
    "PROVIDERS__OPENID__CONFIG__REDIRECT_URIS=[\"https://demo.opencti.io/auth/oic/callback\"]"
    ```

## Platform

### API & Frontend

#### Basic parameters

| Parameter                    | Environment variable            | Default value         | Description                                                                                                                                  |
|:-----------------------------|:--------------------------------|:----------------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| app:port                     | APP__PORT                       | 4000                  | Listen port of the application                                                                                                               |
| app:base_path                | APP__BASE_PATH                  |                       | Specific URI (ie. /opencti)                                                                                                                  |
| app:base_url                 | APP__BASE_URL                   | http://localhost:4000 | Full URL of the platform (should include the `base_path` if any)                                                                             |
| app:request_timeout          | APP__REQUEST_TIMEOUT            | 1200000               | Request timeout, in ms (default 20 minutes)                                                                                                  |
| app:session_timeout          | APP__SESSION_TIMEOUT            | 1200000               | Session timeout, in ms (default 20 minutes)                                                                                                  |
| app:session_idle_timeout     | APP__SESSION_IDLE_TIMEOUT       | 0                     | Idle timeout (locking the screen), in ms (default 0 minute - disabled)                                                                       |
| app:session_cookie           | APP__SESSION_COOKIE             | false                 | Use memory/session cookie instead of persistent one                                                                                          |
| app:admin:externally_managed | APP__ADMIN__EXTERNALLY_MANAGED  | false                 | Completely remove the default admin user from the platform and never create it again                                                         |
| app:admin:email              | APP__ADMIN__EMAIL               | admin@opencti.io      | Default login email of the admin user                                                                                                        |
| app:admin:password           | APP__ADMIN__PASSWORD            | ChangeMe              | Default password of the admin user                                                                                                           |
| app:admin:token              | APP__ADMIN__TOKEN               | ChangeMe              | Default token (must be a valid UUIDv4)                                                                                                       |
| app:health_access_key        | APP__HEALTH_ACCESS_KEY          | ChangeMe              | Access key for the `/health` endpoint. Must be changed - will not respond to default value. Access with `/health?health_access_key=ChangeMe` |
| app:auth_payload_body_size   | APP__AUTH_PAYLOAD_BODY_SIZE          |                       | Maximum payload body size for SSO/SAML. Controls the Express body-parser `limit` setting (defaults to 100kb). See https://expressjs.com/en/resources/middleware/body-parser.html                                                                                          |


#### Network and security

| Parameter                                            | Environment variable                                   | Default value | Description                                                                                                         |
|:-----------------------------------------------------|:-------------------------------------------------------|:--------------|:--------------------------------------------------------------------------------------------------------------------|
| http_proxy                                           | HTTP_PROXY                                             |               | Proxy URL for HTTP connection (example: http://proxy:80080)                                                         |
| https_proxy                                          | HTTPS_PROXY                                            |               | Proxy URL for HTTPS connection (example: http://proxy:80080)                                                        |
| no_proxy                                             | NO_PROXY                                               |               | Comma separated list of hostnames for proxy exception (example: localhost,127.0.0.0/8,internal.opencti.io)          |
| app:https_cert:cookie_secure                         | APP__HTTPS_CERT__COOKIE_SECURE                         | false         | Set the flag "secure" for session cookies                                                                           |
| app:https_cert:ca                                    | APP__HTTPS_CERT__CA                                    | Empty list [] | Certificate authority paths or content, only if the client uses a self-signed certificate                           |
| app:https_cert:key                                   | APP__HTTPS_CERT__KEY                                   |               | Certificate key path or content                                                                                     |
| app:https_cert:crt                                   | APP__HTTPS_CERT__CRT                                   |               | Certificate crt path or content                                                                                     |
| app:https_cert:reject_unauthorized                   | APP__HTTPS_CERT__REJECT_UNAUTHORIZED                   |               | If not false, the server certificate is verified against the list of supplied CAs                                   |
| app:public_dashboard_authorized_domains              | APP__PUBLIC_DASHBOARD_AUTHORIZED_DOMAINS               | Empty string  | List of domain name that can display public dashboard in an embedded iframe. Empty string means none, '*' means all |
| app:graphql:armor_protection:disabled                | APP__GRAPHQL__ARMOR_PROTECTION__DISABLED               | true          | Disable GraphQL armor protection                                                                                    |
| app:graphql:armor_protection:max_depth               | APP__GRAPHQL__ARMOR_PROTECTION__MAX_DEPTH              | 20            | GraphQL armor protection max depth in queries                                                                       |
| app:graphql:armor_protection:max_directives          | APP__GRAPHQL__ARMOR_PROTECTION__MAX_DIRECTIVES         | 20            | GraphQL armor protection max directives in queries                                                                  |
| app:graphql:armor_protection:max_tokens              | APP__GRAPHQL__ARMOR_PROTECTION__MAX_TOKENS             | 100000        | GraphQL armor protection max tokens                                                                                 |
| app:graphql:armor_protection:cost_limit              | APP__GRAPHQL__ARMOR_PROTECTION__COST_LIMIT             | 3000000       | GraphQL armor protection cost limit                                                                                 |
| app:graphql:armor_protection:block_field_suggestion  | APP__GRAPHQL__ARMOR_PROTECTION__BLOCK_FIELD_SUGGESTION | true          | GraphQL armor protection, block the field suggestion                                                                |
| app:notifier_authorized_functions                    | APP__NOTIFIER_AUTHORIZED_FUNCTIONS                     | see [`default.json`](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/config/default.json)  | Authorized function that can be used in webhook templates           |

#### Logging

##### Errors

| Parameter                   | Environment variable          | Default value | Description                                                      |
|:----------------------------|:------------------------------|:--------------|:-----------------------------------------------------------------|
| app:app_logs:logs_level     | APP__APP_LOGS__LOGS_LEVEL     | info          | The application log level                                        |
| app:app_logs:logs_files     | APP__APP_LOGS__LOGS_FILES     | `true`        | If application logs is logged into files                         |
| app:app_logs:logs_console   | APP__APP_LOGS__LOGS_CONSOLE   | `true`        | If application logs is logged to console (useful for containers) |
| app:app_logs:logs_max_files | APP__APP_LOGS__LOGS_MAX_FILES | 7             | Maximum number of daily files in logs                            |
| app:app_logs:logs_directory | APP__APP_LOGS__LOGS_DIRECTORY | ./logs        | File logs directory                                              |

##### Audit

| Parameter                     | Environment variable            | Default value | Description                                                |
|:------------------------------|:--------------------------------|:--------------|:-----------------------------------------------------------|
| app:audit_logs:logs_files     | APP__AUDIT_LOGS__LOGS_FILES     | `true`        | If audit logs is logged into files                         |
| app:audit_logs:logs_console   | APP__AUDIT_LOGS__LOGS_CONSOLE   | `true`        | If audit logs is logged to console (useful for containers) |
| app:audit_logs:logs_max_files | APP__AUDIT_LOGS__LOGS_MAX_FILES | 7             | Maximum number of daily files in logs                      |
| app:audit_logs:logs_directory | APP__AUDIT_LOGS__LOGS_DIRECTORY | ./logs        | Audit logs directory                                       |

#### Telemetry

| Parameter                                 | Environment variable                         | Default value | Description                             |
|:------------------------------------------|:---------------------------------------------|:--------------|:----------------------------------------|
| app:telemetry:metrics:enabled             | APP__TELEMETRY__METRICS__ENABLED             | `false`       | Enable the metrics collection           |
| app:telemetry:metrics:exporter_otlp       | APP__TELEMETRY__METRICS__EXPORTER_OTLP       |               | Port to expose the OTLP endpoint        |
| app:telemetry:metrics:exporter_prometheus | APP__TELEMETRY__METRICS__EXPORTER_PROMETHEUS | 14269         | Port to expose the Prometheus endpoint  |

For a detailed list of exposed metrics, please refer to the [Telemetry](../deployment/telemetry.md) page.


#### Maps & references

| Parameter                 | Environment variable       | Default value                                                  | Description                                                      |
|:--------------------------|:---------------------------|:---------------------------------------------------------------|------------------------------------------------------------------|
| app:map_tile_server_dark  | APP__MAP_TILE_SERVER_DARK  | https://map.opencti.io/styles/filigran-dark2/{z}/{x}/{y}.png   | The address of the OpenStreetMap provider with dark theme style  |
| app:map_tile_server_light | APP__MAP_TILE_SERVER_LIGHT | https://map.opencti.io/styles/filigran-light2/{z}/{x}/{y}.png  | The address of the OpenStreetMap provider with light theme style |
| app:reference_attachment  | APP__REFERENCE_ATTACHMENT  | `false`                                                        | External reference mandatory attachment                          |

#### Functional customization

| Parameter                                                                    | Environment variable                                           | Default value  | Description                                                                                            |
|:-----------------------------------------------------------------------------|:---------------------------------------------------------------|:---------------|:-------------------------------------------------------------------------------------------------------|
| app:artifact_zip_password                                                    | APP__ARTIFACT_ZIP_PASSWORD                                     | infected       | Artifact encrypted archive default password                                                            |
| app:trash:enabled                                                            | APP__TRASH__ENABLED                                            | `true`         | Enable or disable the trash system. If disabled, the trash manager will also be disabled               |
| relations_deduplication:past_days                                            | RELATIONS_DEDUPLICATION__PAST_DAYS                             | 30             | De-duplicate relations based on `start_time` and `stop_time` - *n* days                                |
| relations_deduplication:next_days                                            | RELATIONS_DEDUPLICATION__NEXT_DAYS                             | 30             | De-duplicate relations based on `start_time` and `stop_time` + *n* days                                |
| relations_deduplication:created_by_based                                     | RELATIONS_DEDUPLICATION__CREATED_BY_BASED                      | `false`        | Take into account the author to duplicate even if `stat_time` / `stop_time` are matching               |
| relations_deduplication:types_overrides:*relationship_type*:past_days        | RELATIONS_DEDUPLICATION__*RELATIONSHIP_TYPE*__PAST_DAYS        |                | Override the past days for a specific type of relationship (ex. *targets*)                             |
| relations_deduplication:types_overrides:*relationship_type*:next_days        | RELATIONS_DEDUPLICATION__*RELATIONSHIP_TYPE*__NEXT_DAYS        |                | Override the next days for a specific type of relationship (ex. *targets*)                             |
| relations_deduplication:types_overrides:*relationship_type*:created_by_based | RELATIONS_DEDUPLICATION__*RELATIONSHIP_TYPE*__CREATED_BY_BASED |                | Override the author duplication for a specific type of relationship (ex. *targets*)                    |
| app:trash:enabled                                                            | APP__TRASH__ENABLED                                            | `true`         | Enable or disable the trash system. If disabled, the trash manager will also be disabled               |
| app:validation_mode                                                          | APP__VALIDATION_MODE                                           | `workbench`    | Can either be `workbench` or `draft` depending on the validation mode to be used for automatic imports |

#### Technical customization

| Parameter                                           | Environment variable                                     | Default value | Description                                                                 |
|:----------------------------------------------------|:---------------------------------------------------------|:--------------|:----------------------------------------------------------------------------|
| app:graphql:playground:enabled                      | APP__GRAPHQL__PLAYGROUND__ENABLED                        | `true`        | Enable the playground on /public/graphql                                    |
| app:graphql:playground:force_disabled_introspection | APP__GRAPHQL__PLAYGROUND__FORCE_DISABLED_INTROSPECTION   | `true`        | Introspection is allowed to auth users but can be disabled in needed        |
| app:concurrency:retry_count                         | APP__CONCURRENCY__RETRY_COUNT                            | 200           | Number of try to get the lock to work an element (create/update/merge, ...) |
| app:concurrency:retry_delay                         | APP__CONCURRENCY__RETRY_DELAY                            | 100           | Delay between 2 lock retry (in milliseconds)                                |
| app:concurrency:retry_jitter                        | APP__CONCURRENCY__RETRY_JITTER                           | 50            | Random jitter to prevent concurrent retry  (in milliseconds)                |
| app:concurrency:max_ttl                             | APP__CONCURRENCY__MAX_TTL                                | 30000         | Global maximum time for lock retry (in milliseconds)                        |

### Dependencies

#### XTM Suite

| Parameter                           | Environment variable             | Default value           | Description                                                                                                  |
|:------------------------------------|:---------------------------------|:------------------------|:-------------------------------------------------------------------------------------------------------------|
| xtm:openaev_url                     | XTM__OPENAEV_URL                 |                         | OpenAEV URL                                                                                                  |
| xtm:openaev_api_url                 | XTM__OPENAEV_API_URL             |                         | If sets, overrides the API base URL used for the OpenAEV integration                                         |
| xtm:openaev_token                   | XTM__OPENAEV_TOKEN               |                         | OpenAEV token                                                                                                |
| xtm:openaev_reject_unauthorized     | XTM__OPENAEV_REJECT_UNAUTHORIZED | false                   | Enable TLS certificate check                                                                                 |
| xtm:openaev_disable_display         | XTM__OPENAEV_DISABLE_DISPLAY     | false                   | Disable OpenAEV posture in the UI                                                                            |
| xtm:xtmhub_url                      | XTM__XTMHUB_URL                  | https://hub.filigran.io | XTM Hub URL. If set to an empty string, integration of XTM Hub features into OpenCTI will be removed from UI |
 

#### ElasticSearch

| Parameter                             | Environment variable                    | Default value         | Description                                                                                                                                                                                                                                                            |
|:--------------------------------------|:----------------------------------------|:----------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| elasticsearch:engine_selector         | ELASTICSEARCH__ENGINE_SELECTOR          | auto                  | `elk` or `opensearch`, default is `auto`, please put `elk` if you use token auth.                                                                                                                                                                                      |
| elasticsearch:engine_check            | ELASTICSEARCH__ENGINE_CHECK             | true                  | Disable Search Engine [compatibility matrix](overview.md#dependencies) verification. <br> __Caution__: OpenCTI was developed in compliance with the [compatibility matrix](overview.md#dependencies). Setting the parameter to `false` may result in negative impacts. |
| elasticsearch:url                     | ELASTICSEARCH__URL                      | http://localhost:9200 | URL(s) of the ElasticSearch (supports http://user:pass@localhost:9200 and list of URLs)                                                                                                                                                                                |
| elasticsearch:username                | ELASTICSEARCH__USERNAME                 |                       | Username can be put in the URL or with this parameter                                                                                                                                                                                                                  |
| elasticsearch:password                | ELASTICSEARCH__PASSWORD                 |                       | Password can be put in the URL or with this parameter                                                                                                                                                                                                                  |
| elasticsearch:api_key                 | ELASTICSEARCH__API_KEY                  |                       | API key for ElasticSearch token auth. Please set also `engine_selector` to `elk`                                                                                                                                                                                       |
| elasticsearch:index_prefix            | ELASTICSEARCH__INDEX_PREFIX             | opencti               | Prefix for the indices                                                                                                                                                                                                                                                 |
| elasticsearch:ssl:reject_unauthorized | ELASTICSEARCH__SSL__REJECT_UNAUTHORIZED | `true`                | Enable TLS certificate check                                                                                                                                                                                                                                           |
| elasticsearch:ssl:ca                  | ELASTICSEARCH__SSL__CA                  |                       | Custom certificate path or content                                                                                                                                                                                                                                     |
| elasticsearch:search_wildcard_prefix  | ELASTICSEARCH__SEARCH_WILDCARD_PREFIX   | `false`               | Search includes words with automatic fuzzy comparison                                                                                                                                                                                                                  |
| elasticsearch:search_fuzzy            | ELASTICSEARCH__SEARCH_FUZZY             | `false`               | Search will include words not starting with the search keyword                                                                                                                                                                                                         |

#### Redis

| Parameter                  | Environment variable        | Default value | Description                                                                           |
|:---------------------------|:----------------------------|:--------------|:--------------------------------------------------------------------------------------|
| redis:mode                 | REDIS__MODE                 | single        | Connect to redis in "single", "sentinel or "cluster"  mode                            |
| redis:namespace            | REDIS__NAMESPACE            |               | Namespace (to use as prefix)                                                          |
| redis:hostname             | REDIS__HOSTNAME             | localhost     | Hostname of the Redis Server                                                          |
| redis:hostnames            | REDIS__HOSTNAMES            |               | Hostnames definition for Redis cluster or sentinel mode: a list of host:port objects. |
| redis:port                 | REDIS__PORT                 | 6379          | Port of the Redis Server                                                              |
| redis:sentinel_master_name | REDIS__SENTINEL_MASTER_NAME |               | Name of your Redis Sentinel Master (mandatory in sentinel mode)                       |
| redis:sentinel_username    | REDIS__SENTINEL_USERNAME    |               | Username to authenticate on Redis Sentinel                                            |
| redis:sentinel_password    | REDIS__SENTINEL_PASSWORD    |               | Password to authenticate on Redis Sentinel                                            |
| redis:use_ssl              | REDIS__USE_SSL              | `false`       | Is the Redis Server has TLS enabled                                                   |
| redis:username             | REDIS__USERNAME             |               | Username of the Redis Server                                                          |
| redis:password             | REDIS__PASSWORD             |               | Password of the Redis Server                                                          |
| redis:database             | REDIS__DATABASE             |               | Database of the Redis Server (only work in single mode)                               |
| redis:ca                   | REDIS__CA                   | []            | List of path(s) of the CA certificate(s)                                              |
| redis:trimming             | REDIS__TRIMMING             | 2000000       | Number of elements to maintain in the stream. (0 = unlimited)                         |

#### RabbitMQ

| Parameter                                   | Environment variable              | Default value | Description                                 |
|:--------------------------------------------|:----------------------------------|:--------------|:--------------------------------------------|
| rabbitmq:hostname                           | RABBITMQ__HOSTNAME                | localhost     | Hostname of the RabbitMQ server             |
| rabbitmq:port                               | RABBITMQ__PORT                    | 5672          | Port of the RabbitMQ server                 |
| rabbitmq:hostname_management                | RABBITMQ__HOSTNAME_MANAGEMENT     |               | Hostname of the RabbitMQ Management Plugin  |
| rabbitmq:port_management                    | RABBITMQ__PORT_MANAGEMENT         | 15672         | Port of the RabbitMQ Management Plugin      |
| rabbitmq:username                           | RABBITMQ__USERNAME                | guest         | RabbitMQ user                               |
| rabbitmq:password                           | RABBITMQ__PASSWORD                | guest         | RabbitMQ password                           |
| rabbitmq:vhost                              | RABBITMQ__VHOST                   | "/"           | RabbitMQ virtual host                       |
| rabbitmq:queue_type                         | RABBITMQ__QUEUE_TYPE              | "classic"     | RabbitMQ Queue Type ("classic" or "quorum") |
| -                                           | -                                 | -             | -                                           |
| rabbitmq:use_ssl                            | RABBITMQ__USE_SSL                 | `false`       | Use TLS connection                          |
| rabbitmq:use_ssl_cert                       | RABBITMQ__USE_SSL_CERT            |               | Path or cert content                        |
| rabbitmq:use_ssl_key                        | RABBITMQ__USE_SSL_KEY             |               | Path or key content                         |
| rabbitmq:use_ssl_pfx                        | RABBITMQ__USE_SSL_PFX             |               | Path or pfx content                         |
| rabbitmq:use_ssl_ca                         | RABBITMQ__USE_SSL_CA              | []            | List of path(s) of the CA certificate(s)    |
| rabbitmq:use_ssl_passphrase                 | RABBITMQ__SSL_PASSPHRASE          |               | Passphrase for the key certificate          |
| rabbitmq:use_ssl_reject_unauthorized        | RABBITMQ__SSL_REJECT_UNAUTHORIZED | `false`       | Reject rabbit self signed certificate       |
| -                                           | -                                 | -             | -                                           |
| rabbitmq:management_ssl                     | RABBITMQ__MANAGEMENT_SSL          | `false`       | Is the Management Plugin has TLS enabled    |
| rabbitmq:management_ssl_reject_unauthorized | RABBITMQ__SSL_REJECT_UNAUTHORIZED | `true`        | Reject management self signed certificate   |

#### S3 Bucket

| Parameter           | Environment variable | Default value  | Description                                                                                                                                                                                                                 |
|:--------------------|:---------------------|:---------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| minio:endpoint      | MINIO__ENDPOINT      | localhost      | Hostname of the S3 Service. Example if you use AWS Bucket S3: __s3.us-east-1.amazonaws.com__ (if `minio:bucket_region` value is _us-east-1_). This parameter value can be omitted if you use Minio as an S3 Bucket Service. |
| minio:port          | MINIO__PORT          | 9000           | Port of the S3 Service. For AWS Bucket S3 over HTTPS, this value can be changed (usually __443__).                                                                                                                          |
| minio:use_ssl       | MINIO__USE_SSL       | `false`        | Indicates whether the S3 Service has TLS enabled. For AWS Bucket S3 over HTTPS, this value could be `true`.                                                                                                                 |
| minio:access_key    | MINIO__ACCESS_KEY    | ChangeMe       | Access key for the S3 Service.                                                                                                                                                                                              |
| minio:secret_key    | MINIO__SECRET_KEY    | ChangeMe       | Secret key for the S3 Service.                                                                                                                                                                                              |
| minio:bucket_name   | MINIO__BUCKET_NAME   | opencti-bucket | S3 bucket name. Useful to change if you use AWS.                                                                                                                                                                            |
| minio:bucket_region | MINIO__BUCKET_REGION | us-east-1      | Region of the S3 bucket if you are using AWS. This parameter value can be omitted if you use Minio as an S3 Bucket Service.                                                                                                 |
| minio:use_aws_role  | MINIO__USE_AWS_ROLE  | `false`        | Indicates whether to use AWS role auto credentials. When this parameter is configured, the `minio:access_key` and `minio:secret_key` parameters are not necessary.                                                          |

#### SMTP Service

| Parameter                | Environment variable      | Default value | Description                               |
|:-------------------------|:--------------------------|:--------------|:------------------------------------------|
| smtp:hostname            | SMTP__HOSTNAME            |               | SMTP Server hostname                      |
| smtp:port                | SMTP__PORT                | 465           | SMTP Port (25 or 465 for TLS)             |
| smtp:use_ssl             | SMTP__USE_SSL             | `false`       | SMTP over TLS                             |
| smtp:reject_unauthorized | SMTP__REJECT_UNAUTHORIZED | `false`       | Enable TLS certificate check              |
| smtp:username            | SMTP__USERNAME            |               | SMTP Username if authentication is needed |
| smtp:password            | SMTP__PASSWORD            |               | SMTP Password if authentication is needed |

#### AI Service

!!! note "AI deployment and cloud services"

    There are several possibilities for [Enterprise Edition](../administration/enterprise.md) customers to use OpenCTI AI endpoints:

     - Use the Filigran AI Service leveraging our custom AI model using the token given by the support team.
     - Use OpenAI, MistralAI or AzureAI cloud endpoints using your own tokens.
     - Deploy or use local AI endpoints.

| Parameter              | Environment variable        | Default value | Description                                                                   |
|:-----------------------|:----------------------------|:--------------|:------------------------------------------------------------------------------|
| ai:enabled             | AI__ENABLED                 | true          | Enable AI capabilities                                                        |
| ai:type                | AI__TYPE                    | mistralai     | AI type (`openai`, `mistralai` or `azureopenai`)                              |              |
| ai:endpoint            | AI__ENDPOINT                |               | Endpoint URL (empty means default cloud service)                              |
| ai:token               | AI__TOKEN                   |               | Token for endpoint credentials                                                |
| ai:model               | AI__MODEL                   |               | Model to be used for text generation (depending on type)                      |
| ai:model_images        | AI__MODEL_IMAGES            |               | Model to be used for image generation (depending on type)                     |
| ai:version             | AI__VERSION                 |               | The version of the deployment server (used for AzureAI)                       |
| ai:ai_azure_instance   | AI__AI_AZURE_INSTANCE       |               | The Azure instance name you use (https://<ai_azure_instance>.openai.azure.ai) |
| ai:ai_azure_deployment | AI__AI_AZURE_DEPLOYMENT     |               | The Azure deployment (often equal to the model used)                          |

#### Protect Sensitive Configurations

| Parameter                                                               | Environment variable                                      | Default value                                                                                                            | Description                                          |
|:------------------------------------------------------------------------|:----------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------|
| protected_sensitive_config:enabled                                      | PROTECT_SENSITIVE_CONFIG__ENABLED                         | true                                                                                                                     | Enable Protect Sensitive Configurations              |
| protected_sensitive_config:markings:enabled                             | PROTECT_SENSITIVE_CONFIG__MARKINGS__ENABLED               | true                                                                                                                     | Protect Markings                                     |
| protected_sensitive_config:markings:protected_definitions               | PROTECT_SENSITIVE_CONFIG__MARKINGS__PROTECTED_DEFINITIONS | ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED", "PAP:CLEAR", "PAP:GREEN", "PAP:AMBER", "PAP:RED"] | List of protected Markings definitions               |
| protected_sensitive_config:groups:enabled                               | PROTECT_SENSITIVE_CONFIG__GROUPS__ENABLED                 | true                                                                                                                     | Enabled Groups protection                            |
| protected_sensitive_config:groups:protected_names                       | PROTECT_SENSITIVE_CONFIG__GROUPS__PROTECTED_NAMES         | ["Administrators", "Connectors", "Default"]                                                                              | List of protected Groups                             |
| protected_sensitive_config:roles:enabled                                | PROTECT_SENSITIVE_CONFIG__ROLES__ENABLED                  | true                                                                                                                     | Enabled Roles protection                             |
| protected_sensitive_config:roles:protected_names                        | PROTECT_SENSITIVE_CONFIG__ROLES__PROTECTED_NAMES          | ["Administrators", "Connectors", "Default"]                                                                              | List of protected Roles                              |
| protected_sensitive_config:rules:enabled                                | PROTECT_SENSITIVE_CONFIG__RULES__ENABLED                  | true                                                                                                                     | Enabled Rules protection                             |
| protected_sensitive_config:ce_ee_toggle:enabled                         | PROTECT_SENSITIVE_CONFIG__CE_EE_TOGGLE__ENABLED           | true                                                                                                                     | Enabled Enterpise/Community Editon toggle protection |
| protected_sensitive_config:file_indexing:enabled                        | PROTECT_SENSITIVE_CONFIG__FILE_INDEXING__ENABLED          | true                                                                                                                     | Enabled File Indexing protection                     |
| protected_sensitive_config:platform_organization:enabled                | PROTECT_SENSITIVE_CONFIG__PLATFORM_ORGANIZATION__ENABLED  | true                                                                                                                     | Enabled main Platform Organization protection        |

#### Using a credentials provider

In some cases, it may not be possible to put directly dependencies credentials directly in environment variables or static configuration. The platform can then retrieve them from a credentials provider. Here is the list of supported providers:

| Credentials provider | Provider key |
|:---------------------|:-------------|
| CyberArk             | `cyberark`   | 

For each dependency, special configuration keys are available to ensure the platform retrieves credentials during start process. Not all dependencies support this mechanism, here is the exhaustive list:

| Dependency     | Prefix          |
|:---------------|:----------------|
| ElasticSearch  | `elasticsearch` | 
| S3 Storage     | `minio`         |
| Redis          | `redis`         |
| OpenID secrets | `oic`           |

##### Common configurations

| Parameter                                                       | Environment variable                                              | Default value | Description                         |
|:----------------------------------------------------------------|:------------------------------------------------------------------|:--------------|:------------------------------------|
| `{prefix}`:credentials_provider:https_cert:reject_unauthorized  | `{PREFIX}`__CREDENTIALS_PROVIDER__HTTPS_CERT__REJECT_UNAUTHORIZED | `false`       | Reject unauthorized TLS connection  |
| `{prefix}`:credentials_provider:https_cert:crt                  | `{PREFIX}`__CREDENTIALS_PROVIDER__HTTPS_CERT__CRT                 |               | Path to the HTTPS certificate       |
| `{prefix}`:credentials_provider:https_cert:key                  | `{PREFIX}`__CREDENTIALS_PROVIDER__HTTPS_CERT__KEY                 |               | Path to the HTTPS key               |
| `{prefix}`:credentials_provider:https_cert:ca                   | `{PREFIX}`__CREDENTIALS_PROVIDER__HTTPS_CERT__CA                  |               | Path to the HTTPS CA certificate    |

##### CyberArk

| Parameter                                                 | Environment variable                                         | Default value | Description                                                                          |
|:----------------------------------------------------------|:-------------------------------------------------------------|:--------------|:-------------------------------------------------------------------------------------|
| `{prefix}`:credentials_provider:cyberark:uri              | `{PREFIX}`__CREDENTIALS_PROVIDER__CYBERARK__URI              |               | The URL of the CyberArk endpoint for credentials retrieval (GET request)             |
| `{prefix}`:credentials_provider:cyberark:app_id           | `{PREFIX}`__CREDENTIALS_PROVIDER__CYBERARK__APP_ID           |               | The used application ID for the dependency within CyberArk                           |
| `{prefix}`:credentials_provider:cyberark:safe             | `{PREFIX}`__CREDENTIALS_PROVIDER__CYBERARK__SAFE             |               | The used safe key for the dependency within CyberArk                                 |
| `{prefix}`:credentials_provider:cyberark:object           | `{PREFIX}`__CREDENTIALS_PROVIDER__CYBERARK__OBJECT           |               | The used object key for the dependency within CyberArk                               |
| `{prefix}`:credentials_provider:cyberark:default_splitter | `{PREFIX}`__CREDENTIALS_PROVIDER__CYBERARK__DEFAULT_SPLITTER | :             | Default splitter of the credentials results, for "username:password", default is ":" |
| `{prefix}`:credentials_provider:cyberark:field_targets    | `{PREFIX}`__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS    | []            | Fields targets in the data content response after splitting                          |

Here is an example for ElasticSearch:

Environment variables:
```yaml
- ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__URI=http://my.cyberark.com/AIMWebService/api/Accounts
- ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__APP_ID=opencti-elastic
- ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__SAFE=mysafe-key
- ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__OBJECT=myobject-key
- "ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__DEFAULT_SPLITTER=:" # As default is already ":", may not be necessary
- "ELASTICSEARCH__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS=[\"username\",\"password\"]"
```

JSON version:
```json
"elasticsearch": {
    "credentials_provider": {
        "cyberark": {
            "uri": "http://my.cyberark.com/AIMWebService/api/Accounts",
            "app_id": "opencti-elastic",
            "safe": "mysafe-key",
            "object": "myobject-key",
            "default_splitter": ":",
            "field_targets": ["username", "password"]
      }
    }
}
```

Another example for MinIo (S3) using certificate:

Environment variables:
```yaml
- MINIO__CREDENTIALS_PROVIDER__HTTPS_CERT__CRT=/cert_volume/mycert.crt
- MINIO__CREDENTIALS_PROVIDER__HTTPS_CERT__KEY=/cert_volume/mycert.key
- MINIO__CREDENTIALS_PROVIDER__HTTPS_CERT__CA=/cert_volume/ca.crt
- MINIO__CREDENTIALS_PROVIDER__CYBERARK__URI=http://my.cyberark.com/AIMWebService/api/Accounts
- MINIO__CREDENTIALS_PROVIDER__CYBERARK__APP_ID=opencti-s3
- MINIO__CREDENTIALS_PROVIDER__CYBERARK__SAFE=mysafe-key
- MINIO__CREDENTIALS_PROVIDER__CYBERARK__OBJECT=myobject-key
- "MINIO__CREDENTIALS_PROVIDER__CYBERARK__DEFAULT_SPLITTER=:" # As default is already ":", may not be necessary
- "MINIO__CREDENTIALS_PROVIDER__CYBERARK__FIELD_TARGETS=[\"access_key\",\"secret_key\"]"
```

<a id="engines-schedules-managers"></a>
### Engines, Schedules and Managers

| Parameter                                            | Environment variable                                  | Default value                    | Description                                            |
|:-----------------------------------------------------|:------------------------------------------------------|:---------------------------------|:-------------------------------------------------------|
| rule_engine:enabled                                  | RULE_ENGINE__ENABLED                                  | `true`                           | Enable/disable the rule engine                         |
| rule_engine:lock_key                                 | RULE_ENGINE__LOCK_KEY                                 | rule_engine_lock                 | Lock key of the engine in Redis                        |
| -                                                    | -                                                     | -                                | -                                                      |
| history_manager:enabled                              | HISTORY_MANAGER__ENABLED                              | `true`                           | Enable/disable the history manager                     |
| history_manager:lock_key                             | HISTORY_MANAGER__LOCK_KEY                             | history_manager_lock             | Lock key for the manager in Redis                      |
| -                                                    | -                                                     | -                                | -                                                      |
| task_scheduler:enabled                               | TASK_SCHEDULER__ENABLED                               | `true`                           | Enable/disable the task scheduler                      |
| task_scheduler:lock_key                              | TASK_SCHEDULER__LOCK_KEY                              | task_manager_lock                | Lock key for the scheduler in Redis                    |
| task_scheduler:interval                              | TASK_SCHEDULER__INTERVAL                              | 10000                            | Interval to check new task to do (in ms)               |
| -                                                    | -                                                     | -                                | -                                                      |
| sync_manager:enabled                                 | SYNC_MANAGER__ENABLED                                 | `true`                           | Enable/disable the sync manager                        |
| sync_manager:lock_key                                | SYNC_MANAGER__LOCK_KEY                                | sync_manager_lock                | Lock key for the manager in Redis                      |
| sync_manager:interval                                | SYNC_MANAGER__INTERVAL                                | 10000                            | Interval to check new sync feeds to consume (in ms)    |
| -                                                    | -                                                     | -                                | -                                                      |
| expiration_scheduler:enabled                         | EXPIRATION_SCHEDULER__ENABLED                         | `true`                           | Enable/disable the scheduler                           |
| expiration_scheduler:lock_key                        | EXPIRATION_SCHEDULER__LOCK_KEY                        | expired_manager_lock             | Lock key for the scheduler in Redis                    |
| expiration_scheduler:interval                        | EXPIRATION_SCHEDULER__INTERVAL                        | 300000                           | Interval to check expired indicators (in ms)           |
| -                                                    | -                                                     | -                                | -                                                      |
| retention_manager:enabled                            | RETENTION_MANAGER__ENABLED                            | `true`                           | Enable/disable the retention manager                   |
| retention_manager:lock_key                           | RETENTION_MANAGER__LOCK_KEY                           | retention_manager_lock           | Lock key for the manager in Redis                      |
| retention_manager:interval                           | RETENTION_MANAGER__INTERVAL                           | 60000                            | Interval to check items to be deleted (in ms)          |
| -                                                    | -                                                     | -                                | -                                                      |
| notification_manager:enabled                         | NOTIFICATION_MANAGER__ENABLED                         | `true`                           | Enable/disable the notification manager                |
| notification_manager:lock_live_key                   | NOTIFICATION_MANAGER__LOCK_LIVE_KEY                   | notification_live_manager_lock   | Lock live key for the manager in Redis                 |
| notification_manager:lock_digest_key                 | NOTIFICATION_MANAGER__LOCK_DIGEST_KEY                 | notification_digest_manager_lock | Lock digest key for the manager in Redis               |
| notification_manager:interval                        | NOTIFICATION_MANAGER__INTERVAL                        | 10000                            | Interval to push notifications                         |
| -                                                    | -                                                     | -                                | -                                                      |
| publisher_manager:enabled                            | PUBLISHER_MANAGER__ENABLED                            | `true`                           | Enable/disable the publisher manager                   |
| publisher_manager:lock_key                           | PUBLISHER_MANAGER__LOCK_KEY                           | publisher_manager_lock           | Lock key for the manager in Redis                      |
| publisher_manager:interval                           | PUBLISHER_MANAGER__INTERVAL                           | 10000                            | Interval to send notifications / digests (in ms)       |
| publisher_manager:enable_buffering                   | PUBLISHER_MANAGER__ENABLE_BUFFERING                   | `true`                           | Enable/disable buffering of messages                   |
| publisher_manager:buffering_seconds                  | PUBLISHER_MANAGER__BUFFERING_SECONDS                  | 60                               | Buffering windows used (in seconds)                    |
| -                                                    | -                                                     | -                                | -                                                      |
| ingestion_manager:enabled                            | INGESTION_MANAGER__ENABLED                            | `true`                           | Enable/disable the ingestion manager                   |
| ingestion_manager:lock_key                           | INGESTION_MANAGER__LOCK_KEY                           | ingestion_manager_lock           | Lock key for the manager in Redis                      |
| ingestion_manager:interval                           | INGESTION_MANAGER__INTERVAL                           | 30000                            | Interval to check for new data in remote feeds         |
| ingestion_manager:rss_feed:min_interval_minutes      | INGESTION_MANAGER__RSS_FEED__MIN_INTERVAL_MINUTES     | 5                                | Minimum interval before requesting again same RSS Feed |
| ingestion_manager:rss_feed:user_agent                | INGESTION_MANAGER__RSS_FEED__USER_AGENT               |                                  | User agent to use for RSS Feed requests                |
| ingestion_manager:csv_feed:min_interval_minutes      | INGESTION_MANAGER__CSV_FEED__MIN_INTERVAL_MINUTES     | 5                                | Minimum interval before requesting again same CSV Feed |
| -                                                    | -                                                     | -                                | -                                                      |
| playbook_manager:enabled                             | PLAYBOOK_MANAGER__ENABLED                             | `true`                           | Enable/disable the playbook manager                    |
| playbook_manager:lock_key                            | PLAYBOOK_MANAGER__LOCK_KEY                            | publisher_manager_lock           | Lock key for the manager in Redis                      |
| playbook_manager:interval                            | PLAYBOOK_MANAGER__INTERVAL                            | 60000                            | Interval to check new playbooks                        |
| -                                                    | -                                                     | -                                | -                                                      |
| activity_manager:enabled                             | ACTIVITY_MANAGER__ENABLED                             | `true`                           | Enable/disable the activity manager                    |
| activity_manager:lock_key                            | ACTIVITY_MANAGER__LOCK_KEY                            | activity_manager_lock            | Lock key for the manager in Redis                      |
| -                                                    | -                                                     | -                                | -                                                      |
| connector_manager:enabled                            | CONNECTOR_MANAGER__ENABLED                            | `true`                           | Enable/disable the connector manager                   |
| connector_manager:lock_key                           | CONNECTOR_MANAGER__LOCK_KEY                           | connector_manager_lock           | Lock key for the manager in Redis                      |
| connector_manager:works_day_range                    | CONNECTOR_MANAGER__WORKS_DAY_RANGE                    | 7                                | Days range before considering the works as too old     |
| connector_manager:interval                           | CONNECTOR_MANAGER__INTERVAL                           | 10000                            | Interval to check the state of the works               |
| -                                                    | -                                                     | -                                | -                                                      |
| import_csv_built_in_connector:enabled                | IMPORT_CSV_BUILT_IN_CONNECTOR__ENABLED                | `true`                           | Enable/disable the csv import connector                |
| import_csv_built_in_connector:validate_before_import | IMPORT_CSV_BUILT_IN_CONNECTOR__VALIDATE_BEFORE_IMPORT | `false`                          | Validates the bundle before importing                  |
| -                                                    | -                                                     | -                                | -                                                      |
| file_index_manager:enabled                           | FILE_INDEX_MANAGER__ENABLED                           | `true`                           | Enable/disable the file indexing manager               |
| file_index_manager:stream_lock_key                   | FILE_INDEX_MANAGER__STREAM_LOCK                       | file_index_manager_stream_lock   | Stream lock key for the manager in Redis               |
| file_index_manager:interval                          | FILE_INDEX_MANAGER__INTERVAL                          | 60000                            | Interval to check for new files                        |
| -                                                    | -                                                     | -                                | -                                                      |
| indicator_decay_manager:enabled                      | INDICATOR_DECAY_MANAGER__ENABLED                      | `true`                           | Enable/disable the indicator decay manager             |
| indicator_decay_manager:lock_key                     | INDICATOR_DECAY_MANAGER__LOCK_KEY                     | indicator_decay_manager_lock     | Lock key for the manager in Redis                      |
| indicator_decay_manager:interval                     | INDICATOR_DECAY_MANAGER__INTERVAL                     | 60000                            | Interval to check for indicators to update             |
| indicator_decay_manager:batch_size                   | INDICATOR_DECAY_MANAGER__BATCH_SIZE                   | 10000                            | Number of indicators handled by the manager            |
| -                                                    | -                                                     | -                                | -                                                      |
| garbage_collection_manager:enabled                   | GARBAGE_COLLECTION_MANAGER__ENABLED                   | `true`                           | Enable/disable the trash manager                       |
| garbage_collection_manager:lock_key                  | GARBAGE_COLLECTION_MANAGER__LOCK_KEY                  | garbage_collection_manager_lock  | Lock key for the manager in Redis                      |
| garbage_collection_manager:interval                  | GARBAGE_COLLECTION_MANAGER__INTERVAL                  | 60000                            | Interval to check for trash elements to delete         |
| garbage_collection_manager:batch_size                | GARBAGE_COLLECTION_MANAGER__BATCH_SIZE                | 10000                            | Number of trash elements to delete at once             |
| garbage_collection_manager:deleted_retention_days    | GARBAGE_COLLECTION_MANAGER__DELETED_RETENTION_DAYS    | 7                                | Days after which elements in trash are deleted         |
| -                                                    | -                                                     | -                                | -                                                      |
| telemetry_manager:lock_key                           | TELEMETRY_MANAGER__LOCK_LOCK                          | telemetry_manager_lock           | Lock key for the manager in Redis                      |


!!! note "Manager's duties"
    
    A description of each manager's duties is available on [a dedicated page](managers.md).

## Worker and connector

Can be configured manually using the configuration file `config.yml` or through environment variables.

| Parameter                      | Environment variable           | Default value | Description                                                |
|:-------------------------------|:-------------------------------|:--------------|:-----------------------------------------------------------|
| opencti:url                    | OPENCTI_URL                    |               | The URL of the OpenCTI platform                            |
| opencti:token                  | OPENCTI_TOKEN                  |               | A token of an administrator account with bypass capability |
| -                              | -                              | -             | -                                                          |
| mq:use_ssl                     | /                              | /             | Depending of the API configuration (fetch from API)        |
| mq:use_ssl_ca                  | MQ_USE_SSL_CA                  |               | Path or ca content                                         |
| mq:use_ssl_cert                | MQ_USE_SSL_CERT                |               | Path or cert content                                       |
| mq:use_ssl_key                 | MQ_USE_SSL_KEY                 |               | Path or key content                                        |
| mq:use_ssl_passphrase          | MQ_USE_SSL_PASSPHRASE          |               | Passphrase for the key certificate                         |
| mq:use_ssl_reject_unauthorized | MQ_USE_SSL_REJECT_UNAUTHORIZED | `false`       | Reject rabbit self signed certificate                      |

### Worker specific configuration

#### Logging

| Parameter                      | Environment variable           | Default value | Description                                                |
|:-------------------------------|:-------------------------------|:--------------|:-----------------------------------------------------------|
| worker:log_level               | WORKER_LOG_LEVEL               | info          | The log level (error, warning, info or debug)              |

#### Technical

| Parameter               | Environment variable           | Default value | Description                                                                                                                                                              |
|:------------------------|:-------------------------------|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| worker:objects_max_refs | WORKER_OBJECTS_MAX_REFS               | 0             | The refs amount threshold: if set to a value higher than 0, all objects that have a number of refs higher than this will be sent to a dead letter queue and not ingested |

#### Telemetry

| Parameter                          | Environment variable               | Default value | Description                               |
|:-----------------------------------|:-----------------------------------|:--------------|:------------------------------------------|
| worker:telemetry_enabled           | WORKER_TELEMETRY_ENABLED           | false         | Enable the Prometheus endpoint            |
| worker:telemetry_prometheus_port   | WORKER_PROMETHEUS_TELEMETRY_PORT   | 14270         | Port of the Prometheus endpoint           |
| worker:telemetry_prometheus_host   | WORKER_PROMETHEUS_TELEMETRY_HOST   | 0.0.0.0       | Listen address of the Prometheus endpoint |

### Connector specific configuration

For specific connector configuration, you need to check each connector behavior.

## ElasticSearch

If you want to adapt the memory consumption of ElasticSearch, you can use these options:

```bash
# Add the following environment variable:
"ES_JAVA_OPTS=-Xms8g -Xmx8g"
```

This can be done in configuration file in the `jvm.conf` file.
