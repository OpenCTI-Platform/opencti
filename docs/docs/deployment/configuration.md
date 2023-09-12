# Configuration

The purpose of this section is to learn how to configure OpenCTI to have it tailored for your production and development needs. 
 
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

| Parameter                   | Environment variable       | Default value         | Description                                                      |
| :-------------------------- |:---------------------------|:----------------------|:-----------------------------------------------------------------|
| app:port                    | APP__PORT                  | 4000                  | Listen port of the application                                   |
| app:base_path               | APP__BASE_PATH             |                       | Specific URI (ie. /opencti)                                      |
| app:base_url                | APP__BASE_URL              | http://localhost:4000 | Full URL of the platform (should include the `base_path` if any) |
| app:request_timeout         | APP__REQUEST_TIMEOUT       | 1200000               | Request timeout, in ms (default 20 minutes)                      |
| app:session_timeout         | APP__SESSION_TIMEOUT       | 0                     | Session timeout, in ms (default 0 minute - disabled)             |
| app:session_idle_timeout    | APP__SESSION_IDLE_TIMEOUT  | 1200000               | Idle timeout, in ms (default 20 minutes)                         |
| app:admin:email             | APP__ADMIN__EMAIL          | admin@opencti.io      | Default login email of the admin user                            |
| app:admin:password          | APP__ADMIN__PASSWORD       | ChangeMe              | Default password of the admin user                               |
| app:admin:token             | APP__ADMIN__TOKEN          | ChangeMe              | Default token (must be a valid UUIDv4)                           |

#### SSL / TLS

| Parameter                          | Environment variable                            | Default value                 | Description                                                                                |
| :--------------------------------- | :---------------------------------------------- | :---------------------------- |:-------------------------------------------------------------------------------------------|
| app:https_cert:ca                  | APP__HTTPS_CERT__CA                             | Empty list []                 | Certificate authority paths or content, only if the client uses a self-signed certificate. |
| app:https_cert:key                 | APP__HTTPS_CERT__KEY                            |                               | Certificate key path or content                                                            |
| app:https_cert:crt                 | APP__HTTPS_CERT__CRT                            |                               | Certificate crt path or content                                                            |
| app:https_cert:reject_unauthorized | APP__HTTPS_CERT__REJECT_UNAUTHORIZED            |                               | If not false, the server certificate is verified against the list of supplied CAs          |

#### Logging

##### Errors

| Parameter                          | Environment variable                            | Default value                 | Description                                                                         |
| :--------------------------------- | :---------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------- |
| app:app_logs:logs_level            | APP__APP_LOGS__LOGS_LEVEL                       | info                          | The application log level                                                           |
| app:app_logs:logs_files            | APP__APP_LOGS__LOGS_FILES                       | `true`                        | If application logs is logged into files                                            |
| app:app_logs:logs_console          | APP__APP_LOGS__LOGS_CONSOLE                     | `true`                        | If application logs is logged to console (useful for containers)                    |
| app:app_logs:logs_max_files        | APP__APP_LOGS__LOGS_MAX_FILES                   | 7                             | Maximum number of daily files in logs                                               |
| app:app_logs:logs_directory        | APP__APP_LOGS__LOGS_DIRECTORY                   | ./logs                        | File logs directory                                                                 |

##### Audit

| Parameter                          | Environment variable                            | Default value                 | Description                                                                         |
| :--------------------------------- | :---------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------- |
| app:audit_logs:logs_files          | APP__AUDIT_LOGS__LOGS_FILES                     | `true`                        | If audit logs is logged into files                                                  |
| app:audit_logs:logs_console        | APP__AUDIT_LOGS__LOGS_CONSOLE                   | `true`                        | If audit logs is logged to console (useful for containers)                          |
| app:audit_logs:logs_max_files      | APP__AUDIT_LOGS__LOGS_MAX_FILES                 | 7                             | Maximum number of daily files in logs                                               |
| app:audit_logs:logs_directory      | APP__AUDIT_LOGS__LOGS_DIRECTORY                 | ./logs                        | Audit logs directory                                                                |

#### Maps & references

| Parameter                          | Environment variable                     | Default value                                              | Description                                                      |
| :--------------------------------- | :--------------------------------------- | :--------------------------------------------------------- | ---------------------------------------------------------------- |
| app:map_tile_server_dark           | APP__MAP_TILE_SERVER_DARK                | https://map.opencti.io/styles/luatix-dark/{z}/{x}/{y}.png  | The address of the OpenStreetMap provider with dark theme style  |
| app:map_tile_server_light          | APP__MAP_TILE_SERVER_LIGHT               | https://map.opencti.io/styles/luatix-light/{z}/{x}/{y}.png | The address of the OpenStreetMap provider with light theme style |
| app:reference_attachment           | APP__REFERENCE_ATTACHMENT                | `false`                                                    | External reference mandatory attachment                          |

#### Technical customization

| Parameter                                              | Environment variable                                    | Default value | Description                                                                         |
|:-------------------------------------------------------|:--------------------------------------------------------|:--------------| :---------------------------------------------------------------------------------- |
| app:graphql:playground:enabled                         | APP__GRAPHQL__PLAYGROUND__ENABLED                       | `true`        | Enable the playground on /graphql                                                   |
| app:graphql:playground:force_disabled_introspection    | APP__GRAPHQL_PLAYGROUND__FORCE_DISABLED_INTROSPECTION   | `false`       | Introspection is allowed to auth users but can be disabled in needed                |
| app:concurrency:retry_count                            | APP__CONCURRENCY__RETRY_COUNT                           | 200           | Number of try to get the lock to work an element (create/update/merge, ...)         |
| app:concurrency:retry_delay                            | APP__CONCURRENCY__RETRY_DELAY                           | 100           | Delay between 2 lock retry (in milliseconds)                                        |
| app:concurrency:retry_jitter                           | APP__CONCURRENCY__RETRY_JITTER                          | 50            | Random jitter to prevent concurrent retry  (in milliseconds)                        |
| app:concurrency:max_ttl                                | APP__CONCURRENCY__MAX_TTL                               | 30000         | Global maximum time for lock retry (in milliseconds)                                |

### Dependencies

#### ElasticSearch

| Parameter                              | Environment variable                    | Default value                 | Description                                                                             |
|:---------------------------------------| :-------------------------------------- | :---------------------------- |:----------------------------------------------------------------------------------------|
| elasticsearch:engine_selector          | ELASTICSEARCH__ENGINE_SELECTOR          | auto                          | `elk` or `opensearch`, default is `auto`, please put `elk` if you use token auth.       |
| elasticsearch:url                      | ELASTICSEARCH__URL                      | http://localhost:9200         | URL(s) of the ElasticSearch (supports http://user:pass@localhost:9200 and list of URLs) |
| elasticsearch:username                 | ELASTICSEARCH__USERNAME                 |                               | Username can be put in the URL or with this parameter                                   |
| elasticsearch:password                 | ELASTICSEARCH__PASSWORD                 |                               | Password can be put in the URL or with this parameter                                   |
| elasticsearch:api_key                  | ELASTICSEARCH__API_KEY                  |                               | API key for ElasticSearch token auth. Please set also `engine_selector` to `elk`        |
| elasticsearch:index_prefix             | ELASTICSEARCH__INDEX_PREFIX             | opencti                       | Prefix for the indices                                                                  |
| elasticsearch:ssl:reject_unauthorized  | ELASTICSEARCH__SSL__REJECT_UNAUTHORIZED | `true`                        | Enable TLS certificate check                                                            |
| elasticsearch:ssl:ca                   | ELASTICSEARCH__SSL__CA                  |                               | Custom certificate path or content                                                      |
| elasticsearch:ssl:ca_plain (depecated) | ELASTICSEARCH__SSL__CA_PLAIN            |                               | @depecated, use ca directly                                                             |

#### Redis

| Parameter                          | Environment variable                          | Default value                 | Description                                                                         |
| :--------------------------------- | :-------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------- |
| redis:mode                         | REDIS__MODE                                   | single                        | Connect to redis "single" or "cluster"                                              |
| redis:namespace                    | REDIS__NAMESPACE                              |                               | Namespace (to use as prefix)                                                        |
| redis:hostname                     | REDIS__HOSTNAME                               | localhost                     | Hostname of the Redis Server                                                        |
| redis:hostnames                    | REDIS__HOSTNAMES                              |                               | Hostnames definition for Redis cluster mode: a list of host/port objects.           |
| redis:port                         | REDIS__PORT                                   | 6379                          | Port of the Redis Server                                                            |
| redis:use_ssl                      | REDIS__USE_SSL                                | `false`                       | Is the Redis Server has TLS enabled                                                 |
| redis:username                     | REDIS__USERNAME                               |                               | Username of the Redis Server                                                        |
| redis:password                     | REDIS__PASSWORD                               |                               | Password of the Redis Server                                                        |
| redis:ca                           | REDIS__CA                                     |                               | Path of the CA certificate                                                          |
| redis:trimming                     | REDIS__TRIMMING                               | 2000000                       | Number of elements to maintain in the stream. (0 = unlimited)                       |

#### RabbitMQ

| Parameter                                   | Environment variable              | Default value  | Description                                 |
|:--------------------------------------------|:----------------------------------|:---------------|:--------------------------------------------|
| rabbitmq:hostname                           | RABBITMQ__HOSTNAME                | localhost      | Hostname of the RabbitMQ server             |
| rabbitmq:port                               | RABBITMQ__PORT                    | 5672           | Port of the RabbitMQ server                 |
| rabbitmq:port_management                    | RABBITMQ__PORT_MANAGEMENT         | 15672          | Port of the RabbitMQ Management Plugin      |
| rabbitmq:username                           | RABBITMQ__USERNAME                | guest          | RabbitMQ user                               |
| rabbitmq:password                           | RABBITMQ__PASSWORD                | guest          | RabbitMQ password                           |
| rabbitmq:queue_type                         | RABBITMQ__QUEUE_TYPE              | "classic"      | RabbitMQ Queue Type ("classic" or "quorum") |
| -                                           | -                                 | -              | -                                           |
| rabbitmq:use_ssl                            | RABBITMQ__USE_SSL                 | `false`        | Use TLS connection                          |                                                |                               |                                                                                     |
| rabbitmq:use_ssl_cert                       | RABBITMQ__USE_SSL_CERT            |                | Path or cert content                        |
| rabbitmq:use_ssl_key                        | RABBITMQ__USE_SSL_KEY             |                | Path or key content                         |
| rabbitmq:use_ssl_pfx                        | RABBITMQ__USE_SSL_PFX             |                | Path or pfx content                         |
| rabbitmq:use_ssl_ca                         | RABBITMQ__USE_SSL_CA              |                | Path or cacert content                      |
| rabbitmq:use_ssl_passphrase                 | RABBITMQ__SSL_PASSPHRASE          |                | Passphrase for the key certificate          |
| rabbitmq:use_ssl_reject_unauthorized        | RABBITMQ__SSL_REJECT_UNAUTHORIZED | `false`        | Reject rabbit self signed certificate       |
| -                                           | -                                 | -              | -                                           |
| rabbitmq:management_ssl                     | RABBITMQ__MANAGEMENT_SSL          | `false`        | Is the Management Plugin has TLS enabled    |                                                |                               |                                                                                     |
| rabbitmq:management_ssl_reject_unauthorized | RABBITMQ__SSL_REJECT_UNAUTHORIZED | `true`         | Reject management self signed certificate   |

#### S3 Bucket

| Parameter                          | Environment variable                            | Default value                 | Description                                                                         |
| :--------------------------------- | :---------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------- |
| minio:endpoint                     | MINIO__ENDPOINT                                 | localhost                     | Hostname of the S3 Service                                                          |
| minio:port                         | MINIO__PORT                                     | 9000                          | Port of the S3 Service                                                              |
| minio:use_ssl                      | MINIO__USE_SSL                                  | `false`                       | Is the S3 Service has TLS enabled                                                   |
| minio:access_key                   | MINIO__ACCESS_KEY                               | ChangeMe                      | The S3 Service access key                                                           |
| minio:secret_key                   | MINIO__SECRET_KEY                               | ChangeMe                      | The S3 Service secret key                                                           |
| minio:bucket_name                  | MINIO__BUCKET_NAME                              | opencti-bucket                | The S3 bucket name (useful to change if you use AWS)                                |
| minio:bucket_region                | MINIO__BUCKET_REGION                            | us-east-1                     | The S3 bucket region if you use AWS                                                 |
| minio:use_aws_role                 | MINIO__USE_AWS_ROLE                             | `false`                       | To use AWS role auto credentials                                                    |

#### SMTP Service

| Parameter                          | Environment variable                            | Default value                 | Description                                                                         |
| :--------------------------------- | :---------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------- |
| smtp:hostname                      | SMTP__HOSTNAME                                  |                               | SMTP Server hostname                                                                |
| smtp:port                          | SMTP__PORT                                      | 9000                          | SMTP Port (25 or 465 for TLS)                                                       |
| smtp:use_ssl                       | SMTP__USE_SSL                                   | `false`                       | SMTP over TLS                                                                       |
| smtp:reject_unauthorized           | SMTP__REJECT_UNAUTHORIZED                       | `false`                       | Enable TLS certificate check                                                        |
| smtp:username                      | SMTP__USERNAME                                  |                               | SMTP Username if authentication is needed                                           |
| smtp:password                      | SMTP__PASSWORD                                  |                               | SMTP Password if authentication is needed                                           |
| smtp:from_email                    | SMTP__FROM_EMAIL                                | notifications@opencti.io      | Sender email address                                                                |

### Schedules & Engines

| Parameter                          | Environment variable                            | Default value                 | Description                                                                         |
| :--------------------------------- | :---------------------------------------------- | :---------------------------- | :---------------------------------------------------------------------------------- |
| rule_engine:enabled                | RULE_ENGINE__ENABLED                            | `true`                        | Enable/disable the rule engine                                                      |
| rule_engine:lock_key               | RULE_ENGINE__LOCK_KEY                           | rule_engine_lock              | Lock key of the engine in Redis                                                     |
| -                                  | -                                               | -                             | -                                                                                   |
| history_manager:enabled            | HISTORY_MANAGER__ENABLED                        | `true`                        | Enable/disable the history manager                                                  |
| history_manager:lock_key           | HISTORY_MANAGER__LOCK_KEY                       | history_manager_lock          | Lock key for the manager in Redis                                                   |
| -                                  | -                                               | -                             | -                                                                                   |
| task_scheduler:enabled             | TASK_SCHEDULER__ENABLED                         | `true`                        | Enable/disable the task scheduler                                                   |
| task_scheduler:lock_key            | TASK_SCHEDULER__LOCK_KEY                        | task_manager_lock             | Lock key for the scheduler in Redis                                                 |
| task_scheduler:interval            | TASK_SCHEDULER__INTERVAL                        | 10000                         | Interval to check new task to do (in ms)                                            |
| -                                  | -                                               | -                             | -                                                                                   |
| sync_manager:enabled               | SYNC_MANAGER__ENABLED                           | `true`                        | Enable/disable the sync manager                                                     |
| sync_manager:lock_key              | SYNC_MANAGER__LOCK_KEY                          | sync_manager_lock             | Lock key for the manager in Redis                                                   |
| sync_manager:interval              | SYNC_MANAGER__INTERVAL                          | 10000                         | Interval to check new sync feeds to consume (in ms)                                 |
| -                                  | -                                               | -                             | -                                                                                   |
| expiration_scheduler:enabled       | EXPIRATION_SCHEDULER__ENABLED                   | `true`                        | Enable/disable the scheduler                                                        |
| expiration_scheduler:lock_key      | EXPIRATION_SCHEDULER__LOCK_KEY                  | expired_manager_lock          | Lock key for the scheduler in Redis                                                 |
| expiration_scheduler:interval      | EXPIRATION_SCHEDULER__INTERVAL                  | 300000                        | Interval to check expired indicators                                                |
| -                                  | -                                               | -                             | -                                                                                   |
| retention_manager:enabled          | RETENTION_MANAGER__ENABLED                      | `true`                        | Enable/disable the manager                                                          |
| retention_manager:lock_key         | RETENTION_MANAGER__LOCK_KEY                     | retention_manager_lock        | Lock key for the manager in Redis                                                   |
| retention_manager:interval         | RETENTION_MANAGER__INTERVAL                     | 60000                         | Interval to check items to be deleted                                               |
| -                                  | -                                               | -                             | -                                                                                   |
| notification_manager:enabled       | NOTIFICATION_MANAGER__ENABLED                   | `true`                        | Enable/disable the notification manager                                             |
| notification_manager:lock_key      | NOTIFICATION_MANAGER__LOCK_KEY                  | notification_manager_lock     | Lock key for the manager in Redis                                                   |
| notification_manager:interval      | NOTIFICATION_MANAGER__INTERVAL                  | 10000                         | Sender email address                                                                |
| -                                  | -                                               | -                             | -                                                                                   |
| publisher_manager:enabled          | PUBLISHER_MANAGER__ENABLED                      | `true`                        | Enable/disable the publisher manager                                                |
| publisher_manager:lock_key         | PUBLISHER_MANAGER__LOCK_KEY                     | publisher_manager_lock        | Sender email address                                                                |
| publisher_manager:interval         | PUBLISHER_MANAGER__INTERVAL                     | 10000                         | Sender email address                                                                |

!!! note "Default file"
    
    It is possible to check all default parameters implemented in the platform in the [`default.json` file](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/config/default.json).

## Worker and connector

Can be configured manually using the configuration file `config.yml` or through environment variables.

| Parameter                      | Environment variable           | Default value | Description                                                |
|:-------------------------------|:-------------------------------|:--------------|:-----------------------------------------------------------|
| opencti:url                    | OPENCTI_URL                    |               | The URL of the OpenCTI platform                            |
| opencti:token                  | OPENCTI_TOKEN                  |               | A token of an administrator account with bypass capability |
| -                              | -                              | -             | -                                                          |
| mq:use_ssl                     | /                              | /             | Depending of the API configuration (fetch from API)        |
| mq:use_ssl_ca                  | MQ_USE_SSL_CA                  |               | Path or cacert content                                     |
| mq:use_ssl_cert                | MQ_USE_SSL_CERT                |               | Path or cert content                                       |
| mq:use_ssl_key                 | MQ_USE_SSL_KEY                 |               | Path or key content                                        |
| mq:use_ssl_passphrase          | MQ_USE_SSL_PASSPHRASE          |               | Passphrase for the key certificate                         |
| mq:use_ssl_reject_unauthorized | MQ_USE_SSL_REJECT_UNAUTHORIZED | `false`       | Reject rabbit self signed certificate                      |

### Worker specific configuration

| Parameter                      | Environment variable           | Default value | Description                                                |
|:-------------------------------|:-------------------------------|:--------------|:-----------------------------------------------------------|
| worker:log_level               | WORKER_LOG_LEVEL               | info          | The log level (error, warning, info or debug)              |

### Connector specific configuration

For specific connector configuration, you need to check each connector behavior.

## ElasticSearch

If you want to adapt the memory consumption of ElasticSearch, you can use theses options:

```bash
# Add the following environment variable:
"ES_JAVA_OPTS=-Xms8g -Xmx8g"
```

This can be done in configuration file in the `jvm.conf` file.
