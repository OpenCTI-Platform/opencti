---
id: version-3.0.0-configuration
title: Configuration
sidebar_label: Configuration
original_id: configuration
---


## Parameters

In this section, we learn how to configure OpenCTI to have it tailored to our production and development needs. Here are the configuration keys, for both Docker and manual deployment.

### Platform

| Manual                   | Docker                | Default                               | Description                                               |
| -------------------------| ----------------------| --------------------------------------| ----------------------------------------------------------|
| app:port                 | APP__PORT             | 4000                                  | Listen port of the application                            |
| app:logs                 | APP__LOGS             | ./logs                                | Logs directory (logs are also rendered to stdout)         |
| app:logs_level           | APP__LOGS_LEVEL       | info                                  | Log level: `debug`,`info`,`warning`,`error`               |
| app:cookie_secure        | APP__COOKIE_SECURE    | `false`                               | Turn on if your app is in `https`                         |
| app:base_path            | APP_PORT              |                                       | Specific URI (ie: `/opencti`)                             |
| app:platform_demo        | APP_PORT              | `false`                               | *Reserved*                                                |
| app:admin:email          | APP__ADMIN__EMAIL     | admin@opencti.io                      | Default login email of the admin user                     |
| app:admin:password       | APP__ADMIN__PASSWORD  | *ChangeMe*                            | Default password of the admin user                        |
| app:admin:token          | APP__ADMIN__TOKEN     | *ChangeMe*                            | Default token (must be a valid `UUIDv4`                   |

### Services

| Manual                      | Docker                      | Default                               | Description                                               |
| ----------------------------| ----------------------------| --------------------------------------| ----------------------------------------------------------|
| grakn:hostname              | GRAKN__HOSTNAME             | localhost                             | Hostname of the Grakn Core Server                         |
| grakn:port                  | GRAKN__PORT                 | 48555                                 | Port of the Grakn Core Server                             |
| grakn:timeout               | GRAKN__TIMEOUT              | 30000                                 | Timeout of the GRPC Grakn Client                          |
| redis:hostname              | REDIS__HOSTNAME             | localhost                             | Hostname of the Redis Server                              |
| redis:port                  | REDIS__PORT                 | 6379                                  | Port of the Redis Server                                  |
| elasticsearch:url           | ELASTICSEARCH__URL          | http://localhost:9200                 | URL of the ElasticSearch Server                           |
| elasticsearch:noQueryCache  | ELASTICSEARCH__NOQUERYCACHE | `false`                               | Disable ElasticSearch caching of select queries           |
| minio:endpoint              | MINIO__ENDPOINT             | localhost                             | Hostname of the Minio server                              |
| minio:port                  | MINIO__PORT                 | 9000                                  | Port of the Minio server                                  |
| minio:use_ssl               | MINIO__USE_SSL              | `false`                               | Is the Minio Server has SSL enabled                       |
| minio:access_key            | MINIO__ACCESS_KEY           | *ChangeMe*                            | The Minio Server access key                               |
| minio:secret_key            | MINIO__SECRET_KEY           | *ChangeMe*                            | The Minio Server secret key                               |
| rabbitmq:hostname           | RABBITMQ__HOSTNAME          | localhost                             | Hostname of the RabbitMQ server                           |
| rabbitmq:port               | RABBITMQ__PORT              | 5672                                  | Port of the RabbitMQ server                               |
| rabbitmq:port_management    | RABBITMQ__PORT_MANAGEMENT   | 15672                                 | Port of the RabbitMQ Management Plugin                    |
| rabbitmq:management_ssl     | RABBITMQ__MANAGEMENT_SSL    | `false`                               | Is the Management Plugin has SSL enabled                  |
| rabbitmq:username           | RABBITMQ__USERNAME          | guest                                 | RabbitMQ user                                             |
| rabbitmq:password           | RABBITMQ__PASSWORD          | guest                                 | RabbitMQ password                                         |


### Authentication

OpenCTI supports several authentication providers. If you configure multiple strategies, they will be tested in the order you declared them.

Here are one example for the `production.json` file:

```yaml
"providers": {
    "local": {
      "strategy": "LocalStrategy"
    },
    "ldap": {
      "strategy": "LdapStrategy",
      "config": {
        "url": "ldap://mydc.limeo.org:389",
        "bind_dn": "cn=Administrator,cn=Users,dc=limeo,dc=org",
        "bind_credentials": "XXXXXXXXXX",
        "search_base": "cn=Users,dc=limeo,dc=org",
        "search_filter": "(cn={{username}})",
        "email_attribute": "userPrincipalName",
        "account_attribute": "name"
      }
    },
    "facebook": {
      "strategy": "FacebookStrategy",
      "config": {
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://demo.opencti.io/auth/facebook/callback"
      }
    },
    "google": {
      "strategy": "GoogleStrategy",
      "config": {
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://demo.opencti.io/auth/google/callback"
      }
    },
    "github": {
      "strategy": "GithubStrategy",
      "config": {
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://demo.opencti.io/auth/github/callback"
      }
    }
  }
```

An other example for the LDAP Strategy with `docker-compose.yml`:

```yaml
- PROVIDERS__LDAP__STRATEGY=LdapStrategy
- PROVIDERS__LDAP__CONFIG__URL=ldap://mydc.limeo.org:389
- PROVIDERS__LDAP__CONFIG__BIND_DN=cn=Administrator,cn=Users,dc=limeo,dc=org
- PROVIDERS__LDAP__CONFIG__BIND_CREDENTIALS=XXXXXXXXXX
- PROVIDERS__LDAP__CONFIG__SEARCH_BASE=cn=Users,dc=limeo,dc=org
- PROVIDERS__LDAP__CONFIG__SEARCH_FILTER=(cn={{username}})
- PROVIDERS__LDAP__CONFIG__EMAIL_ATTRIBUTE=userPrincipalName
- PROVIDERS__LDAP__CONFIG__ACCOUNT_ATTRIBUTE=name
```

## Maintenance

### Reindexing ElasticSearch

If you need to reindex your data in ElasticSearch, we provide a command to run:

```bash
$ yarn index
```
