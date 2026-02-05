# Tool usefully for development purpose

## docker compose / podman compose part

```
docker compose up -d
podman compose up -d
```

Will start:
- elasticsearch + Kibana (`opencti-dev-elasticsearch` & `opencti-dev-kibana`)
- rabbitMq (`opencti-dev-rabbitmq`)
- MinIO (`opencti-dev-minio`)
- Redis + redis insight (`opencti-dev-redis` & `opencti-dev-redis-insight`)
- [Fake smtp server](#fake-smtp-server) (`opencti-dev-smtp`)

Optionally additional services can be started:
- [Keycloak as OpenID and SAML providers](#keycloak-as-openid-and-saml-idp)
- [Opensearch instead of elasticsearch](#opensearch--opensearch-dashboard-instead-of-elasticsearch--kibana)
- [A mock as LDAP provider](#ldap-mock)
- [A mock as Cyber Ark provider](#cyberark-mock)

### Fake SMTP server

In `development.json` configuration:

```json
{
  "smtp": {
    "hostname": "localhost",
    "use_ssl": false,
    "rejectUnauthorized": false,
    "port": 1025
  }
}
```

- You can see email at [http://localhost:1025](http://localhost:1025)

### Opensearch + opensearch dashboard instead of elasticsearch + kibana

```
docker compose --profile opensearch up -d
podman compose --profile opensearch up -d
```

You need to stop elasticsearch and kibana that are in the default setup:
```
docker compose stop opencti-dev-elasticsearch opencti-dev-kibana
podman compose stop opencti-dev-elasticsearch opencti-dev-kibana
```

In opencti configuration you can now setup OpenSearch:

`development.json`
```json
{
  "elasticsearch": {
    "url": "http://localhost:9201",
    "username": "admin",
    "password": "GraceH00per!"
  }
}
```

Dashboard on [http://localhost:5602](http://localhost:5602).

### Keycloak as OpenID and SAML IDP

Keycloak is automatically setup with some users and groups. See [keycloak-configuration/master-users-0.json](keycloak-configuration/master-users-0.json)
- All password are `admin`
- You can try for example with connector@filigran.io / admin

In docker-compose file `opencti-mokapi`

```
docker compose --profile keycloak up -d
podman compose --profile keycloak up -d
```

In SSO configuration for SAML:
```json
{
"saml": {
      "identifier": "saml",
      "strategy": "SamlStrategy",
      "config": {
        "issuer": "openctisaml",
        "label": "SAML",
        "entry_point": "http://localhost:9999/realms/master/protocol/saml",
        "saml_callback_url": "http://localhost:4000/auth/saml/callback",
        "cert": "MIICmzCCAYMCBgGbiFigqTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjYwMTA0MDkyOTI4WhcNMzYwMTA0MDkzMTA4WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDluAl7r07cXwEpCgnXiOxlghynbf//M4h4d35YxX9gIO918kHkDUN0Slm+jT6cJT9J/FZdF960xe3L0buHvYasfWwU/YE2cZhiBrsv+Ag3p6950LKq3T91GtvFyvLANbSb5lAoY29HBTDZTIme+3rzVPFpl+LQMz1Wajx5y5KjtzddIDgXX7VWGzUicuVM1O1hGYNqCAZksOgUbRP9WWfxGcs01uFMMtbr8QdKH1S8kvJdMXqHS9vqz3y7EeM+O7rnU3ete7tbtLjb4GjdjbQK+W6JcH/vNg5UwJEsR/ZQOnI8oT8K8PMMICai+S6cTs6g5L8+UFOTlM/YMK5LFbI5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBADf9Aj0607hPwHkGh9IdGgZm4Xs2E5v9Bzh7qtfxInJAErhZmChc/6AwNwkCIsGXPb6LRK+BGu2EIY8G3WvoBWQK2s16OSSH3QENA+GWIVLqHibEY+oLfoFmtyTGo/5TqXHZ/XlLFxyn+6BUpdZyr4p406uhKx2PCYHgDziLsDo1c/56AnjUbehEI30gCGCI3F0NYfxYzsnCJGK8ZzOzU2h9/Bfemt0t9gQUcwVJn6QHvKnT5mNO1qzJPRBwpz1GiB9P5+UT0SAnt+oxIAH5Gtwr0qI5sb9ZIAaS2FJut/cqiTsKzSjpRBE/AwsyU915Eyygy3HUjVxTxqH0BZga178=",
        "logout_remote": false,
        "want_assertions_signed": false,
        "want_authn_response_signed": false,
        "audience": false,
        "auto_create_group": true,
        "prevent_default_groups": false,
        "groups_management": {
          "group_attributes": [
            "member"
          ],
          "groups_mapping": [
            "/Connector:Connectors",
            "/Administrator:Administrators",
            "/Default:Default"
          ]
        },
        "organizations_management": {
          "organizations_path": [
            "member"
          ],
          "organizations_mapping": [
            "/Filigran org:Filigran"
          ]
        }
      }
    }
}
```
In SSO configuration for OpenID:

```
{
"oick": {
      "identifier": "oick",
      "strategy": "OpenIDConnectStrategy",
      "enabled": true,
      "config": {
        "organizations_default": ["Filigran"],
        "label": "OpenID K",
        "issuer": "http://localhost:9999/realms/master",
        "client_id": "openctioid",
        "client_secret": "aOBaQuG6WVoQ4FKhOdIWOOdJp9e0M1Fc",
        "redirect_uris": [
          "http://localhost:4000/auth/oick/callback"
        ],
        "logout_remote": true,
        "prevent_default_groups": false,
        "auto_create_group": true,
        "groups_management": {
          "groups_path": [
            "groups"
          ],
          "groups_mapping": [
            "/Connector:Connectors",
            "/Administrator:Administrators",
            "/Default:Default"
          ],
          "read_userinfo": false,
          "token_reference": "access_token"
        },
        "organizations_management": {
          "organizations_path": [
            "groups"
          ],
          "organizations_mapping": [
            "/Filigran org:Filigran"
          ],
          "read_userinfo": false,
          "token_reference": "access_token"
        }
      }
    },
}
```

### LDAP mock

In docker-compose file `opencti-mokapi`

```
docker compose --profile mokapi up -d
podman compose --profile mokapi up -d
```

Users can be find in [mock-api/users.ldif](mock-api/users.ldif)

You can try for example with `bob@bob.com` and password `bob`

In SSO configuration:
```json
{
"ldap": {
      "strategy": "LdapStrategy",
      "config": {
        "url": "ldap://localhost:389",
        "bind_dn": "dc=mokapi,dc=io",
        "search_base": "ou=people,dc=mokapi,dc=io",
        "group_search_base": "ou=groups,dc=mokapi,dc=io",
        "group_search_filter": "(member={{dn}})",
        "search_filter": "mail={{username}}",
        "mail_attribute": "mail",
        "account_attribute": "givenName",
        "firstname_attribute": "cn",
        "allow_self_signed": true,
        "groups_management": {
          "groups_mapping": [
            "Developers:Connectors",
            "Admins:Administrators"
          ]
        }
      }
    }
}
```

### Cyberark mock

In docker-compose file `opencti-mokapi`

```
docker compose --profile mokapi up -d
podman compose --profile mokapi up -d
```

`development.json` configuration, be carefully that **identifier** matches the one in database (here oiccyberark).
```json
{
  "providers": {
    "oiccyberark": {
      "strategy": "OpenIDConnectStrategy",
      "identifier": "oiccyberark",
      "credentials_provider": {
        "selector": "cyberark",
        "cyberark": {
          "uri": "http://localhost:8090/AIMWebService/api/Accounts",
          "field_targets": [
            "client_secret"
          ],
          "app_id": "cyberark",
          "safe": "safe",
          "object": "secret"
        },
        "https_cert": {
          "reject_unauthorized": false
        }
      }
    }
  }
}
```