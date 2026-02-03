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

### LDAP mock

### Cyberark mock

In docker-compose file `opencti-mokapi`

```
docker compose --profile mockapi up -d
podman compose --profile mockapi up -d
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
          "object": "secret",
          "https_cert": {
            "reject_unauthorized": false
          }
        }
      }
    }
  }
}
```