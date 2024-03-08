# How to use docker compose keycloak service

## Start the container

Keycloak is disabled by default, to start:

```shell
docker compose --profile openid up -d
```

Keycloak should be up and running at http://localhost:9999
Admin login is `admin/admin` (see docker-compose environments variables)

## Helper to init configuration and data

In keycloak folder you can find:

### Some users and groups

keycloak-realm-export.json : an export of some users and groups. You can use it with:

```shell
docker cp keycloak-realm-export.json opencti-dev-keycloak:/tmp
docker exec -ti opencti-dev-keycloak /opt/keycloak/bin/kc.sh import --file /tmp/realm-export.json
```

> Note: all users password is 'admin'

### SAML and Open ID client configuration

- saml-client.json: SAML client configuration
- openid-client.json: Open ID client configuration

To import, go on Keycloak UI, "Client", there is an "Import client" link.

On OpenCTI side, here are example of configuration:

```json
  "providers": {
    "local": {
      "strategy": "LocalStrategy"
    },
    "oic": {
      "identifier": "oic",
      "strategy": "OpenIDConnectStrategy",
      "config": {
        "label": "Login with OpenID",
        "issuer": "http://localhost:9999/realms/master",
        "client_id": "openctioid",
        "client_secret": "aOBaQuG6WVoQ4FKhOdIWOOdJp9e0M1Fc",
        "redirect_uris": ["http://localhost:3000/auth/oic/callback"],
        "logout_remote": true
      }
    },
    "saml": {
      "identifier": "saml",
      "strategy": "SamlStrategy",
      "config": {
        "issuer": "openctisaml",
        "entry_point": "http://localhost:9999/realms/master/protocol/saml",
        "saml_callback_url": "http://localhost:3000/auth/saml/callback",
        "cert": "MIICmzCCAYMCBgGNsQFxFDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwMjE2MDgxOTM4WhcNMzQwMjE2MDgyMTE4WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCe/ImiUIx3TCFwzm7xR/Scv9Yxc7fQC0FW4rZLSp9Jz+hm5YeUYi9S623US+rNs0VAgdE0YL7oVqk21YbD90j95lUXNDW+J6oJ+DmRwn4r0xaF1WJZU23TJ2VJzkqb6O8J5M2EonySCntasVsjxYFuRznm+VmhK1XTYiyO0agyx/7Tkcs3eEtlRN3JYp/fWvT2c5vz+UOt4xCZO77/PU1C6o8zPSl/3WkXEDMj4w+D3A5GjkDYX/u/S0USpw08rdY7tjwozGz+Zzp9naXWk5eiXh1BFgUYAcJxgo30xGyenGG8kVHxPLv06ySFstVwATcQpr0gP5MWG134O3i/yTnBAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACXj7312F2dCxE1w8R4WYj1Q62OoKFgshc2AMfcQkDO9X2tGqrsv0vbvgcvn61gvG2oXdBeRVut8r6jWKofGu5lr7JYBVBR+R5aFhstUY2cDdnlKFWaiHmkisCLV2e7TV/O1NRAPRSnI1syfz+q/Wc/PS2Z6LfnCJEuvDPbmk4X7PS4XNF077pnM5/61j9Pz4yNylAmOH+Y3MkPL1oe52TgRCVtYnPkbBR2pE/j3fzY6adN079sWdMqXLldDVnoUhw2a7JZjgUrMPx2pUCVuhMxIwuEdstmjNR87LhqpGpvjruTeDmgeSmgW9IfWO0kxuxYFiRd3VelJBa1i1xl/m9Q=",
        "logout_remote": true,
        "want_assertions_signed": false,
        "want_authn_response_signed": false,
        "config": {
          "groups_management": {
            "group_attributes": [
              "Group"
            ],
            "groups_mapping": [
              "group-admin:Administrator",
              "group-user:Default",
              "group-connector:Connector"
            ]
          }
        }
      }
    }
  }
```

> The more easy way to change from one user to another, is to use the "private tab" navigation in browser, one per user.