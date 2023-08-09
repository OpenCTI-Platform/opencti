# Authentication

## Introduction

OpenCTI supports several authentication providers. If you configure multiple strategies, they will be tested **in the order** you declared them.

!!! note "Activation"

    You need to configure/activate only that you really want to propose to your users in term of authentication

The product proposes two kind of authentication strategy:

- Form (asking user for a user/password)
- Buttons (click with authentication on an external system)

## Supported Strategies

Under the hood we technically use the strategies provided by [PassportJS](http://www.passportjs.org/). We integrate a subset of the strategies available with passport we if you need more we can theatrically integrate all the passport strategies.

### Local users (form)

This strategy used the OpenCTI database as user management.

OpenCTI use this strategy as the default but its not the one we recommend for security reason.

```json
"local": {
    "strategy": "LocalStrategy",
    "config": {
        "disabled": false
    }
}
```

!!! note "Production deployment"

    Please use the LDAP/Auth0/OpenID/SAML strategy for production deployment.

### LDAP (form)

This strategy can be used to authenticate your user with your company LDAP and is based on [Passport - LDAPAuth](http://www.passportjs.org/packages/passport-ldapauth).

```json
"ldap": {
    "strategy": "LdapStrategy",
    "config": {
        "url": "ldaps://mydc.domain.com:686",
        "bind_dn": "cn=Administrator,cn=Users,dc=mydomain,dc=com",
        "bind_credentials": "MY_STRONG_PASSWORD",
        "search_base": "cn=Users,dc=mydomain,dc=com",
        "search_filter": "(cn={{username}})",
        "mail_attribute": "mail",
        // "account_attribute": "givenName",
        // "firstname_attribute": "cn",
        // "lastname_attribute": "cn",
        "account_attrgroup_search_filteribute": "givenName",
        "allow_self_signed": true
    }
}
```

If you would like to use LDAP groups to automatically associate LDAP groups and OpenCTI groups/organizations:

```json
"ldap": {
    "config": {
        ...
        "group_search_base": "cn=Groups,dc=mydomain,dc=com",
        "group_search_filter": "(member={{dn}})",
        "groups_management": { // To map LDAP Groups to OpenCTI Groups
            "group_attribute": "cn",
            "groups_mapping": ["LDAP_Group_1:OpenCTI_Group_1", "LDAP_Group_2:OpenCTI_Group_2", ...]
        },
        "organizations_management": { // To map LDAP Groups to OpenCTI Organizations
            "group_attribute": "cn",
            "groups_mapping": ["LDAP_Group_1:OpenCTI_Organization_1", "LDAP_Group_2:OpenCTI_Organization_2", ...]
        }
    }
}
```

### SAML (button)

This strategy can be used to authenticate your user with your company SAML and is based on [Passport - SAML](http://www.passportjs.org/packages/passport-saml).

```json
"saml": {
    "identifier": "saml",
    "strategy": "SamlStrategy",
    "config": {
        "issuer": "mytestsaml",
        // "account_attribute": "nameID",
        // "firstname_attribute": "nameID",
        // "lastname_attribute": "nameID",
        "entry_point": "https://auth.mydomain.com/auth/realms/mydomain/protocol/saml",
        "saml_callback_url": "http://localhost:4000/auth/saml/callback",
        // "private_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwg...",
        "cert": "MIICmzCCAYMCBgF2Qt3X1zANBgkqhkiG9w0BAQsFADARMQ8w..."
    }
}
```

For the SAML strategy to work:

- The `cert` parameter is mandatory (PEM format) because it is used to validate the SAML response.
- The `private_key` (PEM format) is optional and is only required if you want to sign the SAML client request.

!!! note "Certificates"

    Be careful to put the `cert` / `private_key`  key in PEM format. Indeed, a lot of systems generally export the the keys in X509 / PCKS12 formats and so you will need to convert them. 
    Here is an example to extract PEM from PCKS12:
    ```bash
    openssl pkcs12 -in keystore.p12 -out newfile.pem -nodes
    ```

Here is an example of SAML configuration using environment variables:

```yaml
- PROVIDERS__SAML__STRATEGY=SamlStrategy 
- "PROVIDERS__SAML__CONFIG__LABEL=Login with SAML"
- PROVIDERS__SAML__CONFIG__ISSUER=mydomain
- PROVIDERS__SAML__CONFIG__ENTRY_POINT=https://auth.mydomain.com/auth/realms/mydomain/protocol/saml
- PROVIDERS__SAML__CONFIG__SAML_CALLBACK_URL=http://opencti.mydomain.com/auth/saml/callback
- PROVIDERS__SAML__CONFIG__CERT=MIICmzCCAYMCBgF3Rt3X1zANBgkqhkiG9w0BAQsFADARMQ8w
```

OpenCTI support mapping SAML Roles/Groups on OpenCTI Groups. Here is an example:

```json
"saml": {
    "config": {
        ...,
        // Groups mapping
        "groups_management": { // To map SAML Groups to OpenCTI Groups
            "group_attributes": ["Group"],
            "groups_mapping": ["SAML_Group_1:OpenCTI_Group_1", "SAML_Group_2:OpenCTI_Group_2", ...]
        },
        "groups_management": { // To map SAML Roles to OpenCTI Groups
            "group_attributes": ["Role"],
            "groups_mapping": ["SAML_Role_1:OpenCTI_Group_1", "SAML_Role_2:OpenCTI_Group_2", ...]
        },
        // Organizations mapping
        "organizations_management": { // To map SAML Groups to OpenCTI Organizations
            "group_attributes": ["Group"],
            "groups_mapping": ["SAML_Group_1:OpenCTI_Organization_1", "SAML_Group_2:OpenCTI_Organization_2", ...]
        },
        "organizations_management": { // To map SAML Roles to OpenCTI Organizations
            "group_attributes": ["Role"],
            "groups_mapping": ["SAML_Role_1:OpenCTI_Organization_1", "SAML_Role_2:OpenCTI_Organization_2", ...]
        }
    }
}
```

Here is an example of SAML Groups mapping configuration using environment variables:

```yaml
- "PROVIDERS__SAML__CONFIG__GROUPS_MANAGEMENT__GROUP_ATTRIBUTES=[\"Group\"]"
- "PROVIDERS__SAML__CONFIG__GROUPS_MANAGEMENT__GROUPS_MAPPING=[\"SAML_Group_1:OpenCTI_Group_1\", \"SAML_Group_2:OpenCTI_Group_2\", ...]"
```

### Auth0 (button)

This strategy allows to use [Auth0 Service](https://auth0.com) to handle the authentication and is based on [Passport - Auth0](http://www.passportjs.org/packages/passport-auth0).

```json
"authzero": {
    "identifier": "auth0",
    "strategy": "Auth0Strategy",
    "config": {
        "clientID": "XXXXXXXXXXXXXXXXXX",
        "baseURL": "https://opencti.mydomain.com",
        "clientSecret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://opencti.mydomain.com/auth/auth0/callback",
        "domain": "mycompany.eu.auth0.com",
        "audience": "XXXXXXXXXXXXXXX",
        "scope": "openid email profile XXXXXXXXXXXXXXX"
    }
}
```

Here is an example of Auth0 configuration using environment variables:

```yaml
- PROVIDERS__AUTHZERO__STRATEGY=Auth0Strategy
- PROVIDERS__AUTHZERO__CONFIG__CLIENT_ID=${AUTH0_CLIENT_ID}
- PROVIDERS__AUTHZERO__CONFIG__BASEURL=${AUTH0_BASE_URL}
- PROVIDERS__AUTHZERO__CONFIG__CLIENT_SECRET=${AUTH0_CLIENT_SECRET}
- PROVIDERS__AUTHZERO__CONFIG__CALLBACK_URL=${AUTH0_CALLBACK_URL}
- PROVIDERS__AUTHZERO__CONFIG__DOMAIN=${AUTH0_DOMAIN}
- PROVIDERS__AUTHZERO__CONFIG__SCOPE="openid email profile"
```

### OpenID Connect (button)

This strategy allows to use the [OpenID Connect Protocol](https://openid.net/connect) to handle the authentication and is based on [Node OpenID Client](https://github.com/panva/node-openid-client) that is more powerful than the passport one.

```json
"oic": {
    "identifier": "oic",
    "strategy": "OpenIDConnectStrategy",
    "config": {
        "label": "Login with OpenID",
        "issuer": "https://auth.mydomain.com/auth/realms/mydomain",
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "redirect_uris": ["https://opencti.mydomain.com/auth/oic/callback"]
    }
}
```

Here is an example of OpenID configuration using environment variables:

```yaml
- PROVIDERS__OPENID__STRATEGY=OpenIDConnectStrategy 
- "PROVIDERS__OPENID__CONFIG__LABEL=Login with OpenID"
- PROVIDERS__OPENID__CONFIG__ISSUER=https://auth.mydomain.com/auth/realms/xxxx
- PROVIDERS__OPENID__CONFIG__CLIENT_ID=XXXXXXXXXXXXXXXXXX
- PROVIDERS__OPENID__CONFIG__CLIENT_SECRET=XXXXXXXXXXXXXXXXXX
- "PROVIDERS__OPENID__CONFIG__REDIRECT_URIS=[\"https://opencti.mydomain.com/auth/oic/callback\"]"
```

OpenCTI support mapping OpenID Roles/Groups on OpenCTI Groups (everything is tied to a group in the platform). Here is an example:

```json
"oic": {
    "config": {
        ...,
        // Groups mapping
        "groups_management": { // To map OpenID Groups to OpenCTI Groups
            "groups_scope": "groups",
            "groups_path": ["groups", "realm_access.groups", "resource_access.account.groups"],
            "groups_mapping": ["OpenID_Group_1:OpenCTI_Group_1", "OpenID_Group_2:OpenCTI_Group_2", ...]
        },
        "groups_management": { // To map OpenID Roles to OpenCTI Groups
            "groups_scope": "roles",
            "groups_path": ["roles", "realm_access.roles", "resource_access.account.roles"],
            "groups_mapping": ["OpenID_Role_1:OpenCTI_Group_1", "OpenID_Role_2:OpenCTI_Group_2", ...]
        },
        // Organizations mapping  
        "organizations_management": { // To map OpenID Groups to OpenCTI Organizations
            "organizations_scope": "groups",
            "organizations_path": ["groups", "realm_access.groups", "resource_access.account.groups"],
            "organizations_mapping": ["OpenID_Group_1:OpenCTI_Group_1", "OpenID_Group_2:OpenCTI_Group_2", ...]
        },
        "organizations_management": { // To map OpenID Roles to OpenCTI Organizations
            "organizations_scope": "roles",
            "organizations_path": ["roles", "realm_access.roles", "resource_access.account.roles"],
            "organizations_mapping": ["OpenID_Role_1:OpenCTI_Group_1", "OpenID_Role_2:OpenCTI_Group_2", ...]
        },
    }
}
```

Here is an example of OpenID Groups mapping configuration using environment variables:

```yaml
- "PROVIDERS__OPENID__CONFIG__GROUPS_MANAGEMENT__GROUPS_SCOPE=groups"
- "PROVIDERS__OPENID__CONFIG__GROUPS_MANAGEMENT__GROUPS_PATH=[\"groups\", \"realm_access.groups\", \"resource_access.account.groups\"]"
- "PROVIDERS__OPENID__CONFIG__GROUPS_MANAGEMENT__GROUPS_MAPPING=[\"OpenID_Group_1:OpenCTI_Group_1\", \"OpenID_Group_2:OpenCTI_Group_2\", ...]"
```

### Facebook (button)

This strategy can authenticate your users with Facebook and is based on [Passport - Facebook](http://www.passportjs.org/packages/passport-facebook)

```json
"facebook": {
    "identifier": "facebook",
    "strategy": "FacebookStrategy",
    "config": {
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://opencti.mydomain.com/auth/facebook/callback"
    }
}
```

### Google (button)

This strategy can authenticate your users with Google and is based on [Passport - Google](http://www.passportjs.org/packages/passport-google-oauth)

```json
"google": {
    "identifier": "google",
    "strategy": "GoogleStrategy",
    "config": {
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://opencti.mydomain.com/auth/google/callback"
    }
}
```

### GitHub (button)

This strategy can authenticate your users with GitHub and is based on [Passport - GitHub](http://www.passportjs.org/packages/passport-github)

```json
"github": {
    "identifier": "github",
    "strategy": "GithubStrategy",
    "config": {
        "client_id": "XXXXXXXXXXXXXXXXXX",
        "client_secret": "XXXXXXXXXXXXXXXXXX",
        "callback_url": "https://opencti.mydomain.com/auth/github/callback"
  }
}
```

### Client certificate (button)

This strategy can authenticate a user based on SSL client certificates. For this you need to configure your OCTI to start in HTTPS, for example:

```json
"port": 443,
"https_cert": {
    "key": "/cert/server_key.pem",
    "crt": "/cert/server_cert.pem",
    "reject_unauthorized":true
}
```

And then add the `ClientCertStrategy`:

```json
"cert": {
    "strategy":"ClientCertStrategy",
    "config": {
        "label":"CLIENT CERT"
    }
}
```

Then when accessing for the first time OCTI, the browser will ask for the certificate you want to use.

## Automatically create group on SSO

The variable **auto_create_group** can be added in the options of some strategies (LDAP, SAML and OpenID). If this variable is true, the groups of a user that logins will automatically be created if they don’t exist.

More precisely, if the user that tries to authenticate has groups that don’t exist in OpenCTI but exist in the SSO configuration, there are two cases:

- if *auto_create_group= true* in the SSO configuration: the groups are created at the platform initialization and the user will be mapped on them.
- else: an error is raised.

### Example

We assum that *Group1* exists in the platform, and *newGroup* doesn’t exist. The user that tries to log in has the group *newGroup*. If *auto_create_group = true* in the SSO configuration, the group named *newGroup* will be created at the platform initialization and the user will be mapped on it. If *auto_create_group = false* or is undefined, the user can’t login and an error is raised.

```json
"groups_management": {
  "group_attribute": "cn",
  "groups_mapping": ["SSO_GROUP_NAME1:group1", "SSO_GROUP_NAME_2:newGroup", ...]
},
"auto_create_group": true
```

## Examples

### LDAP then fallback to local

In this example the users have a login form and need to enter login and password. The authentication is done on LDAP first, then locally if user failed to authenticate and finally fail if none of them succeded. Here is an example for the `production.json` file:

```json
"providers": {
    "ldap": {
        "strategy": "LdapStrategy",
        "config": {
            "url": "ldaps://mydc.mydomain.com:636",
            "bind_dn": "cn=Administrator,cn=Users,dc=mydomain,dc=com",
            "bind_credentials": "MY_STRONG_PASSWORD",
            "search_base": "cn=Users,dc=mydomain,dc=com",
            "search_filter": "(cn={{username}})",
            "mail_attribute": "mail",
            "account_attribute": "givenName"
        }
    },
    "local": {
        "strategy": "LocalStrategy",
        "config": {
            "disabled": false
        }
    }
}
```

If you use a container deployment, here is an example using environment variables:

```yaml
- PROVIDERS__LDAP__STRATEGY=LdapStrategy
- PROVIDERS__LDAP__CONFIG__URL=ldaps://mydc.mydomain.org:636
- PROVIDERS__LDAP__CONFIG__BIND_DN=cn=Administrator,cn=Users,dc=mydomain,dc=com
- PROVIDERS__LDAP__CONFIG__BIND_CREDENTIALS=XXXXXXXXXX
- PROVIDERS__LDAP__CONFIG__SEARCH_BASE=cn=Users,dc=mydomain,dc=com
- PROVIDERS__LDAP__CONFIG__SEARCH_FILTER=(cn={{username}})
- PROVIDERS__LDAP__CONFIG__MAIL_ATTRIBUTE=mail
- PROVIDERS__LDAP__CONFIG__ACCOUNT_ATTRIBUTE=givenName
- PROVIDERS__LDAP__CONFIG__ALLOW_SELF_SIGNED=true
- PROVIDERS__LOCAL__STRATEGY=LocalStrategy
```
