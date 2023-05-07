# Configuration

In this section, we learn how to configure OpenCTI to have it tailored to our production and development needs. 

Here are the configuration keys, for both Docker (environment variables) and manual deployment.

<aside>
💡 The equivalent of a config variable in environment variables is the usage of a double underscores (__) for a level of config. Example:
`"providers": {
    "ldap": {
      "strategy": "LdapStrategy"
   }
}`
will become `PROVIDERS__LDAP__STRATEGY=LdapStrategy`

If you need to put a list of element for the key, it must have a special formatting.
Example for redirect uris for openid config:

`"PROVIDERS__OPENID__CONFIG__REDIRECT_URIS=[\"https://demo.opencti.io/auth/oic/callback\"]"`

</aside>

<aside>
👉 To change the allowed memory of the platform process, you can use the environment variable `NODE_OPTIONS=--max-old-space-size=8096` (where 8096 is the amount of memory in MB).

</aside>

[API / Front](https://www.notion.so/93dd0f2899254b2581553d8b7df362da)

<aside>
💡 Example to enforce references:

</aside>

```json
"enforce_references": [
      "Threat-Actor",
      "Intrusion-Set",
			...
]
```

[Schedulers / engines](https://www.notion.so/1d22f1b73ee0457f9d6649a401fbc8f4)

[Dependencies](https://www.notion.so/bb7e7b7b16d24a87a497829660b19c2b)

# Worker

The Python worker can be configured manually using the configuration file `config.yml` or through environment variables.

[Python worker](https://www.notion.so/8dbd5914091446a58903d90ad3f88ca7)

# Dependencies

Dependencies have their own set of configuration that you can found in their specific documentation.

<aside>
💡 Sometime the documentation doesn't have every options so we try to fill the gap here.

</aside>

## ElasticSearch memory

If you want to adapt the memory consumption of ElasticSearch, you can use theses options:

```bash
# Add the followiung environment variable:
"ES_JAVA_OPTS=-Xms8g -Xmx8g"
```

# Authentication

## Introduction

OpenCTI supports several authentication providers. If you configure multiple strategies, they will be tested **in the order** you declared them.

<aside>
💡 You need to configure/activate only that you really want to propose to your users in term of authentication

</aside>

The product proposes two kind of authentication strategy:

- Form (asking user for a user/password)
- Buttons (click with authentication on an external system)

## Supported Strategies

Under the hood we technically use the strategies provided by [http://www.passportjs.org/](http://www.passportjs.org/)

We integrate a subset of the strategies available with passport we if you need more we can theatrically integrate all the passport strategies.

### LocalStrategy (form)

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

<aside>
💡 Please use the LDAP/Auth0/OpenID strategy for production deployment

</aside>

### LdapStrategy (form)

This strategy can be used to authenticate your user with your company LDAP.
Based on [http://www.passportjs.org/packages/passport-ldapauth/](http://www.passportjs.org/packages/passport-ldapauth/)

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

If you would like to use LDAP groups to automatically associate a role and/or group to users depending of its group.

```yaml
"group_search_base": "cn=Groups,dc=mydomain,dc=com",
"group_search_filter": "(member={{dn}})",
"roles_management": {
  "group_attribute": "cn",
  "groups_mapping": ["GROUP_NAME:Administrator", "GROUP_NAME_2:ROLE_NAME", ...]
}
"groups_management": {
  "group_attribute": "cn",
  "groups_mapping": ["GROUP_NAME:AdminGroup", "GROUP_NAME_2:GROUP_NAME", ...]
}
```

### SamlStrategy (button)

This strategy can be used to authenticate your user with your company SAML.
Based on [http://www.passportjs.org/packages/passport-saml/](http://www.passportjs.org/packages/passport-saml/)

```json
"saml": {
    "identifier": "saml",
    "strategy": "SamlStrategy",
    "config": {
        "issuer": "mytestsaml",
        // "account_attribute": "nameID",
        // "firstname_attribute": "nameID",
        // "lastname_attribute": "nameID",
        "entry_point": "https://auth.citeum.org/auth/realms/citeum/protocol/saml",
        "saml_callback_url": "http://localhost:4000/auth/saml/callback",
        // "private_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwg...",
        "cert": "MIICmzCCAYMCBgF2Qt3X1zANBgkqhkiG9w0BAQsFADARMQ8w...",
        "roles_management": { // Only if you need to
          "role_attributes": ["Role"],
          "roles_mapping": ["asso_limeo_founder:Administrator"]
        }
    }
},
```

- cert is mandatory (pem format), used to validate the SAML response
- private_key (pem format) is optional, only required if you want to sign the SAML client request

<aside>
💡 **Be careful to put the cert/private key in PEM format.
A lot of system give you the keys in X509 / PCKS12 format and so need to be converted.**
**Example to extract from PCKS12**: openssl pkcs12 -in keystore.p12 -out newfile.pem -nodes

</aside>

Docker style:

```yaml
- PROVIDERS__SAML__STRATEGY=SamlStrategy 
- "PROVIDERS__SAML__CONFIG__LABEL=Login with SAML"
- PROVIDERS__SAML__CONFIG__ISSUER=mytestsaml
- PROVIDERS__SAML__CONFIG__ENTRY_POINT=https://auth.citeum.org/auth/realms/citeum/protocol/saml
- PROVIDERS__SAML__CONFIG__SAML_CALLBACK_URL=http://localhost:4000/auth/saml/callback
- PROVIDERS__SAML__CONFIG__CERT=MIICmzCCAYMCBgF2Qt3X1zANBgkqhkiG9w0BAQsFADARMQ8w
```

### Auth0Strategy (button)

This strategy permits to use [https://auth0.com/](https://auth0.com/) service to handle the authentication.

Based on [http://www.passportjs.org/packages/passport-auth0/](http://www.passportjs.org/packages/passport-auth0/)

```json
"authzero": {
	"identifier": "auth0",
  "strategy": "Auth0Strategy",
  "config": {
    "clientID": "XXXXXXXXXXXXXXXXXX",
    "baseURL": "https://demo.opencti.io",
    "clientSecret": "XXXXXXXXXXXXXXXXXX",
    "callback_url": "https://demo.opencti.io/auth/auth0/callback",
    "domain": "luatix.eu.auth0.com",
		"audience": "XXXXXXXXXXXXXXX",
		"scope": "openid email profile XXXXXXXXXXXXXXX"
  }
}
```

### OpenIDConnectStrategy (button)

This strategy can use the [https://openid.net/connect/](https://openid.net/connect/) protocol to handle the authentication.

Based on [https://github.com/panva/node-openid-client](https://github.com/panva/node-openid-client) that is more powerful than the passport one.

```json
"oic": {
  "identifier": "oic",
  "strategy": "OpenIDConnectStrategy",
  "config": {
    "label": "Login with OpenID",
	  "issuer": "https://xxxxxxx/auth/realms/xxxx",
    "client_id": "XXXXXXXXXXXXXXXXXX",
    "client_secret": "XXXXXXXXXXXXXXXXXX",
    "redirect_uris": ["https://demo.opencti.io/auth/oic/callback"]
  }
}
```

Docker style:

```yaml
- PROVIDERS__OPENID__STRATEGY=OpenIDConnectStrategy 
- "PROVIDERS__OPENID__CONFIG__LABEL=Login with OpenID"
- PROVIDERS__OPENID__CONFIG__ISSUER=https://xxxxxxx/auth/realms/xxxx
- PROVIDERS__OPENID__CONFIG__CLIENT_ID=XXXXXXXXXXXXXXXXXX
- PROVIDERS__OPENID__CONFIG__CLIENT_SECRET=XXXXXXXXXXXXXXXXXX
- "PROVIDERS__OPENID__CONFIG__REDIRECT_URIS=[\"https://demo.opencti.io/auth/oic/callback\"]"
```

Examples of roles mapping in OpenID strategies (for group mappings, just replace “roles” with “groups”).

In the mapping, the syntax is `OpenID-Role:OpenCTI-Group-Name`.

```json
"roles_management": {
	"roles_scope": "roles",
	"roles_path": ["roles", "realm_access.roles", "resource_access.account.roles"],
	"roles_mapping": ["asso_luatix_admin:Administrator", "asso_luatix_supporter:Default", "asso_luatix_active:Default", "asso_luatix_sponsor:Default", "asso_luatix_founder:Default"]
}
```

In Docker style:

```json
- "PROVIDERS__OPENID__CONFIG__ROLES_MANAGEMENT__ROLES_SCOPE=roles"
- "PROVIDERS__OPENID__CONFIG__ROLES_MANAGEMENT__ROLES_PATH=[\"roles\", \"realm_access.roles\", \"resource_access.account.roles\"]"
- "PROVIDERS__OPENID__CONFIG__ROLES_MANAGEMENT__ROLES_MAPPING=[\"asso_luatix_admin:Administrator\", \"asso_luatix_supporter:Default\", \"asso_luatix_active:Default\", \"asso_luatix_sponsor:Default\", \"asso_luatix_founder:Default\"]"
```

### FacebookStrategy (button)

This strategy can authenticate your users with Facebook

Based on [http://www.passportjs.org/packages/passport-facebook/](http://www.passportjs.org/packages/passport-facebook/)

```json
"facebook": {
  "identifier": "facebook",
  "strategy": "FacebookStrategy",
  "config": {
    "client_id": "XXXXXXXXXXXXXXXXXX",
    "client_secret": "XXXXXXXXXXXXXXXXXX",
    "callback_url": "https://demo.opencti.io/auth/facebook/callback"
  }
}
```

### GoogleStrategy (button)

This strategy can authenticate your users with Google

Based on [http://www.passportjs.org/packages/passport-google-oauth/](http://www.passportjs.org/packages/passport-google-oauth/)

```json
"google": {
  "identifier": "google",
  "strategy": "GoogleStrategy",
  "config": {
    "client_id": "XXXXXXXXXXXXXXXXXX",
    "client_secret": "XXXXXXXXXXXXXXXXXX",
    "callback_url": "https://demo.opencti.io/auth/google/callback"
  }
}
```

### GithubStrategy (button)

This strategy can authenticate your users with Github

Based on [http://www.passportjs.org/packages/passport-github/](http://www.passportjs.org/packages/passport-github/)

```json
"github": {
	"identifier": "github",
  "strategy": "GithubStrategy",
  "config": {
    "client_id": "XXXXXXXXXXXXXXXXXX",
    "client_secret": "XXXXXXXXXXXXXXXXXX",
    "callback_url": "https://demo.opencti.io/auth/github/callback"
  }
}
```

-

### ClientCertStrategy (button)

This strategy can authenticate a user based on ssl client certificate.
For this you need to configure your OCTI to start in https, for example

```json
"port": 443,
"https_cert": {
  "key": "/cert/server_key.pem",
  "crt": "/cert/server_cert.pem",
  "reject_unauthorized":true
},
```

And the add the ClientCertStrategy

```json
"cert": {
  "strategy":"ClientCertStrategy",
  "config": {
    "label":"CLIENT CERT"
  }
}
```

Then when accessing for the first time OCTIm your browser will ask for the certificate you want to use.

## Examples

### LDAP then fallback to local

In this example the users have a login form and need to enter username / password.

Authentication is done on LDAP first, then locally if user not authenticated by the LDAP, then fail.

If you use local deployment, here are an example for the `production.json` file:

```json
"providers": {
    "ldap": {
      "strategy": "LdapStrategy",
      "config": {
        "url": "ldap://mydc.mydomain.com:389",
        "bind_dn": "cn=Administrator,cn=Users,dc=mydomain,dc=com",
        "bind_credentials": "MY_STRONG_PASSWORD",
        "search_base": "cn=Users,dc=mydomain,dc=com",
        "search_filter": "(cn={{username}})",
        "mail_attribute": "mail",
				"account_attribute": "givenName"
      }
    },
    "local": {
      "strategy": "LocalStrategy"
			"config": {
        "disabled": false
      }
    }
  }
```

If you use docker deployment, here an example for the `docker-compose.yml` file:

```yaml
- PROVIDERS__LDAP__STRATEGY=LdapStrategy
- PROVIDERS__LDAP__CONFIG__URL=ldaps://mydc.limeo.org:636
- PROVIDERS__LDAP__CONFIG__BIND_DN=cn=Administrator,cn=Users,dc=limeo,dc=org
- PROVIDERS__LDAP__CONFIG__BIND_CREDENTIALS=XXXXXXXXXX
- PROVIDERS__LDAP__CONFIG__SEARCH_BASE=cn=Users,dc=limeo,dc=org
- PROVIDERS__LDAP__CONFIG__SEARCH_FILTER=(cn={{username}})
- PROVIDERS__LDAP__CONFIG__MAIL_ATTRIBUTE=mail
- PROVIDERS__LDAP__CONFIG__ACCOUNT_ATTRIBUTE=givenName
- PROVIDERS__LDAP__CONFIG__ALLOW_SELF_SIGNED=true
- PROVIDERS__LOCAL__STRATEGY=LocalStrategy
```