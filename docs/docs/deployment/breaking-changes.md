# Breaking changes and migrations

This section lists breaking changes introduced in OpenCTI, per version starting with the latest.

Please follow the migration guides if you need to upgrade your platform. 

## Breakdown per version

This table regroups all the breaking changes introduced, with the corresponding version in which the change was implemented.

| Change                                                                                                              | Deprecated in | Changed in |
|:--------------------------------------------------------------------------------------------------------------------|:--------------|:-----------|
| [SSO, cryptography and tokens management](#cryptography-and-tokens-management)                                      | -             | 7.260224.0 |
| [Update license for SSO (& migration to UI)](#SSO-update-license)                                                |               | 7.260224.0        |
| [XTM Composer version compatibility](#xtm-composer-version-compatibility)                                           | -             | 7.260224.0 |
| [GenerationScenario Mutations in OpenCTI - OpenBAS](#generation-scenario-mutation-openti-openbas-with-placeholders) | 6.5           | 6.8        |
| [Removing bi-directional stream connectors](#removing-some-stream-connectors)                                       | 6.3           | 6.6        |
| [Promote Observable API](#change-to-the-observable-promote-API)                                                     | 6.2           | 6.8        |
| [SAML authentication parameters](#change-to-SAML-authentication)                                                    |               | 6.2        |
| [Major changes to Filtering API](#new-filtering-API)                                                                |               | 5.12       |


<a id="cryptography-and-tokens-management"></a>
## OpenCTI 7.260224.0

<a id="SSO-update-license"></a>
### Licensing change for SSO

SSO becomes an [Enterprise edition](../administration/enterprise.md) feature.
Using SSO defined in configuration file (environment variable) to login will not be possible anymore for **Community Edition** platforms. 
Local authentication will still be available with complex policies and 2FA. If you need more time to migrate, its always possible to get a [trial license](https://filigran.io/enterprise-editions-trial/)

#### UI configuration authentication
Additionally, authentication strategies will be converted to UI.
For more information read the [migration process](breaking-changes/7.260224.0-SSO-authentication-migration.md) and the new associated feature (Define Authentication via UI) pages.

### Breaking changes

#### OpenAEV and OpenCTI version compatibility

Upgrading to OpenCTI 7.260224.0 requires you to upgrade OpenAEV to version 2.2.

<a id="xtm-composer-version-compatibility"></a>
#### XTM Composer and OpenCTI version compatibility

Upgrading to OpenCTI 7.260224.0 requires you to upgrade XTM Composer to version >=2. 
This new version is required to support the security improvements introduced in OpenCTI 7, including the new token management and JWT-based authentication mechanisms.

#### Mandatory Cryptography configuration

Upgrading to OpenCTI 7.260224.0 requires configuring the cryptography key in the application configuration.
Encryption keys must be randomly generated and kept secret. They should be at least 32 bytes longs and encoded in base 64 to ensure strong security.
To generate a secure random key, you can use the following command in a terminal:

```bash
openssl rand -base64 32
```

!!! warning "Cryptography configuration"

    - Env variable: `APP__ENCRYPTION_KEY=yK***************************************N0=`
    - Configuration file: `app { encryption_key = "yK***************************************N0=" }`

#### Tokens management

Security improvement replacing the legacy **single cleartext `api_token` per user** with a
modern **multi-token system** featuring HMAC-hashed storage, expiration policies, per-token usage tracking,
and capability-based access control. Connector-to-platform authentication is upgraded from raw token
passthrough to **JWT-based mutual authentication** using platform-derived Ed25519 key pairs.

All existing tokens are automatically migrated to the new system.
**After migration existing tokens will be encrypted and so no longer be retrievable by the user.**

!!! warning "GraphQL API breaking changes"

    - `User.api_token` → `User.api_tokens` (type changed from `String!` to `[ApiToken!]!`)
    - `MeUser.api_token` → `MeUser.api_tokens`
    - `meTokenRenew` mutation removed
    - `UserEditMutations.tokenRenew` mutation removed

!!! warning "Python client breaking changes"
    - `MeUser.api_token` → `MeUser.api_tokens`
    - `token_renew()` method removed, replaced by `create_token()` / `remove_token()`

#### Python 3.9 not supported anymore
Please review any script that may use some functionalities available in this version .

## OpenCTI 6.5

### Deprecation

<a id="generation-scenario-mutation-openti-openbas-with-placeholders"></a>
#### GenerationScenario Mutations in OpenCTI - OpenBAS

The mutations related to GenerationScenario have been deprecated due to changes in their signature and response format. These updates provide more detailed information when generating scenarios.

For example, if an attack pattern does not exist in the OpenBAS catalog, the response will now include a list of the missing these attack pattern identifiers.

For more details, see [this migration guide](./breaking-changes/6.5-generation-scenario-opencti-openbas-placeholders.md)

## OpenCTI 6.4.11

### Breaking change

Webhook template are now restricted to a list of authorized functions.
A new template cannot be created if it contains unauthorized function, and existing templates cannot be updated with unauthorized functions.

In case a function is required in webhook template in addition of default safe list, it can be added to your own risk by overriding APP__NOTIFIER_AUTHORIZED_FUNCTIONS.

For example:
```bash
APP__NOTIFIER_AUTHORIZED_FUNCTIONS="[\"if\", \"for\", \"forEach\", \"while\", \"stringify\", \"Date\", \"toLocaleString\"]"
```


## OpenCTI 6.3

### Deprecation

<a id="removing-some-stream-connectors"></a>
#### Removing some stream connectors

Some bi-directional stream connectors have been divided into two distinct connectors:

- An **external import connector** that gathers information from external organizations, applications, or services into OpenCTI.
- A **stream connector** that transfers OpenCTI data to third-party platforms.

The existing connectors affected by this change will be removed and replaced with these two new connectors.

For more details, see [this migration guide](./breaking-changes/6.3-removing-some-connectors.md)

## OpenCTI 6.2

### Deprecation

<a id="change-to-the-observable-promote-API"></a>
#### Change to the observable promote API  

The API calls that promote an Observable to Indicator now return the created Indicator instead of the original Observable.

For more details, see [this migration guide](./breaking-changes/6.2-promote-to-indicator.md).

### Breaking Changes

<a id="change-to-SAML-authentication"></a>
### Change to SAML authentication

Upgrading `passport-saml` library introduced a breaking change with respect to the default SAML parameters regarding signing responses and assertions. 

For more details, see [this migration guide](./breaking-changes/6.2-saml-authentication.md).

## OpenCTI 5.12

### Breaking changes

<a id="new-filtering-API"></a>
#### Major changes to the filtering API

OpenCTI 5.12 introduces a major rework of the **filter engine** with breaking changes to the model.
A [dedicated blog post](https://blog.filigran.io/introducing-advanced-filtering-possibilities-in-opencti-552147565faf) describes the reasons behind these changes.

Please read the dedicated [migration guide](./breaking-changes/5.12-filters.md).
