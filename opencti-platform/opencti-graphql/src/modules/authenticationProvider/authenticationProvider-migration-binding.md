# Authentication Provider Binding Reference

This document maps every configuration variable available in the YAML/environment configuration (consumed by `initializeEnvAuthenticationProviders` in `providers-initialization.js`) to the new database-backed authentication provider models (OIDC, SAML, LDAP) exposed via GraphQL and the Settings UI.

Each passport library field has been **validated against the actual type definitions** in node_modules.

> **Note on `configurationMapping`**: The env config loader remaps snake_case keys to the camelCase names expected by passport libraries. This document always uses the **snake_case** (YAML-side) name as the reference.

---

## Common / Base fields

These fields are shared across all provider types and map to `AuthenticationProviderBaseInput`.

| YAML config key | GraphQL field (`AuthenticationProviderBaseInput`) | UI field | Status |
|---|---|---|---|
| `config.label` | `name` | Configuration name | ✅ Covered |
| `config.disabled` (inverted) | `enabled` | Enabled toggle | ✅ Covered |
| `identifier` (top-level) | `identifier_override` | Provider identifier (toggle) | ✅ Covered (OIDC/SAML only, not LDAP) |
| — | `description` | Description (advanced) | ✅ New field (no env equivalent) |
| — | `button_label_override` | Login button label (advanced) | ✅ New field (no env equivalent) |

---

## OIDC (OpenID Connect)

Library: `openid-client` v5 (`openid-clientv5` import) — all config in snake_case natively.

### Configuration fields

| YAML config key | configRemapping | GraphQL field (`OidcConfigurationInput`) | openid-client field | UI field | Status |
|---|---|---|---|---|---|
| `config.issuer` | — | `issuer` | `issuer` (URL for discovery) | Issuer | ✅ |
| `config.client_id` | `clientID` | `client_id` | `client_id` (discovery config) | Client ID | ✅ |
| `config.client_secret` | `clientSecret` | `client_secret_cleartext` | `client_secret` (discovery config) | Client secret | ✅ Encrypted at rest |
| `config.default_scopes` | — | `scopes` | `scope` (joined with space) | Scopes | ✅ Defaults `openid,email,profile` |
| `config.audience` | — | `audience` | `audience` (authorization params) | Audience | ✅ Advanced |
| `config.callback_url` | `callbackURL` | — (computed at runtime) | `callbackURL` (strategy options) | Callback URL (read-only) | ✅ Computed `platform_url + identifier` |
| `config.logout_remote` | — | `logout_remote` | — (custom logout handler) | Logout remote | ✅ Advanced |
| `config.logout_callback_url` | — | `logout_callback_url` | `post_logout_redirect_uri` | Logout callback URL | ✅ Advanced |
| `config.use_proxy` | — | `use_proxy` | custom proxy agent via `customFetch` | Use proxy | ✅ Advanced |

### User info mapping

| YAML config key | GraphQL field | Old env usage (default) | UI field | Status |
|---|---|---|---|---|
| `config.email_attribute` | `user_info_mapping.email_expr` | `userinfo[email_attribute]` (default `email`) | Email expression | ✅ |
| `config.name_attribute` | `user_info_mapping.name_expr` | `userinfo[name_attribute]` (default `name`) | Name expression | ✅ |
| `config.firstname_attribute` | `user_info_mapping.firstname_expr` | `userinfo[firstname_attribute]` (default `given_name`) | First name expression | ✅ Advanced |
| `config.lastname_attribute` | `user_info_mapping.lastname_expr` | `userinfo[lastname_attribute]` (default `family_name`) | Last name expression | ✅ Advanced |
| `config.get_user_attributes_from_id_token` | — | Reads from `id_token` instead of `userinfo` | — | 🔄 Replaced by expression model (e.g. `tokens.id_token.email`) |

### Groups mapping

| YAML config key | GraphQL field | Old env usage | Status |
|---|---|---|---|
| `config.groups_management.groups_mapping` | `groups_mapping.groups_mapping` | `genConfigMapper(groups_mapping)` | ✅ |
| `config.groups_management.groups_path` | `groups_mapping.groups_expr` | `R.path(path, decodedUser)` (default `['groups']`) | ✅ |
| `config.groups_management.groups_scope` | — | Added to OAuth scopes | 🔄 User should add to `scopes` field manually |
| `config.groups_management.read_userinfo` | — | Reads from `userinfo` vs decoded token | 🔄 Replaced by expression model |
| `config.groups_management.token_reference` | — | `access_token` or `id_token` source | 🔄 Replaced by expression model |
| `config.auto_create_group` | `groups_mapping.auto_create_groups` (output type only) | `autoCreateGroup` option | ⚠️ **Missing from `GroupsMappingInput`** |

### Organizations mapping

| YAML config key | GraphQL field | Old env usage | Status |
|---|---|---|---|
| `config.organizations_default` | `organizations_mapping.default_organizations` | Default orgs always assigned | ✅ |
| `config.organizations_management.organizations_mapping` | `organizations_mapping.organizations_mapping` | `genConfigMapper(orgs_mapping)` | ✅ |
| `config.organizations_management.organizations_path` | `organizations_mapping.organizations_expr` | `R.path(path, decodedUser)` (default `['organizations']`) | ✅ |
| `config.organizations_management.organizations_scope` | — | Added to OAuth scopes | 🔄 User should add to `scopes` field manually |
| `config.organizations_management.read_userinfo` | — | Reads from `userinfo` vs decoded token | 🔄 Replaced by expression model |
| `config.organizations_management.token_reference` | — | Source for orgs | 🔄 Replaced by expression model |

---

## SAML

Library: `@node-saml/passport-saml` v5 → types from `@node-saml/node-saml`

Reference types: `SamlOptions` (in `node-saml/lib/types.d.ts`), `SamlSigningOptions`, `MandatorySamlOptions`

### Configuration fields

| YAML config key | configRemapping | GraphQL field (`SamlConfigurationInput`) | **Actual passport-saml field** (`SamlOptions`) | **Type** | UI field | Status | Notes |
|---|---|---|---|---|---|---|---|
| `config.issuer` | — | `issuer` | **`issuer`** | `string` (mandatory) | Issuer | ✅ | |
| `config.entry_point` | `entryPoint` | `entry_point` | **`entryPoint`** | `string?` | Entry point | ✅ | |
| `config.cert` | `idpCert` | `idp_certificate` | **`idpCert`** | `string \| string[] \| IdpCertCallback` (mandatory) | IDP certificate | ✅ | |
| `config.private_key` | `privateKey` | `private_key_cleartext` | **`privateKey`** | `string \| Buffer` (from `SamlSigningOptions`) | Private key | ✅ | Encrypted at rest |
| `config.saml_callback_url` | `callbackUrl` | — (computed at runtime) | **`callbackUrl`** | `string` (mandatory) | Callback URL (read-only) | ✅ | Computed from `platform_url + identifier` |
| `config.logout_remote` | — | `logout_remote` | — (custom logout handler) | — | Logout remote | ✅ | Advanced |
| `config.want_assertions_signed` | `wantAssertionsSigned` | `want_assertions_signed` | **`wantAssertionsSigned`** | `boolean` | Want assertion signed | ✅ | ⚠️ Bug: `provider-saml.ts` maps this to `conf.want_authn_response_signed` |
| `config.want_authn_response_signed` | `wantAuthnResponseSigned` | `want_authn_response_signed` | **`wantAuthnResponseSigned`** | `boolean` | Want authn response signed | ✅ | |
| `config.signing_cert` | `signingCert` | `signing_cert` | **`publicCert`** | `string?` (from `SamlSigningOptions`) | Signing certificate | ✅ | This is the **SP signing cert** (used to sign outgoing requests). Not the IdP cert. |
| `config.sso_binding_type` | — | `sso_binding_type` | **`authnRequestBinding`** | `string?` (e.g. `HTTP-POST`, `HTTP-Redirect`) | SSO Binding type | ✅ | Advanced |
| `config.force_authn` | `forceAuthn` | `force_reauthentication` | **`forceAuthn`** | `boolean` | Force reauthentication | ✅ | Advanced |
| `config.identifier_format` | `identifierFormat` | — | **`identifierFormat`** | `string \| null` | — | 📦 Via `extra_conf` | |
| `config.signature_algorithm` | `signatureAlgorithm` | — | **`signatureAlgorithm`** | `"sha1" \| "sha256" \| "sha512"` (from `SamlSigningOptions`) | — | 📦 Via `extra_conf` | Key: `signatureAlgorithm` |
| `config.digest_algorithm` | `digestAlgorithm` | — | **`digestAlgorithm`** | `string?` (from `SamlSigningOptions`) | — | 📦 Via `extra_conf` | Key: `digestAlgorithm` |
| `config.authn_context` | `authnContext` | — | **`authnContext`** | `string[]` | — | 📦 Via `extra_conf` | Key: `authnContext` |
| `config.disable_requested_authn_context` | `disableRequestedAuthnContext` | — | **`disableRequestedAuthnContext`** | `boolean` | — | 📦 Via `extra_conf` | Key: `disableRequestedAuthnContext` |
| `config.disable_request_acs_url` | `disableRequestAcsUrl` | — | **`disableRequestAcsUrl`** | `boolean` | — | 📦 Via `extra_conf` | Key: `disableRequestAcsUrl` |
| `config.skip_request_compression` | `skipRequestCompression` | — | **`skipRequestCompression`** | `boolean` | — | 📦 Via `extra_conf` | Key: `skipRequestCompression` |
| `config.decryption_pvk` | `decryptionPvk` | — | **`decryptionPvk`** | `string \| Buffer` | — | 📦 Via `extra_conf` | Key: `decryptionPvk` |
| `config.decryption_cert` | `decryptionCert` | — | — | — | — | ⚠️ See note | Not a direct `SamlOptions` field. Used for `generateServiceProviderMetadata` only. |
| — | — | — | **`logoutUrl`** | `string` | — | ❌ Not exposed | passport-saml field for IdP logout URL |
| — | — | — | **`logoutCallbackUrl`** | `string?` | — | ❌ Not exposed | Separate from `callbackUrl`, for logout responses |

> **Important**: `decryptionCert` is in `configurationMapping` but it is **not a direct `SamlOptions` field**. It is only used in `generateServiceProviderMetadata()`. If passed via `extra_conf` and spread, it will be ignored by the SAML strategy itself.

### `buildSAMLOptions` mapping validation (provider-saml.ts)

| Our field | Maps to | Passport field | Correct? |
|---|---|---|---|
| `conf.name` | `name` | `name` (StrategyOptions) | ✅ |
| `conf.issuer` | `issuer` | `issuer` | ✅ |
| `conf.idp_certificate` | `idpCert` | `idpCert` | ✅ |
| `conf.callback_url` | `callbackUrl` | `callbackUrl` | ✅ |
| `conf.want_authn_response_signed` | `wantAssertionsSigned` | `wantAssertionsSigned` | ❌ **BUG** — should be `conf.want_assertions_signed` |
| `conf.want_authn_response_signed` | `wantAuthnResponseSigned` | `wantAuthnResponseSigned` | ✅ |
| `conf.signing_cert` | `publicCert` | `publicCert` (SamlSigningOptions) | ✅ SP signing cert for outgoing requests |
| `conf.sso_binding_type` | `authnRequestBinding` | `authnRequestBinding` | ✅ |
| `conf.force_reauthentication` | `forceAuthn` | `forceAuthn` | ✅ |
| `conf.extra_conf` | `...spread` | Any additional SamlOptions field | ✅ |

> **Missing from `buildSAMLOptions`**: `privateKey` is not being passed. The old env code passed `privateKey` via the spread of `mappedConfig`. In the new model, `private_key` is decrypted in `samlStoreToProvider` and set on the provider config, but `buildSAMLOptions` does not map it to `privateKey`. This means **SAML request signing is broken**. Must add `privateKey: conf.private_key` to `buildSAMLOptions`.

### User info mapping

| YAML config key | GraphQL field | Old env usage (default) | UI field | Status |
|---|---|---|---|---|
| `config.mail_attribute` | `user_info_mapping.email_expr` | `samlAttributes[mail_attribute]` (fallback `nameID`) | Email expression | ✅ |
| `config.account_attribute` | `user_info_mapping.name_expr` | `samlAttributes[account_attribute]` | Name expression | ✅ |
| `config.firstname_attribute` | `user_info_mapping.firstname_expr` | `samlAttributes[firstname_attribute]` | First name expression | ✅ Advanced |
| `config.lastname_attribute` | `user_info_mapping.lastname_expr` | `samlAttributes[lastname_attribute]` | Last name expression | ✅ Advanced |

### Groups mapping

| YAML config key | GraphQL field | Old env usage | Status |
|---|---|---|---|
| `config.groups_management.groups_mapping` | `groups_mapping.groups_mapping` | `genConfigMapper(groups_mapping)` | ✅ |
| `config.groups_management.group_attributes` | `groups_mapping.groups_expr` | Attribute names to read groups (default `['groups']`) | ✅ |
| `config.auto_create_group` | `groups_mapping.auto_create_groups` (output type only) | `autoCreateGroup` option | ⚠️ **Missing from `GroupsMappingInput`** |
| `config.roles_management` | — | **DEPRECATED** | ❌ Removed intentionally |

### Organizations mapping

| YAML config key | GraphQL field | Old env usage | Status |
|---|---|---|---|
| `config.organizations_default` | `organizations_mapping.default_organizations` | Default orgs | ✅ |
| `config.organizations_management.organizations_mapping` | `organizations_mapping.organizations_mapping` | `genConfigMapper(orgs_mapping)` | ✅ |
| `config.organizations_management.organizations_path` | `organizations_mapping.organizations_expr` | `R.path(path, profile)` (default `['organizations']`) | ✅ |

---

## LDAP

Library: `passport-ldapauth` → `ldapauth-fork` → `ldapjs`

Reference types: `LdapAuth.Options` (in `ldapauth-fork/lib/ldapauth.d.ts`), passport-ldapauth strategy options

### Configuration fields

| YAML config key | configRemapping | GraphQL field (`LdapConfigurationInput`) | **Actual ldapauth-fork field** (`LdapAuth.Options`) | **Type** | UI field | Status | Notes |
|---|---|---|---|---|---|---|---|
| `config.url` | — | `url` | **`url`** | `string` (from `ClientOptions`) | URL | ✅ | e.g. `ldap://localhost:389` |
| `config.bind_dn` | `bindDN` | `bind_dn` | **`bindDN`** | `string?` | Bind DN | ✅ | |
| `config.bind_credentials` | `bindCredentials` | `bind_credentials_cleartext` | **`bindCredentials`** | `string?` | Bind credentials | ✅ | Encrypted at rest. Forced to string in old code. |
| `config.search_base` | `searchBase` | `search_base` | **`searchBase`** | `string` | Search base | ✅ | |
| `config.search_filter` | `searchFilter` | `search_filter` | **`searchFilter`** | `string` | Search filter | ✅ | ⚠️ Bug in `ldapStoreToProvider` (see below) |
| `config.search_attributes` | `searchAttributes` | — | **`searchAttributes`** | `string[]?` | — | 📦 Via `extra_conf` | Key: `searchAttributes`. Array of attributes to return. |
| `config.username_field` | `usernameField` | — | **`usernameField`** | `string` (default `username`) | — | 📦 Via `extra_conf` | Key: `usernameField`. passport-ldapauth level option, NOT server option. |
| `config.password_field` | `passwordField` | — | **`passwordField`** | `string` (default `password`) | — | 📦 Via `extra_conf` | Key: `passwordField`. passport-ldapauth level option, NOT server option. |
| `config.credentials_lookup` | `credentialsLookup` | — | **`credentialsLookup`** | `function` | — | ❌ Not possible | Function type, cannot be stored as config. |
| `config.group_search_base` | `groupSearchBase` | `group_base` | **`groupSearchBase`** | `string?` | Group base | ✅ | |
| `config.group_search_filter` | `groupSearchFilter` | `group_filter` | **`groupSearchFilter`** | `string \| GroupSearchFilterFunction` | Group filter | ✅ | |
| `config.group_search_attributes` | `groupSearchAttributes` | — | **`groupSearchAttributes`** | `string[]?` | — | 📦 Via `extra_conf` | Key: `groupSearchAttributes` |
| `config.allow_self_signed` | — | `allow_self_signed` | **`tlsOptions.rejectUnauthorized`** (inverted) | `boolean` via `ConnectionOptions` | Allow self-signed | ✅ | Advanced |
| — | — | — | **`searchScope`** | `Scope` (`base` \| `one` \| `sub`, default `sub`) | — | 📦 Via `extra_conf` | Key: `searchScope` |
| — | — | — | **`groupSearchScope`** | `Scope` (default `sub`) | — | 📦 Via `extra_conf` | Key: `groupSearchScope` |
| — | — | — | **`groupDnProperty`** | `string` (default `dn`) | — | 📦 Via `extra_conf` | Key: `groupDnProperty` |
| — | — | — | **`bindProperty`** | `string` (default `dn`) | — | 📦 Via `extra_conf` | Key: `bindProperty` |
| — | — | — | **`cache`** | `boolean` | — | 📦 Via `extra_conf` | Key: `cache`. Caches up to 100 credentials for 5 min. |
| — | — | — | **`starttls`** | `boolean` | — | 📦 Via `extra_conf` | Key: `starttls` |
| — | — | — | **`reconnect`** | `boolean` | — | 📦 Via `extra_conf` | Key: `reconnect`. ldapjs client option. |

> **Important on `usernameField` / `passwordField`**: These are passport-ldapauth strategy-level options, NOT server-level options. In our `convertConfiguration` (provider-ldap.ts), `extra_conf` is spread inside the `server` object. So these fields would **not work** via `extra_conf` unless the code is modified to spread them at the strategy level.

### `convertConfiguration` mapping validation (provider-ldap.ts)

| Our field | Maps to | ldapauth-fork field | Correct? |
|---|---|---|---|
| `conf.url` | `server.url` | `url` | ✅ |
| `conf.bind_dn` | `server.bindDN` | `bindDN` | ✅ |
| `conf.bind_credentials` | `server.bindCredentials` | `bindCredentials` | ✅ |
| `conf.search_base` | `server.searchBase` | `searchBase` | ✅ |
| `conf.search_filter` | `server.searchFilter` | `searchFilter` | ✅ |
| `conf.group_base` | `server.groupSearchBase` | `groupSearchBase` | ✅ |
| `conf.group_filter` | `server.groupSearchFilter` | `groupSearchFilter` | ✅ |
| `conf.allow_self_signed` | `server.tlsOptions.rejectUnauthorized` (inverted) | `tlsOptions` | ✅ |
| `conf.extra_conf` | `...spread` in `server` | Any `LdapAuth.Options` field | ✅ (but only server-level, not strategy-level) |

### User info mapping

| YAML config key | GraphQL field | Old env usage (default) | UI field | Status |
|---|---|---|---|---|
| `config.mail_attribute` | `user_info_mapping.email_expr` | `user[mail_attribute]` (default `mail`) | Email expression | ✅ |
| `config.account_attribute` | `user_info_mapping.name_expr` | `user[account_attribute]` (default `givenName`) | Name expression | ✅ |
| `config.firstname_attribute` | `user_info_mapping.firstname_expr` | `user[firstname_attribute]` | First name expression | ✅ Advanced |
| `config.lastname_attribute` | `user_info_mapping.lastname_expr` | `user[lastname_attribute]` | Last name expression | ✅ Advanced |

### Groups mapping

| YAML config key | GraphQL field | Old env usage | Status |
|---|---|---|---|
| `config.groups_management.groups_mapping` | `groups_mapping.groups_mapping` | `genConfigMapper(groups_mapping)` | ✅ |
| `config.groups_management.group_attribute` | `groups_mapping.groups_expr` | Group attribute in `_groups` (default `cn`) | ✅ |
| `config.auto_create_group` | `groups_mapping.auto_create_groups` (output type only) | `autoCreateGroup` option | ⚠️ **Missing from `GroupsMappingInput`** |

### Organizations mapping

| YAML config key | GraphQL field | Old env usage | Status |
|---|---|---|---|
| `config.organizations_default` | `organizations_mapping.default_organizations` | Default orgs | ✅ |
| `config.organizations_management.organizations_mapping` | `organizations_mapping.organizations_mapping` | `genConfigMapper(orgs_mapping)` | ✅ |
| `config.organizations_management.organizations_path` | `organizations_mapping.organizations_expr` | `R.path(path, user)` (default `['organizations']`) | ✅ |

---

## Bugs found during validation

### 1. `provider-saml.ts:23` — `wantAssertionsSigned` mapped to wrong field

```typescript
// CURRENT (WRONG)
wantAssertionsSigned: conf.want_authn_response_signed,

// SHOULD BE
wantAssertionsSigned: conf.want_assertions_signed,
```

### 2. `authenticationProvider-domain.ts:173` — `search_filter` mapped to `search_base`

```typescript
// CURRENT (WRONG)
search_filter: configuration.search_base,

// SHOULD BE
search_filter: configuration.search_filter,
```

### 3. `provider-saml.ts` — `privateKey` not passed to SAML options

`buildSAMLOptions` does not include `privateKey: conf.private_key`. The old env code included it via the full config spread. Without it, **SAML request signing will not work**.

```typescript
// MISSING — should be added to buildSAMLOptions
privateKey: conf.private_key,
```

### 4. `provider-ldap.ts` — `usernameField`/`passwordField` cannot be set via `extra_conf`

The `extra_conf` values are spread inside the `server` object, but `usernameField` and `passwordField` are strategy-level options (outside `server`). If users need these, the code needs to support strategy-level extra conf or dedicated fields.

---

## Missing from GraphQL input types

### `GroupsMappingInput` / `OrganizationsMappingInput`

| Field | In output type | In input type | Used in runtime code |
|---|---|---|---|
| `auto_create_groups` | ✅ `GroupsMapping` | ❌ `GroupsMappingInput` | ✅ `providerLoginHandler` |
| `auto_create_organizations` | ✅ `OrganizationsMapping` | ❌ `OrganizationsMappingInput` | ✅ `providerLoginHandler` |

**Action needed**: Add these to the input types so they can be configured from the UI.

---

## `extra_conf` key reference for administrators

When using `extra_conf` to set passport library fields, the key must match the **passport library field name** (camelCase), not the YAML config name.

### SAML extra_conf keys

| Key | Type | Description |
|---|---|---|
| `identifierFormat` | String | SAML NameID format (e.g. `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`) |
| `signatureAlgorithm` | String | `sha1`, `sha256`, or `sha512` |
| `digestAlgorithm` | String | Digest algorithm |
| `authnContext` | String | Authentication context class (serialized) |
| `disableRequestedAuthnContext` | Boolean | Disable requested authn context |
| `disableRequestAcsUrl` | Boolean | Disable assertion consumer service URL in request |
| `skipRequestCompression` | Boolean | Skip request compression |
| `decryptionPvk` | String | Decryption private key (PEM) |
| `logoutUrl` | String | IdP logout URL |
| `logoutCallbackUrl` | String | SP logout callback URL |

### LDAP extra_conf keys (server-level)

| Key | Type | Description |
|---|---|---|
| `searchScope` | String | `base`, `one`, or `sub` (default `sub`) |
| `searchAttributes` | String (JSON array) | Attributes to return from search |
| `groupSearchScope` | String | `base`, `one`, or `sub` (default `sub`) |
| `groupSearchAttributes` | String (JSON array) | Attributes to return from group search |
| `groupDnProperty` | String | Property for `{{dn}}` interpolation (default `dn`) |
| `bindProperty` | String | Property for bind verification (default `dn`) |
| `cache` | Boolean | Enable credential caching |
| `starttls` | Boolean | Use STARTTLS |
| `reconnect` | Boolean | Auto-reconnect on connection loss |

---

## Recommended promotions from `extra_conf` to first-class fields

The following fields are currently only available via `extra_conf` but should be promoted to dedicated GraphQL fields due to security, usability, or frequency-of-use concerns.

### High priority

#### SAML: `decryption_pvk` (decryption private key)

- **Passport field**: `decryptionPvk` (`string | Buffer`)
- **Why**: This is a **secret/private key** used to decrypt encrypted SAML assertions. Storing it in `extra_conf` as a plain string means it **will not be encrypted at rest**, unlike `private_key` which goes through the `encryptAuthValue` pipeline. Many enterprise IdPs (Azure AD, ADFS) encrypt assertions by default.
- **Implementation**: Follow the same pattern as `private_key`: add `decryption_pvk_cleartext` to `SamlConfigurationInput`, store as `decryption_pvk_encrypted`, add to `samlSecretFields`, decrypt in `samlStoreToProvider`, and map to `decryptionPvk` in `buildSAMLOptions`.

#### SAML: `signature_algorithm`

- **Passport field**: `signatureAlgorithm` (`"sha1" | "sha256" | "sha512"`, from `SamlSigningOptions`)
- **Why**: Security-critical setting with a **constrained enum**. Many IdPs reject `sha1` (deprecated). Administrators frequently need to set this explicitly. An enum field in the UI with a sensible default (`sha256`) would prevent misconfiguration compared to a free-text extra_conf entry.
- **Implementation**: Add as an optional enum field (`SignatureAlgorithm`) to GraphQL schema and `SamlConfigurationInput`. Map to `signatureAlgorithm` in `buildSAMLOptions`.

#### LDAP: `starttls`

- **Passport field**: `starttls` (`boolean`)
- **Why**: **Security-critical**. Many LDAP deployments use STARTTLS (`ldap://` + upgrade) instead of LDAPS (`ldaps://`). Without this option being visible, administrators may unknowingly leave connections unencrypted. It pairs naturally with `allow_self_signed` in the UI as a TLS/security section.
- **Implementation**: Add as a boolean field to `LdapConfigurationInput` and `LdapConfiguration`. Pass to `convertConfiguration` in `provider-ldap.ts`.

### Medium priority

#### SAML: `identifier_format`

- **Passport field**: `identifierFormat` (`string | null`)
- **Why**: Very commonly configured in SAML setups. Typical values are URN strings like `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` or `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`. Getting the URN wrong is a common source of errors. A dedicated text field (or select with common values) improves discoverability and reduces misconfiguration.
- **Implementation**: Add as an optional string field to `SamlConfigurationInput`. Map to `identifierFormat` in `buildSAMLOptions`.

#### SAML: `disable_requested_authn_context`

- **Passport field**: `disableRequestedAuthnContext` (`boolean`)
- **Why**: A well-known boolean workaround required by many IdPs (Azure AD being the most common). Burying it in `extra_conf` makes it hard for administrators to discover when troubleshooting SAML authentication failures.
- **Implementation**: Add as an optional boolean field to `SamlConfigurationInput`. Map to `disableRequestedAuthnContext` in `buildSAMLOptions`.

### Should remain in `extra_conf`

| Field | Provider | Reason |
|---|---|---|
| `digestAlgorithm` | SAML | Usually follows `signatureAlgorithm`, rarely set independently |
| `authnContext` | SAML | Array type, niche use case |
| `skipRequestCompression` | SAML | Very rare |
| `disableRequestAcsUrl` | SAML | Very rare |
| `logoutUrl` / `logoutCallbackUrl` | SAML | passport-saml can auto-discover from metadata |
| `searchScope` / `groupSearchScope` | LDAP | Default `sub` is correct 95%+ of the time |
| `searchAttributes` / `groupSearchAttributes` | LDAP | Array type, optimization only |
| `groupDnProperty` / `bindProperty` | LDAP | Rare, default `dn` is almost always correct |
| `cache` / `reconnect` | LDAP | Nice-to-have, defaults are acceptable |

---

## Deprecated strategies (not migrated to new model)

- `STRATEGY_FACEBOOK` → Use OIDC instead
- `STRATEGY_GOOGLE` → Use OIDC instead
- `STRATEGY_GITHUB` → Use OIDC instead
- `STRATEGY_AUTH0` → Use OIDC instead

## Singleton strategies (migrated to Settings entity)

- `STRATEGY_LOCAL` → `Settings.local_auth`
- `STRATEGY_CERT` → `Settings.cert_auth`
- `STRATEGY_HEADER` → `Settings.headers_auth`
