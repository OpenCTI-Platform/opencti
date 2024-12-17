# Breaking changes and migrations

This section lists breaking changes introduced in OpenCTI, per version starting with the latest.

Please follow the migration guides if you need to upgrade your platform. 

## Breakdown per version

This table regroups all the breaking changes introduced, with the corresponding version in which the change was implemented.

| Change                                                           | Deprecated in | Changed in |
|:-----------------------------------------------------------------|:--------------|:-----------|
| [Removing bi-directional stream connectors](#removing-some-stream-connectors)  | 6.3           | 6.6        |
| [Promote Observable API](#change-to-the-observable-promote-API)  | 6.2           | 6.5        |
| [SAML authentication parameters](#change-to-SAML-authentication) |               | 6.2        |
| [Major changes to Filtering API](#new-filtering-API)             |               | 5.12       |



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
