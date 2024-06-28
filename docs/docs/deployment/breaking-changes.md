# Breaking changes and migrations

This section lists breaking changes introduced in OpenCTI, per version starting with the latest.

Please follow the migration guides if you need to upgrade your platform. 

## OpenCTI 6.2

### Change to the observable "promote"  

The API calls that promote an Observable to Indicator now return the created Indicator instead of the original Observable.

**GraphQL API**

* Mutation `StixCyberObservableEditMutations.promote` is now deprecated
* New Mutation `StixCyberObservableEditMutations.promoteToIndicator` introduced


**Client-Python API**

* Client-python method `client.stix_cyber_observable.promote_to_indicator` is now deprecated
* New Client-python method `client.stix_cyber_observable.promote_to_indicator_v2` introduced


!!! warning "Discontinued Support"

    Please note that the deprecated methods will be permanently removed in OpenCTI 6.5.

#### How to migrate

If you are using custom scripts that make use of the deprecated API methods, please update these scripts.

The changes are straightforward: if you are using the return value of the method, you should now expect the new Indicator 
instead of the Observable being promoted; adapt your code accordingly.


### Change to SAML authentication

When `want_assertions_signed` and `want_authn_response_signed` SAML parameter are not present in OpenCTI configuration, 
the default is now set to `true` by the underlying library (passport-saml) when previously it was `false` by default.

#### How to migrate

If you have issues after upgrade, you can try with both parameters set to `false`.

## OpenCTI 5.12

### Major changes to the filtering APi

OpenCTI 5.12 introduces a major rework of the **filter engine** with breaking changes to the model.

A [dedicated blog post](https://blog.filigran.io/introducing-advanced-filtering-possibilities-in-opencti-552147565faf) describes the reasons behind these changes.

#### How to migrate

Please read the dedicated [migration guide](../reference/filters-migration.md).
