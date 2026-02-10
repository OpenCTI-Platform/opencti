# Define an authentication strategy via the graphical interface

!!! tip "Enterprise edition"

     Please read the information below to have all the information.SSO configuration & usage is under the [OpenCTI Enterprise Edition license](https://docs.opencti.io/latest/administration/enterprise/?h=ente). Please read the information below to have all the details.
 
All the configurations listed below require an Enterprise Edition to work, except the Local strategy.

## Supported Strategies

Under the hood, we technically use the strategies provided by [PassportJS](http://www.passportjs.org/). We integrate a subset of the strategies available with passport. If you need more, we can integrate other strategies.

Via UI, you can configure the following stategies  

- LDAP
- Local strategy
- OpenID
- SAML
- Certificate (not avaiable yet)
- Headers.

## Create a new configuration

To create a new configuration, you need to have the [right capability](https://docs.opencti.io/latest/administration/users/). 
Assuming you have it, when navigating to Parameters / Authentications, you will land on a screen to manage your authentication strategies.

![Authentication overview](assets/authentication-overview.png)


Click on the button to create a new strategy. Only the following strategies will be available:

LDAP
OpenID
SAML
Headers
Certificate (if not already existing; only one certificate strategy can exist at a time).
Each of the configurations has some mandatory fields. Once these are provided, you will be able to create your configuration. Providing a group mapping or an org mapping is not mandatory to create your authentication.

By default, a created authentication will be enabled, meaning that it will be visible on your login screen. You can update this behavior by toggling off the field in the creation form.

### Specifities per Configuration

#### OpenID

When selecting OpenID, a form will open.

![OpenID creation form](assets/authentication-OpenID-creation.png)

For OpenID, the following fields are mandatory:

- A configuration name, allowing you to differentiate between two configurations of the same type
- An authentication name, allowing you to customize the name of the button present on the login screen
- Client ID: The ID of your Identity Provider client entity
- Client secret: The secret of your Identity Provider client
- OpenID issuer: The root URI of your platform

Once successfully created, you will land on the overview screen of your authentication.

![OpenID overview](assets/authentication-OpenID-overview.png)


#### SAML
When selecting SAML, a form will open.

![SAML creation form](assets/authentication-SAML-creation.png)

For SAML, the following fields are mandatory:

- A configuration name, allowing you to differentiate between two configurations of the same type
- An authentication name, allowing you to customize the name of the button present on the login screen
- SAML Entity ID/Issuer: the equivalent of the base_url attribute, your actual OpenCTI URL
- SAML URL callback: the Identity Provider’s login endpoint where users are sent to authenticate
- Identity provider encryption certificate: a mandatory parameter (PEM format) because it is used to validate the SAML response. Depending on the certificate format, it may include the header, footer, and newline (\n) characters
- SAML URL (entry point)

Once successfully created, you will land on the overview screen of your authentication.

![SAML overview](assets/authentication-SAML-overview.png)


The private_key (PEM format) is optional and is only required if you want to sign the SAML client request. It will be encrypted in the database for security reasons.

!!! note "Certificates"

    Be careful to put the `cert` / `private_key`  key in PEM format. Indeed, a lot of systems generally export the keys in X509 / PCKS12 formats and so you will need to convert them. 
    Here is an example to extract PEM from PCKS12:
    ```bash
    openssl pkcs12 -in keystore.p12 -out newfile.pem -nodes
    ```


#### LDAP
When selecting LDAP, a form will open.

![LDAP creation form](assets/authentication-LDAP-creation.png)

For LDAP, the following fields are mandatory:

- A configuration name, allowing you to differentiate between two configurations of the same type
- An authentication name, allowing you to customize the name of the button present on the login screen
- URL: the LDAP server URL
- Bind DN: distinguished name of the user to bind to
- Search base
- Search filter
- Group search base
- Group search filter

Once successfully created, you will land on the overview screen of your authentication.

![LDAP overview](assets/authentication-LDAP-overview.png)

#### Certificate

When using an OpenID Connect provider secured with a certificate issued by a **custom Certificate Authority (CA)** or a **self-signed certificate**, OpenCTI (running on Node.js) might not inherently trust this certificate. This can lead to connection errors like `unable to get local issuer certificate`.

To resolve this, you need to instruct OpenCTI to **trust your custom CA certificate**. 

When selecting Certificate a form will open.

After these steps, OpenCTI should successfully establish a secure connection with your OpenID Connect provider using your custom certificate.

**Security Warning:** **Do not disable certificate validation** (e.g, by setting `rejectUnauthorized` to false if such an option existed for OIDC) in production environments. This is a significant security risk and makes your connection vulnerable to Man-in-the-Middle attacks. 

Always prefer trusting the CA certificate as described above.

#### Headers
This strategy can authenticate the users directly from trusted headers.

### Add a custom field not present in SAML, LDAP, OpenID forms

The list of fields present in the graphical interface are the main fields that we have seen being used. However, it is important to be able to support additional fields that are needed for various authentications.
In this regard, there is the possibility to add more custom values that will be used by our Passport/Node OpenID library.

You need to specify a type, add the corresponding value that you want to send to Passport, and the key it will match in Passport so that you can send the correct value with the right field.

![custom fields](assets/authentication-creation-addMoreFields.png)

#### All passport fields
[This Github page](https://github.com/node-saml/node-saml/blob/25c434a3ccada8777e13a1e6b34c42bbd5b9ef4b/src/types.ts#L144-L211) represents the list of fields that are supported by our passport library. It's fairly technical information, but will give you the full picture of all custom fields you can add in your authentication, on the top of the already provided fields. 

### Passeport List of non-supported fields 

| category                                        | field name                                                                              | field type                | commment                 |
|-------------------------------------------------|-----------------------------------------------------------------------------------------|---------------------------|--------------------------|
|                                                 | Identity ProviderCert                                                                   | string                    | one string only supported|
|                                                 | Identity ProviderCertCallback                                                           | string                    | one string only supported|
|                                                 | decryptionPvk?                                                                          | Buffer                    | only string is supported |
|                                                 | additionalParams                                                                        | Record<string, string>    |                          |
|                                                 | additionalAuthorizeParams                                                               | Record<string, string>    |                          |
|                                                 | additionalLogoutParams                                                                  | Record<string, string>    |                          |
|                                                 | racComparison                                                                           | RacComparison             |                          |
|                                                 | scoping?| SamlScopingConfig                                                             |                           |                          |
|                                                 | cacheProvider                                                                           | CacheProvider             |                          |
|                                                 | validateInResponseTo                                                                    | ValidateInResponseTo      |                          |
|                                                 | samlAuthnRequestExtensions?                                                             | Record<string, unknown>   |                          |
|                                                 | samlLogoutRequestExtensions?                                                            | Record<string, unknown>   |                          |
| metadataContactPerson?                          | "@contactType": "technical", "support", "administrative","billing", "other"; Extensions?| string                    |                          |
| metadataContactPerson?                          | Company?                                                                                | string                    |                          |
| metadataContactPerson?                          | GivenName?                                                                              | string                    |                          |
|  metadataContactPerson?                         | SurName?                                                                                | string                    |                          |
| metadataContactPerson?                          | EmailAddress?                                                                           | string                    |                          |
| metadataContactPerson?                          | TelephoneNumber?                                                                        | string                    |                          |
| metadataOrganization?: {OrganizationName:       | @xml:lang                                                                               | string                    |                          |
| metadataOrganization?: {OrganizationName:       | #text                                                                                   | string                    |                          |
| metadataOrganization?: {OrganizationDisplayName:| @xml:lang                                                                               | string                    |                          |
| metadataOrganization?: {OrganizationDisplayName:| #text                                                                                   | string                    |                          |
| metadataOrganization?: {OrganizationURL:        | @xml:lang                                                                               | string                    |                          |
| metadataOrganization?: {OrganizationURL:        | #text                                                                                   | string                    |                          |


#### Passeport List supported fields

| category                          | field name                      | field type    | commment |
|-----------------------------------|---------------------------------|---------------|----------|
| Mandatory                         | Identity ProviderCert           | string        |          |
| Mandatory                         | issuer                          | string        |          |
| Mandatory                         | callbackUrl                     | string        |          |
| Core                              | entryPoint?                     | string        |          |
| Core                              | decryptionPvk?                  | string        |          |
| Additional SAML behaviors         | identifierFormat                | string, null  |          |
| Additional SAML behaviors         | allowCreate                     | bolean        |          |
| Additional SAML behaviors         | spNameQualifier?                | string, null  |          |
| Additional SAML behaviors         | acceptedClockSkewMs             | number        |          |
| Additional SAML behaviors         | attributeConsumingServiceIndex?:| string        |          |
| Additional SAML behaviors         | disableRequestedAuthnContext    | boolean       |          |
| Additional SAML behaviors         | authnContext                    | string        |          |
| Additional SAML behaviors         | forceAuthn                      | boolean       |          |
| Additional SAML behaviors         | skipRequestCompression          | boolean       |          |
| Additional SAML behaviors         | authnRequestBinding?            | string        |          |
| Additional SAML behaviors         | providerName?                   | string        |          |
| Additional SAML behaviors         | passive                         | boolean       |          |
| Additional SAML behaviors         | Identity ProviderIssuer?        | string        |          |
| Additional SAML behaviors         | audience                        | string, false |          |
| Additional SAML behaviors         | wantAssertionsSigned            | boolean       |          |
| Additional SAML behaviors         | wantAuthnResponseSigned         | boolean       |          |
| Additional SAML behaviors         | maxAssertionAgeMs               | boolean       |          |
| Additional SAML behaviors         | generateUniqueId                | string        |          |
| Additional SAML behaviors         | signMetadata                    | boolean       |          |
| InResponseTo Validation           | requestIdExpirationPeriodMs     | number        |          |
| Logout                            | logoutUrl                       | string        |          |
| Logout                            | logoutCallbackUrl?              | string        |          |
| extras                            | disableRequestAcsUrl            | boolean       |          |

#### Deprecated for all strategies
The following field is deprecated for all strategies: `roles_management`.
`credentials_provider` from CyberArk is not migrated either. 

### Using Cyberark along with OpenID
To use Cybrark with OpenID, you can follow these steps: 

- Create OpenID configuration in UI, note the identifier (eg: "oic") it will need to match environment varaible name
- For the field that will be overrided by cyberark configuration, you can put any string it will be ignored (to pass the mandatory field checks)
- You will need to keep the cyberark configuration in environment variable such as:

```json
{
 "providers": {
   "oic": {
     "credentials_provider": {
       "selector": "cyberark",
       "cyberark": {
         "uri": "https://<cyberark-url>",
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

## Group mapping

Now that a configuration is defined, you can define the group mapping (if applicable) for the authentication supporting this functionality.

Depending on the option you have set in OpenCTI, a newly created user will inherit or not inherit some default groups. Therefore, any new user, in addition to the mapping provided in the configuration, will be created with the groups and associated roles defined by default.
This can be managed in Settings / Security / Groups, by going into a specific group and enabling or disabling the toggle “Granted by default at user creation”.

## Common behavior for all authentications supporting group mapping: automatically create a new group
When performing group mapping, you can always enable an option to create specific groups within OpenCTI.
The groups of a user who logs in will automatically be created if they don’t exist.

More precisely, if the user who tries to authenticate has groups that don’t exist in OpenCTI but exist in the SSO configuration, there are two cases:

If the “automatically create a new group” option is enabled in the configuration: the groups are created at the platform initialization, and the user will be mapped to them.
Else: an error is raised.


### OpenID group mapping 

To create group mapping, you first need to identify within the token, the attribute that will be used to identify group. Additional data can be used to help you defining group mapping, such as the 'group path', 'group scope' & 'access token'.
**Please be aware that data needs to be added with a specific format: add square bracket & each value between single quotes (even for unique value). For example: ['value1', 'value2']**

If not sufficient, in a similar way than the configuration form, you can add custom values, if you need to map multiple groups from your identity provider to OpenCTI groups clicking on the option to "add a new value".

Last but not least, you can also enable an option (disbaled by default) to automatically add users to the default groups you have defined in OpenCTI, in addition to the groups you have selected. 

![OpenId group mapping](assets/authentication-OpenID-groupMapping.png)


### SAML group mapping

To create group mapping, you first need to identify within the token, the attribute that will be used to identify group.
**Please be aware that data needs to be added with a specific format: add square bracket & each value between single quotes (even for unique value). For example: ['value1', 'value2']**

Then, in a similar way than the configuration form, to add your mapping from your identity provider to OpenCTI groups, click on the option to "add a new value".

![group mapping](assets/authentication-All-groupMapping.png)

### LDAP group mapping 
To create group mapping, you first need to identify within the token, the attribute that will be used to identify group.

Then, in a similar way than the configuration form, to add your mapping from your identity provider to OpenCTI groups, click on the option to "add a new value".

![group mapping](assets/authentication-All-groupMapping.png)

### Headers group mapping
To create group mapping, you first need to identify within the token, the attribute that will be used to identify group.

Then, in a similar way than the configuration form, to add your mapping from your identity provider to OpenCTI groups, click on the option to "add a new value".

![group mapping](assets/authentication-All-groupMapping.png)

### Certificate group mapping
To create group mapping, you first need to identify within the token, the attribute that will be used to identify group.

Then, in a similar way than the configuration form, to add your mapping from your identity provider to OpenCTI groups, click on the option to "add a new value".

![group mapping](assets/authentication-All-groupMapping.png)

## Organization mapping
For any Authentication Strategy, you can define the organization mapping, meaning to which organization in OpenCTI you want your users to belong when they will log in.

### OpenID organization mapping 
First define, the path in token.

Then, you can add organization scope & access token & provide mapping by clicking on add new value.

![organization mapping](assets/authentication-OpenID-orgMapping.png)

###  All other strategies
For all other strategies, you only need to define the path in the token that should be used to define the organization mapping & define the mapping via the Add a new value button.

![organization mapping](assets/authentication-All-orgMapping.png)

## Troubleshooting 
Setting up a configuration correctly is always a struggle. To understand what is happening you need to have a look at your logs, available in your solution used to deploy OpenCTI.


## Specific behavior of Local Auth 
Local Auth is the authentication with Username & password. 

This Authentication is unique, meaning that you cannot create a new one. The authentication can be however disabled. 

If the authentication is disabled, it means that the form to enter username & password will not be present within UI. 

Please be careful before disabling it: 

- you should ensure that you have at least another authentication working (meaning that not only you get successfully authenticated, but that both your group mapping & organization mapping are correct) before disabling it.







