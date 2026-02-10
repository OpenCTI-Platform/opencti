# Define an authntication strategy via the graphical interface

!!! tip "Enterprise edition"

     SSO configuration & usage is under the [OpenCTI Enterprise Edition](https://docs.opencti.io/latest/administration/enterprise/?h=ente) license. Please read the information below to have all the information.
 
All the configurations listed below require an Entreprise Edition to work, except the Local strategy. 

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
Assuming you have it, wen navigating to Parameters/authentications, you will land on a screen to manage your authentication strategies.

Click on the button to create a new strategy. Only the following stategies will be avaiable: 

- LDAP
- OpenID
- SAML
- Headers
- Certificate (if not already existing, only one certifcate strategy can exist at a time).

Each of the configurations have some mandatory fields. Once these are provided, you will be able to create your configuration. Providing a group mapping or an org mapping **is not mandatory to create your authentication.**
By default, an authentication created will be enabled, meaning that it will be visible on your login screen: you can update this beahvior by toggling off the field in the creation form.

### Specifities per Configuration

#### OpenID

When selecting OpenID a form will open:


For OpenID, the following fields are mandatory: 

- a configuration name, allowing you to differentiate between two configurations of the same type
- an authentication name, allowing to customize the name of the button present on the login screen.
- ClientID: The ID of your Identity Provider client entity that created & signed the SAML
- Client Secret: The secret of your Identity Provider client
- OpenID issuer: the root URI of your platform

Once succesfully created, you will land on the overview screen of your Authentication.

#### SAML
When selecting SAML a form will open:

For SAML, the following fields are mandatory: 

- a configuration name, allowing you to differentiate between two configurations of the same type
- an authentication name, allowing to customize the name of the button present on the login screen.
- SAML Entity ID/Issuer: the equivalent of the `base_url` attribute, your actual OpenCTI URL.
- SAML SSO URL: The Identity Provider’s login endpoint where users are sent to authenticate.
- Identidy provider encryption certificate: parameter mandatory (PEM format) because it is used to validate the SAML response. Depending on certificate format it may include the header, footer and newline (\n) characters.
- Entry point: **what is it? ⇒ it’s the Identity Provider url, duplicates with**  SAML SSO URL ??

The private_key (PEM format) is optional and is only required if you want to sign the SAML client request. Will be encrypted in database for security reason.

!!! note "Certificates"

    Be careful to put the `cert` / `private_key`  key in PEM format. Indeed, a lot of systems generally export the keys in X509 / PCKS12 formats and so you will need to convert them. 
    Here is an example to extract PEM from PCKS12:
    ```bash
    openssl pkcs12 -in keystore.p12 -out newfile.pem -nodes
    ```


#### LDAP
When selecting LDAP a form will open:


For LDAP, the following fields are mandatory: 

- a configuration name, allowing you to differentiate between two configurations of the same type
- an authentication name, allowing to customize the name of the button present on the login screen.
- **URL: the equivalent of the `base_url` attribute, your actual OpenCTI URL.**
- Bind DN: Distinguished name of the user to bind to
- Search Base
- Search Filter
- Group search base
- Group search filter

Once succesfully created, you will land on the overview screen of your Authentication.

#### Certificate

When using an OpenID Connect provider secured with a certificate issued by a **custom Certificate Authority (CA)** or a **self-signed certificate**, OpenCTI (running on Node.js) might not inherently trust this certificate. This can lead to connection errors like `unable to get local issuer certificate`.

To resolve this, you need to instruct OpenCTI to **trust your custom CA certificate**. 

When selecting Certificate a form will open:


After these steps, OpenCTI should successfully establish a secure connection with your OpenID Connect provider using your custom certificate.

**Security Warning:** **Do not disable certificate validation** (e.g, by setting `rejectUnauthorized` to false if such an option existed for OIDC) in production environments. This is a significant security risk and makes your connection vulnerable to Man-in-the-Middle attacks. 

Always prefer trusting the CA certificate as described above.

#### Headers
This strategy can authenticate the users directly from trusted headers.

### Add a custom field not present in SAML, LDAP, OpenID forms

The list of fields present in the graphical interface are the main fields that we have seen being used. However it is important to be able to support additionnal fields that are needed for various authentications.
In this regards, there is the possiblity to add more custom values, that will be used by our Passport/Node OpenID library. 


You need to specify a type, add the corresponding value that you want to send to passport & they key it will match in passport that you can send the correct value with the right field.

#### All passport fields
This Github page represent the list of fields that are supported by our passport library. It's fairly technical information, but will give you the full picture of all custom fields you can add in your authentication, on the top of the already provided fields. 

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

Now that a configuration is defined, you can define the group mapping (if applicable) for the authentication supporting this functionalities.

Depending on the option you have set in OpenCTI, a newly created user will inherit or not of some default groups. Therefore, any new user, in addition to the mapping provided in the configuration will be created with the groups & associated roles defined by default. 

This can be managed in Settings/Security/groups, by going into a specific group and enabling or disabling the toggle “Granted by default at user creation”.

## Common behavior for all authentications supporting group mapping: automatically create a new group
When performing grouping mapping, you can always enable an option to create a specific group within OpenCTI.

The groups of a user that logins will automatically be created if they don’t exist.

More precisely, if the user that tries to authenticate has groups that don’t exist in OpenCTI but exist in the SSO configuration, there are two cases:

- if *the automatically create a new group otpion is enabled* in the  configuration: the groups are created at the platform initialization and the user will be mapped on them.
- else: an error is raised.


### OpenID group mapping 
### SAML group mapping
### LDAP group mapping 
### Headers group mapping
### Certificate group mapping

## Troubleshooting 
Setting up a configuration correctly is always a struggle. To understand what is happening you need to have a look at your logs, available ???




## Specific behavior of Local Auth 
Local Auth is the authentication with Username & password. 

This Authentication is unique, meaning that you cannot create a new one. The authentication can be however disabled. 

If the authentication is disabled, it means that the form to enter username & password will not be present within UI. 

Please be careful before disabling it: 

- you should ensure that you have at least another authentication working (meaning that not only you get successfully authenticated, but that both your group mapping & organization mapping are correct) before disabling it.







