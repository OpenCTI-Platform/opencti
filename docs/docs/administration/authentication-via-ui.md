# Manage authentication strategies via the graphical interface

!!! tip "Enterprise edition"

     Please read the information below to have all the information.The ability to log in via SSO is under the [OpenCTI Enterprise Edition license](https://docs.opencti.io/latest/administration/enterprise/?h=ente). Please read the information below to have all the details.
 
All the configurations listed below require an Enterprise Edition to work, except the Local strategy.

## Capability required to manage authentication strategies
To access the Authentication screen, you need to have the  [Manage Authentication capability](https://docs.opencti.io/latest/administration/users/). 


## Supported Strategies

Via UI, you can configure the following stategies  

- LDAP
- Local strategy
- OpenID
- SAML
- Certificate
- Query headers

Under the hood, we technically use the strategies provided by [PassportJS](http://www.passportjs.org/). We integrate a subset of the strategies available with passport. If you need more, we can integrate other strategies

The Authentication screen will allow you to create new strategies, but some will already be present on your screen:

- Local Strategy
- Query Headers
- Certificate (disabled by default since it requires that you define your platform with HTPS)

## Create a new configuration

WWhen navigating to Parameters / Authentications, you will land on a screen to manage your authentication strategies.

Click on the button to create a new strategy. Only the following strategies will be available:

- LDAP
- OpenID
- SAML

Each configuration has some mandatory fields. Once these are provided, you will be able to create your configuration. Providing a group mapping or an org mapping is not mandatory to create your authentication.

By default, a created authentication will be enabled, meaning it will be visible on your login screen. You can update this behavior by toggling off the field in the creation form.

### Specifities per Configuration

#### OpenID

For OpenID, the following fields are mandatory (indicated with a "*" in the form):

- A configuration name, allowing you to differentiate between two configurations of the same type. Please note that the configuration name will also be used as the name on present on the **Login button**.
- A login button name, allowing you to customize the name of the button present on the login screen
- Client ID: The ID of your Identity Provider client entity
- Client secret: The secret of your Identity Provider client
- OpenID issuer: The root URI of your platform

Additionnal not mandatory fields are present in the **Protocal and Scopes** section.

##### Using Cyberark along with OpenID
To use Cybrark with OpenID you will still need to use at least partially, your environnement variables. Follow these steps:


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


#### SAML

For SAML, the following fields are mandatory (indicated with a "*" in the form):

- A configuration name, allowing you to differentiate between two configurations of the same type. Please note that the configuration name will also be used as the name on present on the **Login button**.
- Issuer: the equivalent of the base_url attribute, your actual OpenCTI URL
- Call back URL: the Identity Provider’s login endpoint where users are sent to authenticate
- Identity provider encryption certificate: a mandatory parameter (PEM format) because it is used to validate the SAML response. Depending on the certificate format, it may include the header, footer, and newline (\n) characters
- SAML URL (entry point)


The private_key (PEM format) is optional and is only required if you want to sign the SAML client request. It will be encrypted in the database for security reasons.

!!! note "Certificates"

    Be careful to put the `cert` / `private_key`  key in PEM format. Indeed, a lot of systems generally export the keys in X509 / PCKS12 formats and so you will need to convert them. 
    Here is an example to extract PEM from PCKS12:
    ```bash
    openssl pkcs12 -in keystore.p12 -out newfile.pem -nodes
    ```
  
  Additionnal not mandatory fields are present in the **Security & Signing** and **Request behavior** sections.


#### LDAP
For LDAP, the following fields are mandatory:

- A configuration name, allowing you to differentiate between two configurations of the same type. Please note that the configuration name will also be used as the name on present on the **Login button**.
- URL: the LDAP server URL
- Bind DN: distinguished name of the user to bind to
- Search base
- Search filter
- Group search base
- Group search filter

Additionnal not mandatory fields are present in the **Search & Authentication** section.

### Add a custom field not present in SAML, LDAP, OpenID 

The list of fields present in the graphical interface are the main fields that we have seen being used. 
However, it is important to be able to support additional fields that are needed for various authentications.

In each form, you can use the **Extra Configuration** section to add a new custom field:
- Click on the "+" to add a new field
- Specify a field type 
- Add a key (the field in passport library that this field needs to map with)
- Add a value .


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



#### Deprecated for all strategies
The following field is deprecated for all strategies: `roles_management`.
`credentials_provider` from CyberArk is not migrated either. 


## Group mapping

Now that a configuration is defined, you can define the group mapping all for authentications (except Local).


All authentications alwyas have these two option: 
- **Prevent platform default group association:** in OpenCTI you can allow some groups to be granted by default at user creation. This option allows you to define whether you want any new user created through the defined authentication to get these default groups granted by default. **By default, users will be granted platform default group**.
- **Auto create groups:** you can decide to automatically create the group that you have mapped. Please be aware that a group requires a role for a user to be able to have some rights [(more information)](../administration/users.md)
When performing group mapping, you can always enable an option to automatically create specific groups within OpenCTI.

Then for each authentications, you need to provide: 
- the group expression: identification of where to find the group information 
- the group splitter: if mutliple groups are present, the character that will be used to parse the various groups 
- the group mapping: the mapping between the value of the group in your provider and the groups that exist in the platform. Be sure to type the exact same group name as it exists in the platform to avoid group duplication. 


## Organization mapping
For any authentication strategy (except Local), you can define the organization mapping, meaning to which organization in OpenCTI you want your users to belong when they will log in.

Organization mapping allow you to create automatically the organization you have mapped. **This option is disabled by default**.

The bahvior is really similar to the group mapping, since you need to provide
- the organization expression: identification of where to find the organization information 
- the organization splitter: if mutliple organizations are present, the character that will be used to parse the various organizations 
- the organization mapping: the mapping between the value of the organization in your provider and the organizations that exist in the platform. Be sure to type the exact same organization name as it exists in the platform to avoid organization duplication. 


## Troubleshooting an authentication

### Use logs provided through UI
When setting up an authentication, it might be difficult to have it right at first try.

For each authentication except Local, the last 50 logs are available to help you troubleshoot any configurations (next to the edit button).
Each log will have the following information:
- Timestamp: when did the log occur
- Level: Info, Success or Error.
- Message: the message indicating the error
- Details: you can view the full log by clicking on the button on the right handside (and copy paste it).

### In case you are locked out
It could be possible to lock yourself out of the platform. 
We have a few safeguard to avoid this situation, but it is possible: for instance local authentication **cannot be disabled if you don't have any other authentication enabled**.

#### Failed migration

In case your authentication used to work prior the [migration](../deployment/breaking-changes/7.0-SSO-authentication-migration.md), there is a solution: 

Steps to unblock yourself: 
1. In your configuration file, add the variable **app:authentication:force_env**.
2. Set the value to **true**.
3. Restart your platform again.

This will allow you to use your configuration file to login instead of the configurations stored in database. 

However, you won't be able to edit any authentication in UI, given you have stated that you wish to use your variables to login.

Enabling the **app:authentication:force_env** variable will remove any stored authnitcation in your Database. When the platform will be restarted without this configuration [all compatible](../deployment/breaking-changes/7.0-SSO-authentication-migration.md) authentications will be migrated once more. 

#### Locked out of the platform, but a local account or administrator exists

In case you have locked yourself out of the application, by disabling local authentication without verifying that you have another working strategy, there is a solution.

This solution however relies on one of the following pre-requesites: 
- a local account, with the capability to [Manage Authentication](administration/users.md) exists, and you know its credentials.
- you have access to the administrator credentials defined in your configuration file.

Steps to unblock yourself:
1. Go into your configuration file and add the variable **app:authentication:force_local**.
2. Set the value to TRUE
3. Restart your platform using this configuration


You should be able to login via username & password. Once logged in, you should enable once more the local authentication in the authentication menu & then remove this variable from your configuration file.


#### Locked out of the platform, no platfrom administrator or local account

This is the exact same situation than above, but you don't have any local account, and you have disabled the administrator defined in the configuration file. 

Steps to unblock yourself:
1. Go into your configuration file and add the variable **app:admin:externally_managed**.
2. Set the value to TRUE
3. Add the variable **app:authentication:force_local**
4. Set the value to FALSE
5. Restart your platform using this configuration

You should be able to login via username & password. Once logged in, you should enable once more the local authentication in the authentication menu & then remove the added variables from your configuration file.


## Manage authentications 

Any authentication can be edited, enabled, disabled or even deleted (except Local, HTTP Headers and Client Certificate).

**Given editing an authentication is a complex action that can require mutliple fields update in one go, it is important to click on update to save your updates**.

## Specificities per authentication


### Local Authentication 

Local authentication is the authentication with Username & password. 
This authentication is unique, meaning that you cannot create a new one.

#### Enable/Disable local authentication 

The authentication can be disabled. 
If the authentication is disabled, it means that the form to enter username & password will not be present within UI. 

Please be careful before disabling it: 

- you should ensure that you have at least another authentication working (meaning that not only you get successfully authenticated, but that both your group mapping & organization mapping are correct) before disabling it.

#### Define password policy

By clicking on the local authentication you can manage your local password policies. Administrators can specify requirements such as minimum/maximum number of characters, symbols, digits, and more to ensure robust password security across the platform. Here are all the parameters available:

| Parameter                                                               | Description                                                   |
|:------------------------------------------------------------------------|:--------------------------------------------------------------|
| `Number of chars must be greater than or equals to`                     | Define the minimum length required for passwords.             |
| `Number of chars must be lower or equals to (0 equals no maximum)`      | Set an upper limit for password length.                       |
| `Number of symbols must be greater or equals to`                        | Specify the minimum number of symbols required in a password. |
| `Number of digits must be greater or equals to`                         | Set the minimum number of numeric characters in a password.   |
| `Number of words (split on hyphen, space) must be greater or equals to` | Enforce a minimum count of words in a password.               |
| `Number of lowercase chars must be greater or equals to`                | Specify the minimum number of lowercase characters.           |
| `Number of uppercase chars must be greater or equals to`                | Specify the minimum number of uppercase characters.           |

### HTTP headers
Unless this authentication strategy was defined before migrating, it should be disabled by default.
To enable it, simply toggle it on via the toggle present in the drawer and edit all the fields according to your needs.

### Client Certificate
Unless this authentication strategy was defined before migrating, it should be disabled by default.

To enable it, you need your platform to be set up to work with HTTPS.

## Manage platform authentication policies

Any configuration related to authentication policy is now managed in the authentication screen. 

### 2 factor authentication
 "Enforce Two-Factor Authentication" button is available, allowing administrators to mandate 2FA activation for users, enhancing overall account security.

### Max concurrent sessions
It is possible to specify the amount of concurrent sessions allowed on your platform. 
By default, there is no limitations (0 means that there is no maximum sessions). If you want to restrict it, simply replace this value by the amount of concurrent sessions you want to allow on OpenCTI.





