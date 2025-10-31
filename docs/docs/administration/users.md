# Users and Role Based Access Control

## Introduction

In OpenCTI, the RBAC system not only related to what users can do or cannot do in the platform (aka. `Capabilities`) but also to the system of [data segregation](segregation.md). Also, platform behavior such as default home dashboards, default triggers and digests as well as default hidden menus or entities can be defined across groups and organizations.

## High level design

![RBAC](assets/rbac.png)

## Roles 

Roles are used in the platform to grant the given groups with some **capabilities** to define what users in those groups can do or cannot do.

### List of capabilities

| Capability                                              | Description                                                                             |
|:--------------------------------------------------------|:----------------------------------------------------------------------------------------|
| `Allow modification of sensitive configuration`         | Ability to perform changes on elements under Danger Zone.                               |
| `Bypass all capabilities`                               | Just bypass everything including data segregation and enforcements.                     |
| `Access knowledge`                                      | Access in read-only to all the knowledge in the platform.                               |
| &nbsp;&nbsp;`Access to collaborative creation`          | Create notes and opinions (and modify its own) on entities and relations.               |
| &nbsp;&nbsp;`Can use web interface export functions`    | Ability to download widgets/graphs... as images/PDF.                                    |
| &nbsp;&nbsp;`Create / Update knowledge`                 | Create and update existing entities and relationships.                                  |
| &nbsp;&nbsp;&nbsp;&nbsp;`Restrict organization access`  | Share entities and relationships with other organizations.                              |
| &nbsp;&nbsp;&nbsp;&nbsp;`Delete knowledge`              | Delete entities and relationships (and merge data).                                     |
| &nbsp;&nbsp;&nbsp;&nbsp;`Manage authorized members`     | Restrict the access to an entity to a user, group or organization.                      |
| &nbsp;&nbsp;&nbsp;&nbsp;`Bypass enforced reference`     | If external references enforced in a type of entity, be able to bypass the enforcement. |
| &nbsp;&nbsp;&nbsp;&nbsp;`Bypass mandatory fields`       | Bypass any custom fields marked as mandatory in entity customization.                   |
| &nbsp;&nbsp;`Upload knowledge files`                    | Upload files in the `Data` and `Content` section of entities.                           |
| &nbsp;&nbsp;`Import knowledge`                          | Trigger the ingestion of an uploaded file.                                              |
| &nbsp;&nbsp;`Download knowledge export`                 | Download the exports generated in the entities (in the `Data` section).                 |
| &nbsp;&nbsp;&nbsp;&nbsp;`Generate knowledge export`     | Trigger the export of the knowledge of an entity.                                       |
| &nbsp;&nbsp;`Ask for knowledge enrichment`              | Trigger an enrichment for a given entity.                                               |
| &nbsp;&nbsp;`Disseminate files by email`                | Ability to send a PDF/HTML generated as a Fintel to a dissemination list.               |
| `Access dashboards`                                     | Access to existing custom dashboards.                                                   |
| &nbsp;&nbsp;`Create / Update dashboards`                | Create and update custom dashboards.                                                    |
| &nbsp;&nbsp;&nbsp;&nbsp;`Delete dashboards`             | Delete existing custom dashboards.                                                      |
| &nbsp;&nbsp;&nbsp;&nbsp;`Manage public dashboards`      | Manage public dashboards.                                                               |
| `Access investigations`                                 | Access to existing investigations.                                                      |
| &nbsp;&nbsp;`Create / Update investigations`            | Create and update investigations.                                                       |
| &nbsp;&nbsp;&nbsp;&nbsp;`Delete investigations`         | Delete existing investigations.                                                         |
| `Access connectors`                                     | Read information in the `Data > Connectors` section.                                    |
| &nbsp;&nbsp;`Manage connector state`                    | Reset the connector state to restart ingestion from the beginning.                      |
| `Connectors API usage: register, ping, export push ...` | Connectors specific permissions for register, ping, push export files, etc.             |
| `Access data sharing`                                   | Access and consume data such as TAXII collections, CSV feeds and live streams.          |
| &nbsp;&nbsp;`Manage data sharing`                       | Share data such as TAXII collections, CSV feeds and live streams or custom dashboards.  |
| `Access ingestion`                                      | Access (read only) remote OCTI streams, TAXII feeds, RSS feeds, CSV feeds.              |
| &nbsp;&nbsp;`Manage ingestion`                          | Create, update, delete any remote OCTI streams, TAXII feeds, RSS feeds, CSV feeds.      |
| `Manage data mappers`                                   | Create, update and delete CSV & JSON mappers.                                           |
| `Use Playbooks`                                         | Use Playbooks (enroll an entity in a playbook).                                                                         |
| &nbsp;&nbsp;`Manage Playbooks`                          | Manage Playbooks.                                                                       |
| `Access to admin functionalities`                       | Parent capability allowing users to only view the settings.                             |
| &nbsp;&nbsp;`Access administration parameters`          | Access and manage overall parameters of the platform in `Settings > Parameters`.        |
| &nbsp;&nbsp;`Manage credentials`                        | Access and manage roles, groups, users, organizations and security policies.            |
| &nbsp;&nbsp;`Manage marking definitions`                | Update and delete marking definitions.                                                  |
| &nbsp;&nbsp;`Manage customization`                      | Customize entity types, rules, notifiers retention policies and decays rules.           |
| &nbsp;&nbsp;`Manage taxonomies`                         | Manage labels, kill chain phases, vocabularies, status templates, cases templates.      |
| &nbsp;&nbsp;`Manage XTM hub`                            | Manage enrollment of the OpenCTI platform into XTMHub.                                  |
| &nbsp;&nbsp;`Access to security activity`               | Access to activity log.                                                                 |
| &nbsp;&nbsp;`Access to file indexing`                   | Manage file indexing.                                                                   |
| &nbsp;&nbsp;`Access to support`                         | Generate and download support packages.                                                 |


### Manage roles

You can manage the roles in `Settings > Security > Roles`.

To create a role, just click on the `+` button:

![Create role](assets/create-role.png)

Then you will be able to define the capabilities of the role:

![Update role](assets/update-role.png)

## Users

You can manage the users in `Settings > Security > Users`. If you are using [Single-Sign-On (SSO)](../deployment/authentication.md), the users in OpenCTI are automatically created upon login.

To create a user, just click on the `+` button:

![Create user](assets/create_user.png)

# Service Account

Service Account aims administrators to create technical users. Service accounts do not have any password which therefore prevent them from logging in via UI.

## Create a Service Account
It is possible to create `Service accounts`. These accounts are specifically designed for technical users, such as connectors.

When creating a service account, an email address is automatically generated for the `Service account` if not provided by the user who creates the service account. A password is automatically generated for the `Service account` and it is not stored in the database. Technical users like connectors will authenticate using their API tokens.
Although these accounts generally do not receive emails, it is possible to add a personalized email.

## Main difference between a Service Account & a user

- A Service Account will be considered to belong to the platform's organization to ensure it can access the data: service account when logging in, will be considered as users of the main platform organisation, in addition of their current organization. This will be done by manually adding **the platform org to the user's session**. It will not be possible to change this behavior. Therefore, even if you change your main platform organization, your service account will always be considered to be part of the main platform organisation, ensuring that you do not have any issue ingesting data. Removing your platform org will ensure that your service account does not belong anymore to the platform organisation, unless a specific relation between the organisation and the service account has been created.
- A Service Account will not be able to log in via Email & Password since the password of the service account will not exists in DB.
- A service account will not be able to receive emails.

## Convert a User into a Service Account & vice-versa

It is possible to convert a user into a service account and ice-versa.
Two options are possible:
- through massive operations.
- directly in the user/service account overview.

![Convert User](assets%2Fconvert_user.png)

Converting a user into a service account will simply remove its password from our Database. The "new" service account will still have the same ID & same Token than the user, to preserve data consistency.

Converting back a service account into a user will also be possible. However, if the service account has directly been created as a service account without adding a specific email address, the "new" user won't be able to trigger a password reset flow to get a new password. We therefore advise you to first provide a valid email address to your "new" user, so that the "new" user can trigger the reset password flow by himself/herself.


### Manage a user

When access to a user, it is possible to:

* Visualize information including the token
* Modify it, reset 2FA if necessary
* Manage its sessions
* Manage its triggers and digests
* Visualize the history and operations
* Manage its max confidence levels
* Manage its status

![User overview](assets/user-overveiw-new.png)

From this view you can edit the user's information by clicking the "Update" button, which opens a panel with several tabs.

* Overview tab: edit all basic information such as the name or language
* Password tab: change the password for this user
* Groups tab: select the groups this user belongs to
* Organization Admin tab: see [Organization administration](users.md#organization-administration)
* Confidences tab: manage the user's maximum confidence level and overrides per entity type

![manage user](assets/user-manage.png)

!!! warning "Mandatory max confidence level"

    A user without Max confidence level won't have the ability to create, delete or update any data in our platform. Please be sure that your users are always either assigned to group that have a confidence level defined or that have an override of this group confidence level.

<a id="group-section"></a>

#### Account status

Account status can have four values: 

* Active: a user active will be able to log in
* Inactive: an inactive user will not be able to log in
* Locked: a locked user will not be able to log in
* Expired: an expired user will not be able to log in. A user can be in an expired state because an **Account Expiry Date** has been defined for this user, and we are past this date. It ensures automatically that the user will not be able to log in after that date.

Only the expired status can be automatically set (given the account expiry date). The other statuses can be set manually or through mass operations within the user management screen. 

## Groups

Groups are the main way to manage permissions and [data segregation](segregation.md) as well as platform customization for the given users part of this group. You can manage the groups in `Settings > Security > Groups`.

Here is the description of the group available parameters.

| Parameter                | Description                                                                                                                                                               |
|:-------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Auto new markings`      | If a new marking definition is created, this group will automatically be granted to it.                                                                                   |
| `Default membership`     | If a new user is created (manually or upon SSO), it will be added to this group.                                                                                          |
| `Roles`                  | Roles and capabilities granted to the users belonging to this group.                                                                                                      |
| `Default dashboard`      | Customize the home dashboard for the users belonging to this group.                                                                                                       |
| `Default markings`       | In `Settings > Customization > Entity types`, if a default marking definition is enabled, default markings of the group is used.                                          |
| `Allowed markings`       | Grant access to the group to the defined marking definitions, more details in [data segregation](segregation.md).                                                         |
| `Max shareable markings` | Grant authorization to the group to share marking definitions.                                                                                                            |
| `Triggers and digests`   | Define defaults triggers and digests for the users belonging to this group.                                                                                               |
| `Max confidence level`   | Define the maximum confidence level for the group: it will impact the capacity to update entities, the confidence level of a newly created entity by a user of the group. |

![Group overview](assets/group-overview-new.png)

!!! information "Max confidence level when a user has multiple groups"
 
    A user with multiple groups will have the **the highest confidence level** of all its groups. 
    For instance, if a user is part of group A (max confidence level = 100) and group B (max confidence level = 50), then the user max confidence level will be 100.

### Manage a group

When managing a group, you can define the members and all above configurations.

![Update a group](assets/update-group-new.png)

<a id="organizations-section"></a>
## Organizations

Users can belong to organizations, which is an additional layer of [data segregation](segregation.md) and customization. To find out more about this part, please refer to the page on [organization segregation](organization-segregation.md).

## Organization administration

Platform administrators can promote members of an organization as "Organization administrator". This elevated role grants them the necessary capabilities to create, edit and delete users from the corresponding Organization. Additionally, administrators have the flexibility to define a list of groups that can be granted to newly created members by the organization administrators. This feature simplifies the process of granting appropriate access and privileges to individuals joining the organization.

![Organization admin Settings view](assets/organization_admin_view.png)

The platform administrator can promote/demote an organization admin through its user edition form.

![Organization admin promoting/demoting](assets/define_organization_admin.png)

!!! info "Organization admin rights"

    The "Organization admin" has restricted access to Settings. They can only manage the members of the organizations for which they have been promoted as "admins".
