# Users and Role Based Access Control

## Introduction

In OpenCTI, the RBAC system not only related to what users can do or cannot do in the platform (aka. `Capabilities`) but also to the system of [data segregation](segregation.md). Also, platform behaviour such as default home dashboards, default triggers and digests as well as default hidden menus or entities can be defined across groups and organizations.

## High level design

![RBAC](assets/rbac.png)

## Roles 

Roles are used in the platform to grant the given groups with some **capabilities** to define what users in those groupes can do or cannot do.

### List of capabilities

| Capability                                                          | Description                                                                             |
| :------------------------------------------------------------------ | :-------------------------------------------------------------------------------------- |
| `Bypass all capabilities`                                           | Just bypass everything including data segregation and enforcements.                     |
| `Access knowledge`                                                  | Access in read-only to all the knowledge in the platform.                               |
| &nbsp;&nbsp;`Access to collaborative creation`                      | Create notes and opinions (and modify its own) on entities and relations.               |
| &nbsp;&nbsp;`Create / Update knowledge`                             | Create and update existing entities and relationships.                                  |
| &nbsp;&nbsp;&nbsp;&nbsp;`Restrict organization access`              | Share entities and relationships with other organizations.                              |
| &nbsp;&nbsp;&nbsp;&nbsp;`Delete knowledge`                          | Delete entities and relationships.                                                      |
| &nbsp;&nbsp;`Upload knowledge files`                                | Upload files in the `Data` and `Content` section of entities.                           |
| &nbsp;&nbsp;`Download knowledge export`                             | Download the exports generated in the entities (in the `Data` section).                 |
| &nbsp;&nbsp;`Ask for knowledge enrichment`                          | Trigger an enrichment for a given entity.                                               |
| `Access exploration`                                                | Access to workspaces whether custom dashboards or investigations.                       |
| &nbsp;&nbsp;`Create / Update exploration`                           | Create and update existing workspaces whether custom dashboards or investigations.      |
| &nbsp;&nbsp;&nbsp;&nbsp;`Delete exploration`                        | Delete workspaces whether custom dashboards or investigations.                          |
| `Access connectors`                                                 | Read information in the `Data > Connectors` section.                                    |
| &nbsp;&nbsp;`Manage connector state`                                | Reset the connector state to restart ingestion from the beginning.                      |
| `Access Taxii feed`                                                 | Access and consume TAXII collections.                                                   |
| &nbsp;&nbsp;`Manage Taxii collections`                              | Create, update and delete TAXII collections.                                            |
| `Access administration`                                             | Access and manage overall parameters of the platform in `Settings > Parameters`.        |
| &nbsp;&nbsp;`Manage credentials`                                    | Access and manage roles, groups, users, organizations and security policies.            |
| &nbsp;&nbsp;`Manage marking definitions`                            | Update and delete marking definitions.                                                  |
| &nbsp;&nbsp;`Manage labels & Attributes`                            | Update and delete labels, custom taxonomies, workflow and case templates.               |
| `Connectors API usage: register, ping, export push ...`             | Connectors specific permissions for register, ping, push export files, etc.             |
| `Connect and consume the platform streams (/stream, /stream/live)`  | List and consume the OpenCTI live streams.                                              |
| `Bypass mandatory references if any`                                | If external references enforced in a type of entity, be able to bypass the enforcement. |


### Manage roles

You can manage the roles in `Settings > Security > Roles`.

To create a role, just click on the `+` button:

![Create role](assets/create-role.png)

Then you will be able to define the capabilities of the role:

![Update role](assets/update-role.png)

## Users

You can manage the users in `Settings > Security > Users`. If you are using [Single-Sign-On (SSO)](../deployment/authentication.md), the users in OpenCTI are automatically created upon login.

To create a user, just click on the `+` button:

![Create user](assets/create-user.png)

### Manage a user

When access to a user, it is possible to:

* Visualize information including the token
* Modify it, reset 2FA if necessary
* Manage its sessions
* Manage its triggers and digests
* Visualize the history and operations

![User overview](assets/user-overview.png)

## Groups

Groups is the main vehicule to manage permissions and [data segregation](segregation.md) as well as platform customization for the given users part of this group. You can manage the groups in `Settings > Security > Groups`.

Here is the description of the group available parameters.

| Parameter                                                         | Description                                                                                                                     |
| :---------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| `Auto new markings`                                               | If a new marking definition is created, this group will automatically be granted to it.                                         |
| `Default membership`                                              | If a new user is created (manually or upon SSO), it will be added to this group.                                                |
| `Roles`                                                           | Roles and capabilities granted to the users belonging to this group.                                                            |
| `Default dashboard`                                               | Customize the home dashboard for the users belonging to this group.                                                             |
| `Default markings`                                                | In `Settings > Customization > Entity types`, if default marking definitions is enabled, default markings of the group is used. |
| `Allowed markings`                                                | Grant access to the group to the defined marking definitions, more details in [data segregation](segregation.md).               |
| `Triggers and digests`                                            | Define defaults triggers and digests for the users belonging to this group.                                                     |

![Group overview](assets/group-overview.png)

### Manage a group

When managing a group, you can define the members and all above configurations.

![Update a group](assets/update-group.png)

## Organizations

Users can belong to organizations, which is an additional layer of [data segregation](segregation.md) and customization.