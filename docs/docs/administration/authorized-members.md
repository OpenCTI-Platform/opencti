# Authorized members

!!! tip "Enterprise edition"

    Authorized members on Entities are under the "OpenCTI Enterprise Edition" license. Please read the information below to have all the information.


You have two variations of Authorized Members within the application: 
- Authorized Members on workspaces (Custom Dashboards, Investigations): By default, when a workspace is created, only the creator of the workspace has access to the workspace. Therefore, the Authorized Members aim to foster collaboration on Workspaces. As a result, these Authorized Members on Workspaces are under **Community Edition**
- Authorized Members on entities (Feedbacks, Reports, Groupings, Incident Response, Request For Information, Organizations): By default, when entities are created in the platform, they are accessible to any users having the right marking (and the right Organization in the context of Org segregation). Authorized Members functionality in that case aims to restrict access to these entities. Given it is mainly useful in the context of organization segregation (where an entity is accessible to a whole organization while you want it to only be accessible to a specific subset of users of this same org), Authorized Members on Entities are un **Entreprise Edition**

**Authorized members** allow to restrict access to an entity to certain users, groups, or organizations within the platform.

Four levels of access are available:

- View: read-only access to the entity.
- Edit: view and modify the entity.
- Manage: view, modify, delete, and administer access to the entity.
- Can use: use the entity to mention it as an author (specifically useful for the **Organization entity type**)

Once authorized members are defined, they will be the only ones with access to the entity. To prevent the creation of "ghost" entities that are only accessible in read-only mode without the ability to delete them, it is mandatory to define an administrator. If you attempt to define authorized members without an admin, an error message will be displayed.

**Authorized members** are available at multiple levels within the platform:

- Custom Dashboards
- Investigations
- Feedbacks
- Reports
- Groupings
- Incident Response
- Request for Information
- Request for Takedown
- Organizations

## Set up authorized members

To define authorized members, you need to click on the '**Manage Access Restriction**' button. This button is visible if you have the '**Manage Authorized Members**' capability.

![authorized-members-manage-access-button.png](assets%2Fauthorized-members-manage-access-button.png)

![authorized-members-pop-up.png](assets%2Fauthorized-members-pop-up.png)

If you grant access to users belonging to an Organization, it is possible since version 6.6 of OpenCTI to restrict access even more specifically to users belonging to one or more groups, in order to provide more granularity in access control.

![authorized-members-group-intersection.png](assets%2Fauthorized-members-group-intersection.png)

For the containers **Report**, **Grouping**, and **Incident Response**, as well as **Case RFT** and **Case RFI**, it is possible to define authorized members directly when creating the entity.

![authorized-members-creation-form.png](assets%2Fauthorized-members-creation-form.png)

## Administrate restricted entities

It is possible to access the list of entities restricted by authorized members via the '**Data > Restrictions**' tab. This tab is accessible to a platform administrator with the '**Bypass**' capability, ensuring that all entities with authorized members are listed without any restriction. Through this tab, it is possible to view the entities restricted by authorized members as well as additional information, such as the date when authorized members were activated. The administrator can also choose to remove the restriction by clicking on the '**Remove Access Restriction**' padlock.
 
![authorized-members-restrictions.png](assets%2Fauthorized-members-restrictions.png)

## Authorized members and organization segregation

!!! tip "Enterprise edition"

    Platform segregation by organization is available under the "OpenCTI Enterprise Edition" license. Please read the [dedicated page](enterprise.md) to have all the information.


For certain container **Reports**, **Groupings**, **Incident Response**, **Case RFI**, and **Case RFT** when segregation by organization is enabled and the container is shared with an organization, it is possible to define authorized members to further restrict access to these members who do not belong to the organization.


**This restriction will only apply to the container and will not cascade to the entities contained within the container.**

Once authorized members are activated for these entities, data segregation by organization is disabled for that specific entity. Only the authorized members will have access to the entity, and the 'Share with an organization' button in the interface is deactivated.

![authorized-members-organization-sharing-deactivation.png](assets%2Fauthorized-members-organization-sharing-deactivation.png)

### Specific case of Authorized Members on Organization in the context of Organization segregation.

In the context of Organization segregation, sometimes, as a Platform Organization, you do not want users to see all the organizations that exist in your database. This is the reason, since the 6.7.X, the Authorized Members on Organizations have been introduced:
- A user with Can View will be able to see the organization in the knowledge list. As a result, if the organization is in the Author field of an entity, or in the shared organization that the entity is shared with, the user will see the organization.
- A user with Can Edit will be able to edit the organization (and see the organization).
- A user with Can Use will be able to assign the organization as a user, but not be able to edit the organization. In essence, the organization will be able to be listed, to be selected in any list, but not editable.
- A user with Can Manage will be able to manage access restrictions on this organization.

Authorized Members of the organization will allow you to control who can see & manage the list of organizations present in your platform.
