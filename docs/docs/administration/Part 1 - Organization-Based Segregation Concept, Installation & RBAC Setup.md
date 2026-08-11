# Organization segregation

!!! tip "Enterprise edition"

    Platform segregation by organization is available under the "OpenCTI Enterprise Edition" license. Please read the [dedicated page](enterprise.md) to have all the information.

*A reference guide covering setup, RBAC configuration, best practices, main-organization customization, and data-sharing patterns.*

## Part 1 — Organization-Based Segregation: Concept, Installation & RBAC Setup

### 1.1 What it is

Organization-based segregation is an **OpenCTI Enterprise Edition** feature that lets a single OpenCTI platform serve multiple organizations (internal business units, external partners, ISAC members, customers, etc.) while controlling, per organization, which pieces of knowledge each group of users can see.

It complements — but is distinct from — OpenCTI's core RBAC system:

| Layer | Purpose | Controls |
|---|---|---|
| Users | Individual accounts | Identity, confidence level |
| Groups | Bundles of capabilities & marking access | What a user can do and up to which TLP/marking they can see as well as confidence level |
| Roles | Sets of capabilities assigned to groups | Fine-grained permissions (create, delete, manage, bypass, etc.) |
| Organizations | Data segregation & administrative grouping | Which entities a user can see, independent of group/role |

Organizations are not a requirement of RBAC, but once organization segregation is switched on at the platform level, they become the primary mechanism for need-to-know access control across tenants sharing the same platform.

!!! warning "License note"

    Organization segregation requires OpenCTI Enterprise Edition. Refer to the Enterprise Edition documentation for licensing details before enabling it.

### 1.2 Prerequisites

Before enabling segregation, confirm the following, since activation has platform-wide consequences:

- Every **user** must belong to at least one organization. Users without an organization will not be able to log in once segregation is active.

- **Connectors users must be Service Accounts.** They will pertain dynamically to the main platform org, without having the admin to make them part of the platform org. This also avoids issues related to Entities having Authorized members (AM), since Service Account bypass by default AM (they are able to edit if if not granted the right to, to ensure for instance that an enrichement connector can enrich data contained in a report with AM).

- A "**main organization**" must be designated in the platform settings (see 1.3). Users belonging to it get unrestricted visibility over all platform data; everyone else only sees what has been explicitly shared with their organization(s).

- Decide in advance which groups will exist and what roles/capabilities they need — particularly who is allowed to share knowledge with other organizations (**Restrict organization access** capability, see 1.5).

### 1.3 Where to enable it

Organization segregation is enabled from:

**Settings > Security > Policies > Platform main organization**

**Steps:**

1. Navigate to **Settings > Security > Policies**.
2. Locate the **Platform main organization** section.
3. Select (or create beforehand, under **Organizations** in the left menu / **Settings > Security > Organizations**) the organization that will act as the platform's "home" organization.

4. Save. From this point on:

   - Users in the main organization see all data in the platform.
   - Users in any other organization only see data explicitly shared with that organization (directly, or inherited via containers/authorized members — see Part 3).

Organizations themselves are created as entities under the **Organizations** menu (left navigation), not directly under Settings > Security. This is because an Organization in OpenCTI plays a dual role: it is both a trackable knowledge entity (e.g., a threat actor's targeted sector, a partner company) and an administrative container of users. Once created, it automatically appears under **Settings > Security > Organizations** for administration purposes.

### 1.4 RBAC setup for a segregated platform

A typical configuration workflow:

1. Create the **Organizations** that will use the platform (e.g., Filigran, Customer A, Customer B, Partner X).

2. Create **Groups** that define default behavior and marking access (e.g., default dashboards, default triggers/digests, hidden menus/entities can all be defined per group, and also per organization).

3. Create/assign **Roles** to those groups, granting only the capabilities each population needs. Key capabilities relevant to segregation:

| Capability | Effect |
|---|---|
| Bypass all capabilities | Ignores segregation entirely (super-admin only) |
| Access knowledge | Read-only baseline access |
| Create / Update knowledge | Needed to create/edit entities |
| ⤷ Restrict organization access | Allows a user to share entities/relationships with other organizations — this is the capability that exposes the "Share with an Organization" button |
| ⤷ Manage authorized members | Allows restricting an entity to specific users/groups/organizations (see Part 1.6) |
| Manage credentials | Manage roles, groups, users, organizations, security policies (admin-level) |

4. Assign **Users** to their Organization(s) and Group(s). A user can belong to several organizations and several groups simultaneously; their effective visibility is the union of what each grants.

5. Designate **Organization Administrators** where relevant (see 1.7) to delegate day-to-day user management without granting full platform admin rights.

### 1.5 What sharing actually grants

Once segregation is active, every shareable entity/relationship displays a "**Share with an Organization**" action (in the entity overview, in graph views of containers, or automated via playbooks — see Part 3). Sharing an object with an organization makes that object visible to all users of that organization who otherwise have sufficient group/role/marking rights to see it. It does not duplicate the object, and it does not, by itself, share anything connected to that object (see Part 3 for the full mechanics).

### 1.6 Authorized Members vs. Organization Segregation

**Authorized Members** is a separate, complementary access-restriction mechanism available on Custom Dashboards, Investigations, Feedbacks, Reports, Groupings, Incident Response, Requests for Information/Takedown, and Organizations themselves. It lets you restrict an object to specific users, groups, or organizations — useful, for example, to hide a sensitive incident-response case from the rest of the platform, including from the main organization.

**Key interactions to know:**

- For containers (Report, Grouping, Incident Response, Case RFI, Case RFT), if organization segregation is enabled and the container is shared with an organization, you can additionally define Authorized Members to further restrict who — within or outside that organization — can access it.

- This restriction only applies to the container itself; it does not cascade to the entities contained within it.

- **Authorized Members (AM) override organization-based segregation for that entity.** Once AM is activated on a specific entity, standard organization sharing rules no longer apply to it — access is governed exclusively by the AM list, and the "Share with an Organization" button is deactivated.
 * ⚠️ **Important — AM grants access directly, no prior sharing required:** if Organization A does not currently have access to a Report (it was never shared with them via organization sharing), you can still grant Organization A access simply by adding it directly to the Report's Authorized Members with view rights. There is no need to first share the entity with that organization — applying AM is sufficient on its own to grant access, independent of any prior sharing state.

- In other words, AM is not an additional restriction layered on top of organization sharing — it's a **replacement access mechanism** for that entity: whoever/whatever is listed in AM (users, groups, or organizations) has access, and organization-based sharing becomes irrelevant for that specific object.

- Since OpenCTI 6.7, Authorized Members can also be applied to Organization entities themselves, so that as a platform/main organization you can control who is even allowed to see the list of organizations in your database (**Can View / Can Edit / Can Manage**).

### 1.7 Organization Administration

Platform administrators can promote a member of an organization to "**Organization administrator**". This role:

- Can create, edit, and delete users within that organization only.

- Can be restricted to a defined list of groups that they are allowed to grant to the members they create (so an org admin cannot escalate privileges beyond what the platform admin intended).

- Has otherwise restricted access to Settings — they cannot manage platform-wide configuration, only their organization's membership.

This is promoted/demoted from the user's edit form by a platform administrator, and is especially useful for ISAC-style deployments or MSSP/customer setups where you want partner organizations to self-manage their own users without granting them platform admin rights.

### 1.8 Requesting access to restricted knowledge

Because segregation can cause a user to be unable to see (or re-create) knowledge that already exists but belongs to another organization, OpenCTI surfaces a generic **Restricted entity already exists** error in that case. Administrators can configure a Request Access workflow so users can formally request visibility instead of hitting a dead end:

1. Open the entity settings for **Request for Information**.

2. Configure the "**Specific workflow for request access**": define the status list to use (the RFI is created with the first status), the status used when accepted, the status used when declined, and the group allowed to see the auto-created RFIs.

3. Once configured, users who hit the restriction see a "**Request Access**" button, letting them state a reason and select the organization to request access from.

4. Users who are both members of the owning organization and the configured validator group receive the RFI (automatically placed under Authorized Members for confidentiality) with **Validate / Decline** actions. Validating shares the requested knowledge immediately.

5. To disable the feature, remove all statuses from the "Specific Workflow for Request Access" section, or remove the group from Validator membership.

### 1.9 Best practices

- Design your organization tree before switching segregation on. Retrofitting is possible but harder once users and knowledge already exist.
- **Always use a Service Account for connectors** — never a regular user account. Service Accounts are technical users designed specifically for connectors and integrations: they have no password (cannot log in via UI), authenticate only via API token, and do not receive emails. Create them in **Settings > Security > Users** (or convert an existing user into a Service Account from its overview or via mass operations).

  **Why this matters for organization segregation:** a Service Account is automatically considered to belong to the platform's main organization, in addition to any organization explicitly assigned to it. This binding is done at the session level and cannot be changed — even if you later change which organization is designated as the main platform organization, existing Service Accounts remain attached to whichever organization was the main one, ensuring uninterrupted data ingestion. (Removing the platform org from a Service Account's session context requires an explicit relation between the Service Account and another organization.) This guarantees a connector's ingested data is never orphaned from a visibility standpoint, regardless of RBAC changes elsewhere.

  **How to define a default group for Service Accounts** (so they inherit the right access automatically):

  1. Go to **Settings > Security > Groups**.

  2. Create (or select) the group intended for technical/connector accounts (e.g., *Connectors* or *Service Accounts*).

  3. In that group's configuration, enable **Default membership**. Any new user — including newly created Service Accounts, whether created manually or provisioned via SSO — will automatically be added to this group upon creation.

  4. Configure this group's **Roles/capabilities**, **Allowed markings**, and **Max confidence level** to match what connectors need (typically: Access knowledge, Create/update knowledge, appropriate TLP markings, and a high confidence level so ingested data isn't rejected).

  5. If the connector's data must also reach specific partner organizations by default (see the connector/service-account sharing model above), additionally assign the Service Account to those target organizations — on top of its automatic main-organization membership.

  **Best practice:** treat "Service Account + default group" as the standard onboarding pattern for every connector, so ingestion and visibility behave predictably without manual, per-connector configuration.

- Limit the **Restrict organization access** capability to a small set of trusted roles (e.g., senior analysts, CSMs) — this is effectively the "who can leak/share data" permission.
- Use **Authorized Members** for anything sensitive, even within your own main organization (e.g., a live incident) — segregation by organization alone won't hide something from your main organization's users.
- Use **Notes** for organization-specific commentary. Since a shared entity is a single shared object (see Part 3, point 1), any edit to it is visible to every organization with access. If an analysis, opinion, or comment should be visible to only one organization, put it in a Note and share that Note independently — never edit the shared entity's own fields with organization-specific content.

  💡 **Note on permissions:** creating and sharing Notes is governed by the "**Access to collaborative creation**" capability — the same capability referenced above for organization sharing. This means you can grant a user or role the ability to create and share Notes (for organization-specific commentary) without granting them broader write access to the underlying entities themselves. This is a useful, more granular way to let partner organizations or analysts annotate shared intelligence without exposing edit rights on the core objects.

- Prefer **playbooks** over manual sharing for anything recurring — manual "Share with an Organization" clicks do not scale and are error-prone (see Part 3).
- Periodically audit **Data > Restrictions** (authorized members) and the Organizations list to ensure segregation is behaving as intended.
- Communicate the "**single shared object**" model to all analysts — this is the single biggest source of confusion and support tickets in multi-organization deployments.

### 1.10 What segregation implies (at a glance)

- A platform with segregation enabled behaves as **one shared knowledge graph with per-organization visibility filters**, not as isolated tenants.

- Visibility is **additive** across a user's organizations and groups: the most permissive combination the user is a member of wins.

- Segregation interacts with, but does not replace, marking-based (TLP) access control — a user still needs both organization access **and** sufficient marking clearance to see an object.

- Segregation and Authorized Members can combine, but **Authorized Members takes precedence** and effectively opts an entity out of organization-based sharing once activated.

---
