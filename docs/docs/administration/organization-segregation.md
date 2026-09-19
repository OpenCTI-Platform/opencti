# Organization segregation

!!! tip "Enterprise edition"

    Platform segregation by organization is available under the "OpenCTI Enterprise Edition" license. Please read the [dedicated page](enterprise.md) to have all the information.

*A reference guide covering setup, RBAC configuration, best practices, main-organization customization, and data-sharing patterns.*

---

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

# Part 2 — Customizing the Platform as the Main Organization

Being the main organization gives you unrestricted visibility across the whole platform, and it comes with a set of administrative levers to shape the experience for every other organization sharing the platform.

### 2.1 Confirm / change the main organization

**Settings > Security > Policies > Platform main organization** — this is a platform-wide switch and should only be changed deliberately (re-read the prerequisites in 1.2 first).

### 2.2 Control what other organizations' users can see about each other

By default, once segregation is active, visibility of other users (in filters, assignee/author/participant pickers, access-restriction dialogs, etc.) is limited. As the main organization, you can decide the policy:

- A user sees all other users if any of the following is true:
  - They hold the **Bypass** capability, or capability to manage users/playbooks/customization.
  - The "**Access to collaborative creation**" capability is granted to the relevant users/roles — without it, users cannot see or select other organizations when sharing entities.
  - The policy option "**Allow users to view users of other organizations**" is enabled (a main-organization-level toggle in **Settings > Policies**) — note: as covered above, this only applies when organization segregation is not strictly enforced; under full segregation, cross-organization user visibility is governed by default enforcement, not this toggle.

  ⚠️ **Important:** this toggle is only relevant when organization segregation is not strictly enforced. Once organization-based segregation is fully enforced (i.e., the EE segregation mode / "Organization segregation" is active), the platform enforces this behavior by default — users cannot see users from other organizations regardless of the toggle, and the setting is no longer configurable in that mode. The toggle only has an effect in the non-segregated (or partially segregated) configuration, where it can be used to loosen or tighten cross-organization user visibility.

- Use **Authorized Members** on Organization entities (since 6.7) if you want to control, at a finer grain, who can even see a given organization in lists/filters — grant **Can View** to expose it in pickers, **Can Edit** to allow editing it, **Can Manage** to allow managing its own access restrictions.

### 2.3 Delegate user management via Organization Administrators

As the main organization, you decide which members of each partner/customer organization can be promoted to Organization Administrator (see 1.7). You also define which groups an org admin is allowed to assign to the users they create — this is your safety rail against privilege escalation by delegated admins. Use this to let large customers or ISAC members onboard their own users without opening a support ticket to main-org admins every time.

### 2.4 Customize behavior per Group / per Organization

As the main organization, you can tailor the platform experience differently for each population:

- **Default home dashboards** — set per group so each organization's users land on a relevant view.

  ⚠️ **Important:** setting a dashboard as the default home view does not grant access to it. Custom Dashboards have their own **Authorized Members (AM)** setting, separate from the "default dashboard" assignment. If you want a specific organization (or group) to land on a specific dashboard:

  1. Grant access to the dashboard first — add the target organization/group (or its members) to the dashboard's Authorized Members.
  2. Then set it as the default home dashboard for that group (or organization).

  Skipping step 1 will result in users being pointed to a dashboard they cannot actually open — always verify AM on the dashboard itself before assigning it as a default.

- **Default triggers and digests** — pre-configure notification behavior per group.
- **Hidden menus / hidden entity types** — hide categories globally (Settings > Parameters) or per role, so partner organizations only see the entity types relevant to them (e.g., hide Case management from an organization that only consumes finished intelligence).

  ⚠️ **Important:** this is a UI-only convenience setting, not an access control. Hiding a menu or entity type only affects what appears in the platform's interface — it does not restrict access. Users can still read, create, or edit those hidden entity types via the API, or via any other capability/permission they already hold. Do not rely on hidden menus as a substitute for proper RBAC (capabilities, roles, groups) or organization-based segregation (Authorized Members, sharing). Use this purely to simplify and declutter the experience for organizations that don't need certain entity types visible — real access boundaries must be enforced through capabilities and segregation settings, as described in Part 1.

- **Confidence level ceilings** — a user's max confidence is the highest across their groups; use this to keep external-organization contributions from overriding your own analysts' confidence by default.

### 2.5 Decide the sharing model you will operate

As the main organization you typically choose (and can combine) one of the following operating models, detailed fully in Part 3:

- **Manual, ad hoc sharing** via the "Share with an Organization" button on individual entities/containers — fine for occasional, low-volume sharing.
- **Automated sharing via playbooks** — the recommended approach for anything recurring, using Resolve Neighbors + Share with Organizations (+ optional Reduce Knowledge filtering).
- **Default sharing via connector/user organization membership** — an alternative model for cases where an entire data source (e.g., a full connector feed such as CrowdStrike, or an entire stream) needs to be shared with an organization, with no filtering or selection logic required.

  Instead of building a playbook to re-share everything that connector ingests, simply add the connector's Service Account (or the user in charge of creating the data) to the target organization(s), in addition to the main/platform organization.

  Because objects are shared by default with the organizations of the user/service account that creates them, this makes sharing happen automatically at ingestion time — no playbook, no Resolve Neighbors step, no risk of missing a relationship or observable.

  **When to use this model**

  - The entire output of a connector or integration should go to one (or several) specific organizations, with no partial/selective sharing needed.
  - You want to avoid maintaining a dedicated playbook per organization just to replicate what a connector already produces.

  **When not to use this model**

  - You need selective or conditional sharing (e.g., only certain entity types, or only TLP:CLEAR data) — use the playbook-based approach with Reduce Knowledge instead.
  - The same connector's data must be split differently across organizations depending on content — a single service account can only default-share to a fixed set of organizations, so it can't apply per-object logic.

  **Trade-off to flag:** since this applies at creation time to everything the account produces, any future addition to that connector's scope (new entity types, new data) will automatically be shared too — review connector scope changes with this in mind.

- A global "**public**" distribution channel using a dedicated **ALL_SUB_ORG** organization for TLP:CLEAR data.
- **Per-organization dedicated playbooks** for organization-specific, non-public data.

### 2.6 Set up the Request Access workflow for your users

As the main organization holding most of the knowledge, you will likely be the one validating access requests from partner organizations (see 1.8). Configure the RFI-based workflow so requests route to the right internal validator group, and assign that group deliberately — it is effectively your "data release" gate.

### 2.7 Governance checklist for the main organization

- Main organization designated and all connector users placed in it.

- Groups/roles reviewed so only intended roles hold Restrict organization access.

- Default dashboards/triggers/hidden menus configured per group for each partner organization.

- Organization Administrators promoted where delegation is desired, with a bounded group list.

- Apply Authorized Members (AM) on constituent/constituent/sub organization Organization entities — for MSSP setups where the main organization manages multiple constituents, restrict each Organization object's Authorized Members to the MSSP admins and that organization's own members only. This ensures constituents cannot see each other or know of each other's existence on the platform. Do this at onboarding time, before any data is shared with the constituent.

- Request Access workflow configured with the correct validator group.

- Sharing model chosen (manual vs. playbook-driven vs. hybrid) and documented internally.

- ALL-style organization created if a public/TLP:CLEAR distribution channel is needed.

---

# Part 3 — How to Share Data With Organizations

This section explains, in practical terms, how sharing actually works once an organization is designated as the platform's main organization, and how to design reliable, automated sharing workflows. Understanding the points below is essential — most of the "why can't organization X see the dashboard/relationship/etc." support cases trace back to one of these mechanics being misunderstood.

### 3.1 Organization-based segregation is not multi-tenancy

**This is the single most important concept to internalize.**

When an entity is shared with several organizations, there is still only **one version** of that entity in OpenCTI. Every organization that has access sees the same object, and any modification to it is immediately visible to all of them.

> **Example:** System A is shared with both Organization X and Organization Y. If an analyst adds an analysis to the system's description, both X and Y instantly see the same updated description — there is no independent copy per organization.

**Practical consequence:** sharing controls *who can see* an object, it does not create isolated copies of it. If a comment or analysis should be visible to only one organization, do not add it to the shared entity itself — create a separate **Note**, and share that Note independently of the main entity.

### 3.2 An entity and a relationship are two distinct objects

In OpenCTI's data model, a statement like:

```
System A  --uses-->  IP 1.2.3.4
```

is actually **three separate STIX objects**: the System A entity, the IP 1.2.3.4 entity, and the `uses` relationship connecting them.

Sharing one of these objects does not automatically share the others. If you only share System A:

- ✅ System A is shared
- ❌ The `uses` relationship is not shared
- ❌ The IP 1.2.3.4 observable is not shared

The recipient organization may therefore see the system, but not the objects connected to it — and may not even know they exist.

### 3.3 Why dashboards can appear empty

This exact scenario has been observed in practice: recipients could see the shared System and the shared Observable, but **not** the relationship linking them.

OpenCTI's dashboards and visualizations, however, are largely built on relationships, not on isolated entities. 

The result: **Visible entities + Invisible relationships = Empty or incomplete dashboard**

If a widget or dashboard looks empty for a partner organization even though the underlying entities are shared, the relationship graph connecting those entities is the first thing to check.

### 3.4 The special case of containers

OpenCTI distinguishes two categories of objects:

- **Standard entities** (System, Malware, Vulnerability, IP, Domain, etc.) — connected to each other exclusively through relationships, which exist as independent objects (see 3.2).
- **Containers** (Report, Case, Grouping, etc.) — where objects are contained inside the container itself, as part of its structure.

This difference has a direct impact on sharing behavior:

| You share… | What gets shared automatically |
|---|---|
| A container | ✅ The container, ✅ its contained entities, ✅ its contained relationships |
| A standard entity | ✅ The entity only — ❌ its relationships, ❌ its neighboring entities are not shared |

In other words, sharing a Report is safe by default (its contents travel with it); sharing a bare System, Malware, or Indicator is not — you must explicitly extend the share to its neighborhood.

### 3.5 Using the "Resolve Neighbors" playbook pattern to close the gap

To correctly share a standard entity together with everything connected to it, build a playbook using this pattern:

```
System entity  →  Resolve Neighbors  →  Share With Organization
```

The **Resolve neighbors relations and entities (add in bundle)** component retrieves the triggering entity, all of its relationships, and all entities at the other end of those relationships ("first neighbors") — collecting the relevant fragment of the knowledge graph:

```
        System
          |
          +---- Relationship
          |
          +---- Observable
          |
          +---- Software
```

The **Share With Organizations** component is then applied to this enriched bundle, sharing the whole fragment — not just the original entity — with the target organization.

> **Note:** Share With Organizations performs a direct database query before the "Send for ingestion" step. If an entity is created earlier in the same playbook (e.g., via a container-creation step) and shared in that same run, the playbook will fail because the entity does not exist yet in the database. In that case, run the creation and the sharing in two separate playbooks.

### 3.6 "All elements in the bundle" is mandatory for neighborhood sharing

Every scope-controlled playbook component (including Share With Organizations) can be applied to:

- **Main element in the bundle** (the default for most components),
- **All elements in the bundle**,
- **All except the main element in the bundle**.

If Share With Organizations is left on its default "Main element only" scope, the playbook will keep re-sharing just the System — the relationships and neighboring observables collected by Resolve Neighbors will never actually be shared. To share the full neighborhood retrieved by Resolve Neighbors, the scope must be changed to "**All elements in the bundle**" (or "All except main element" where the main element is already shared/handled separately).

### 3.7 Filtering what actually gets shared

Sharing everything connected to an entity is not always desirable. After a Resolve Neighbors step, insert a **Reduce Knowledge** component to keep only the part of the graph that should be released — for example, sharing only Observables, or explicitly excluding Incidents.

```
System → Resolve Neighbors → Reduce Knowledge (filter) → Share With Organizations
```

This turns a "share everything nearby" playbook into a selective, governed sharing workflow — the recommended pattern whenever a mix of sensitive and shareable objects surrounds the same entity.

### 3.8 Global distribution of public information (TLP:CLEAR)

For information that is meant to reach every consuming organization (TLP:CLEAR / fully public data), the recommended pattern is **not** to run one playbook per recipient, but to create a single dedicated distribution organization, e.g. **ALL_SUB_ORG**.

- Every constituent/sub organization organization's users are made members of both their own local organization **and** ALL_SUB_ORG.
- A single playbook watches for newly created/updated TLP:CLEAR knowledge and shares it with ALL_SUB_ORG:

```
TLP:CLEAR entity  →  Share With Organizations (ALL_SUB_ORG)
```

- Because every constituent/sub organization belongs to that organization, all of them automatically receive anything marked as publicly shareable, without maintaining a per-organization rule for public data.

### 3.9 Sharing with one specific organization

For knowledge that should go to a single named partner (e.g., Organization A) rather than everyone, combine a manual first step with a recurring automated one:

**Step 1 — Manual, one-time share:**

```
System X  →  (Share with an Organization)  →  Organization A
```

**Step 2 — Recurring playbook (e.g., run daily):**

```
Query Knowledge (systems shared with Organization A)
        →  Resolve Neighbors
        →  Share With Organizations (Organization A)
```

This scheduled playbook re-queries everything already shared with Organization A, resolves each system's current neighborhood, and shares any newly connected relationships/entities that appeared since the last run — keeping the organization's view continuously in sync as the knowledge graph evolves, without requiring an analyst to remember to re-share every update manually.

### 3.10 Why you generally need one playbook per organization

The Share With Organizations component targets a **fixed** organization configured inside the node itself. As a result, a distinct target organization requires a distinct playbook:

```
Organization A → Playbook A
Organization B → Playbook B
Organization C → Playbook C
```

This pattern is perfectly manageable for a handful of organizations (roughly up to ten), but the maintenance overhead grows linearly with the number of organizations and becomes harder to sustain at larger scale. When designing for many recipient organizations, weigh this against the ALL_SUB_ORG pattern (3.8) for anything that doesn't actually need per-organization differentiation, and reserve dedicated playbooks for genuinely organization-specific data.

### 3.11. Sharing to All Organizations or a Subset of Organizations (Clustering via Participation)

The playbook-per-organization approach described above works well for individual, targeted sharing, but it doesn't scale efficiently when the goal is to share information with all organizations at once, or with a logical subset of organizations (e.g., all organizations belonging to the energy sector). Building and maintaining one playbook per organization for this purpose would be error-prone and easy to forget.

**Use case**

As a platform organization, I want to share information with a group of constituents without having to trigger multiple playbooks manually — and without the risk of forgetting one of them.

**Step-by-step setup**

1. Create a "cluster" organization, for example **Energy**. This organization does not represent a real tenant; it acts as a logical grouping/sector container.
2. Enable the rule "**Organization propagation via participation**" in OpenCTI. This rule automatically grants access to members of an organization when that organization participates in another one.
3. Link each relevant organization to the cluster by creating a **part-of** relationship between it and the cluster organization:

   ```
   Organization X ---part-of---> Energy
   ```

   Repeat this for every organization that should belong to the cluster.
4. Share the entity with the cluster organization (**Energy**). Because of the participation rule, all users belonging to any organization that is part-of Energy automatically gain access to the shared entity — with no need for a dedicated playbook per organization.

**Warning**

Because every user in a participating organization inherits access through the cluster, any data shared with the cluster organization becomes visible to all members of every organization that is part of it. This clustering approach should be reserved for information that is genuinely intended for the entire sector/group — not for organization-specific or sensitive data, which should still follow the dedicated organization + dedicated playbook pattern described in section 9.

### 3.12. Executive Summary

- An **entity** is not the same as a **relationship**.
- Sharing an entity does not automatically share its relationships.
- Dashboards rely on relationships to build visualizations.
- **Resolve Neighbors** retrieves: the entity, its relationships, and the connected entities.
- **Share With Organization** must be configured to share "All elements in the bundle."
- Public (TLP:CLEAR) data should be shared through a dedicated **ALL_SUB_ORG** organization.
- Organization-specific data should use a dedicated organization and a dedicated playbook.
- To share with all or a subset of organizations (e.g., a sector cluster) without maintaining one playbook per organization, use a **cluster organization** combined with the "**Organization propagation via participation**" rule and **part-of** relationships — bearing in mind this grants access to every member of every participating organization.
- Organization-based segregation is **not multi-tenancy**: a shared object remains the same object for everyone who has access to it.

[Request for access on knowledge restricted by organization segregation](request-access.md)