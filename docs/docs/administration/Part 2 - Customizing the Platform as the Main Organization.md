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
