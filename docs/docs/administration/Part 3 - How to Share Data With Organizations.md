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
