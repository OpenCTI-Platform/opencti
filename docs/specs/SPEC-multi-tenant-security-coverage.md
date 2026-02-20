# SPEC: Multi-Tenant Security Coverage (MSSP)

**Status:** Draft
**Date:** 2026-02-16
**Scope:** OpenCTI Platform + OpenAEV Connector Integration

---

## 1. Executive Summary

This specification describes the evolution of the Security Coverage feature to support **multiple concurrent security coverage assessments per entity**, each scoped to a specific **organization**. This is required for MSSP (Managed Security Service Provider) deployments where multiple organizations share the same OpenCTI platform with data segregation enabled, and each organization operates its own OpenAEV instance (or tenant) to assess its own security posture.

---

## 2. Context & Vision

### 2.1 Current State

Today, OpenCTI supports **exactly one Security Coverage per covered entity** (Intrusion Set, Report, Campaign, Incident, Grouping, Case Incident). This limitation is enforced at three levels:

1. **Identifier uniqueness** — The `standard_id` of a `Security-Coverage` entity is derived solely from the `objectCovered` reference (see `securityCoverage.ts:31-39`). Two Security Coverages pointing to the same covered entity would produce the same `standard_id`, making them the same object via upsert.

    ```typescript
    // securityCoverage.ts — identifier definition
    identifier: {
      definition: {
        [ENTITY_TYPE_SECURITY_COVERAGE]: [{ src: 'objectCovered' }],
      },
      resolvers: {
        objectCovered(data) { return (data as StoreEntity).standard_id; },
      },
    },
    ```

2. **GraphQL schema** — Every covered entity type exposes `securityCoverage` as a **singular** field (`SecurityCoverage`), not a connection/list:

    ```graphql
    type Report {
      securityCoverage: SecurityCoverage  # singular
    }
    type IntrusionSet {
      securityCoverage: SecurityCoverage  # singular
    }
    ```

3. **Query logic** — The `findSecurityCoverageByCoveredId` function calls `loadEntityThroughRelationsPaginated`, which explicitly fetches `first: 1` and returns only the first edge:

    ```typescript
    // middleware-loader.ts:536-541
    export const loadEntityThroughRelationsPaginated = async <T>(
      context, user, connectedEntityId, relationType, entityType, reverse_relation
    ): Promise<T> => {
      const args = { first: 1 };
      const pagination = await pageRegardingEntitiesConnection<T>(...);
      return pagination.edges[0]?.node;
    };
    ```

4. **Frontend guard** — The creation form (`SecurityCoverageCreation.tsx`) filters out entities that already have a coverage via a `regardingOf` `not_eq` filter, preventing users from creating a second one.

### 2.2 Target Vision

In an MSSP deployment:

- **Organization A** (e.g., a bank) operates its own OpenAEV instance (or a dedicated tenant on a multi-tenant OpenAEV). It wants to assess how well its own security stack covers the threats described in an Intrusion Set like "APT29".
- **Organization B** (e.g., a hospital) on the same OpenCTI platform shares access to the same Intrusion Set "APT29" (via organization sharing / `RELATION_GRANTED_TO`), but has a completely different security stack. It has its own OpenAEV instance and needs its own, independent security coverage results.
- **The MSSP platform operator** (platform organization) may also maintain a reference coverage or a consolidated view.

Each organization must be able to:
1. Create its own Security Coverage for the same covered entity
2. Get results from its own OpenAEV connector/tenant
3. See only its own coverage by default (organization segregation)
4. Optionally compare coverages across organizations (for platform org users)

### 2.3 Complexity: Cross-Organization Visibility

A critical challenge is that **organizations don't have the same access to the same entities**:

- Intrusion Set "APT29" might be shared with Org A and Org B via `RELATION_GRANTED_TO`
- But Report "APT29 Campaign Q1 2026" might only be shared with Org A
- Org B can create a coverage for "APT29" (the Intrusion Set) but not for the Report it cannot see
- The platform organization sees everything and could create coverages on behalf of any entity

This means the multi-tenant coverage system must respect the existing access control model and cannot assume uniform entity visibility across organizations.

---

## 3. Proposed Architecture

### 3.1 Option Analysis

Three approaches were evaluated for associating a Security Coverage with an organization:

| # | Approach | Description | Pros | Cons |
|---|----------|-------------|------|------|
| **A** | **Organization in identifier** | Add organization to the `standard_id` derivation, making (objectCovered + organization) the unique key | Clean uniqueness guarantee; natural deduplication; aligns with STIX identity model | Requires migration; must handle "no org" coverages; single org per coverage |
| **B** | **Connector account → organization** | Derive the organization from the OpenAEV connector's service account organization membership | No data model change for creation; natural link | Fragile coupling; manual coverages have no connector; doesn't solve identifier conflict |
| **C** | **Explicit organization field** | Add a mandatory `coverageOrganization` ref field on SecurityCoverage | Explicit; supports manual + automated; flexible | New field to manage; still needs identifier change |

### 3.2 Recommended Approach: Option A + C Combined

**Add the organization as both a first-class field and an identifier component.**

The Security Coverage identity becomes:

```
standard_id = uuid_v5(objectCovered.standard_id + organization.standard_id)
```

Where `organization` is the **owning organization** of this coverage assessment. This ensures:
- Two orgs can each have their own coverage for the same Intrusion Set
- The platform organization can have its own "reference" coverage
- The identifier is deterministic and prevents duplicates within the same (entity, org) pair

For coverages created on platforms **without** organization segregation enabled, the `organization` component can be the platform's default organization or a sentinel value (e.g., `PLATFORM_COVERAGE`), maintaining backward compatibility.

---

## 4. Data Model Changes

### 4.1 New Field: `coverageOrganization`

A new **mandatory** reference relationship on `Security-Coverage`:

| Property | Value |
|----------|-------|
| **Name** | `coverageOrganization` |
| **Type** | ref (single) |
| **Target** | `Identity-Organization` |
| **Mandatory** | `external` (required at creation) |
| **Filterable** | `true` |
| **Upsert** | `true` |

```typescript
// securityCoverage.ts — new ref relation
{
  name: INPUT_COVERAGE_ORGANIZATION,
  type: 'ref',
  databaseName: RELATION_COVERAGE_ORGANIZATION,
  stixName: ATTRIBUTE_COVERAGE_ORGANIZATION,
  label: 'Coverage organization',
  mandatoryType: 'external',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
},
```

### 4.2 Identifier Change

Update the identifier definition to include both `objectCovered` and `coverageOrganization`:

```typescript
identifier: {
  definition: {
    [ENTITY_TYPE_SECURITY_COVERAGE]: [
      { src: 'objectCovered' },
      { src: 'coverageOrganization' },
    ],
  },
  resolvers: {
    objectCovered(data) { return (data as StoreEntity).standard_id; },
    coverageOrganization(data) { return (data as StoreEntity).standard_id; },
  },
},
```

This makes the unique key `(covered_entity, organization)` — exactly one coverage per entity per organization.

### 4.3 GraphQL Schema Changes

#### On SecurityCoverage type

```graphql
type SecurityCoverage {
  # ... existing fields ...
  coverageOrganization: Organization!  # NEW — the org that owns this assessment
}

input SecurityCoverageAddInput {
  # ... existing fields ...
  coverageOrganization: String!  # NEW — organization ID
}
```

#### On covered entity types — singular to connection

Replace the singular `securityCoverage` field with a connection:

```graphql
type Report {
  # BEFORE:
  # securityCoverage: SecurityCoverage

  # AFTER:
  securityCoverages(
    first: Int
    after: ID
    orderBy: SecurityCoverageOrdering
    orderMode: OrderingMode
    filters: FilterGroup
  ): SecurityCoverageConnection

  # Convenience: get MY org's coverage (based on user's organizations)
  mySecurityCoverage: SecurityCoverage
}
```

Apply the same pattern to: `IntrusionSet`, `Campaign`, `Incident`, `Grouping`, `CaseIncident`.

### 4.4 Backward Compatibility: `mySecurityCoverage`

The `mySecurityCoverage` resolver provides a drop-in replacement for the old singular `securityCoverage` field:

```typescript
mySecurityCoverage: async (entity, _, context) => {
  const user = context.user;
  const userOrgIds = user.organizations.map(o => o.internal_id);
  // Find the first coverage for this entity that belongs to one of the user's orgs
  return findSecurityCoverageByEntityAndOrgs(context, user, entity.id, userOrgIds);
};
```

This ensures existing integrations and frontends that expect a single coverage continue to work seamlessly for the logged-in user's perspective.

---

## 5. Domain Logic Changes

### 5.1 New Query Functions

```typescript
// Find all coverages for a given entity (paginated, respects access control)
export const findSecurityCoveragesByCoveredId = async (
  context: AuthContext, user: AuthUser, coveredId: string, args: EntityOptions
) => {
  const filters = addFilter(args.filters, 'regardingOf', [
    { key: 'relationship_type', values: [RELATION_COVERED] },
    { key: 'id', values: [coveredId] },
  ]);
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverage>(
    context, user, [ENTITY_TYPE_SECURITY_COVERAGE], { ...args, filters }
  );
};

// Find coverage for a specific entity + organization pair
export const findSecurityCoverageByEntityAndOrg = async (
  context: AuthContext, user: AuthUser, coveredId: string, organizationId: string
) => {
  // Query with both filters: object-covered = coveredId AND coverageOrganization = orgId
};

// Find the user's own coverage (first matching org)
export const findMySecurityCoverage = async (
  context: AuthContext, user: AuthUser, coveredId: string
) => {
  const userOrgIds = user.organizations.map(o => o.internal_id);
  for (const orgId of userOrgIds) {
    const coverage = await findSecurityCoverageByEntityAndOrg(context, user, coveredId, orgId);
    if (coverage) return coverage;
  }
  return null;
};
```

### 5.2 Updated Resolvers

Replace all occurrences of `findSecurityCoverageByCoveredId` across:
- `resolvers/report.js`
- `resolvers/intrusionSet.js`
- `resolvers/campaign.js`
- `resolvers/incident.js`
- `modules/grouping/grouping-resolver.ts`
- `modules/case/case-incident/case-incident-resolvers.ts`

With new resolvers:

```typescript
{
  Report: {
    securityCoverages: (report, args, context) =>
      findSecurityCoveragesByCoveredId(context, context.user, report.id, args),
    mySecurityCoverage: (report, _, context) =>
      findMySecurityCoverage(context, context.user, report.id),
  },
}
```

---

## 6. OpenAEV Connector Integration

### 6.1 Current Flow

1. User creates a Security Coverage (manual or automated)
2. If automated: OpenAEV enrichment connector picks up the entity
3. OpenAEV runs tests and pushes results back via the connector API
4. Results update the Security Coverage entity

### 6.2 Multi-Tenant Flow

In a multi-tenant scenario, each organization has its own OpenAEV instance (or tenant). The association works as follows:

```
┌──────────────────────────────────────────────────────┐
│                   OpenCTI Platform                    │
│                                                      │
│  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Security Coverage │  │ Security Coverage │         │
│  │  Intrusion: APT29 │  │  Intrusion: APT29 │        │
│  │  Org: Bank A      │  │  Org: Hospital B  │        │
│  │  [automated]      │  │  [automated]      │        │
│  └────────┬─────────┘  └────────┬─────────┘         │
│           │                      │                    │
│  ┌────────▼─────────┐  ┌────────▼─────────┐         │
│  │ OpenAEV Connector │  │ OpenAEV Connector │        │
│  │ svc-acct: Bank A  │  │ svc-acct: Hosp B  │        │
│  └────────┬─────────┘  └────────┬─────────┘         │
└───────────┼──────────────────────┼───────────────────┘
            │                      │
   ┌────────▼────────┐   ┌────────▼────────┐
   │  OpenAEV         │   │  OpenAEV         │
   │  Instance/Tenant │   │  Instance/Tenant │
   │  (Bank A stack)  │   │  (Hospital B)    │
   └─────────────────┘   └─────────────────┘
```

#### 6.2.1 Connector → Organization Binding

Each OpenAEV connector instance is associated with a **service account user**. That user belongs to an organization. This is the natural binding:

```
OpenAEV Connector → connector_user (service account) → user.organizations[0] → Organization
```

**Rules:**
- When an automated Security Coverage is created, the `coverageOrganization` is set to the organization selected by the user (which must be one of the user's organizations)
- When the enrichment connector receives the coverage to process, it only processes coverages where `coverageOrganization` matches the connector's service account organization
- Each OpenAEV connector instance is therefore scoped to a single organization

#### 6.2.2 Connector Enrichment Routing

Today, enrichment connectors process any `Security-Coverage` entity. With multi-tenancy, we need **connector-to-organization routing**:

```typescript
// When triggering enrichment, select the right connector
const selectEnrichmentConnector = (coverageOrgId: string, connectors: Connector[]) => {
  return connectors.find(c => {
    const connectorOrgs = c.connector_user.organizations.map(o => o.internal_id);
    return connectorOrgs.includes(coverageOrgId);
  });
};
```

**New behavior:**
- When a Security Coverage is created with `coverageOrganization = "Bank A"`, only the OpenAEV connector whose service account belongs to "Bank A" will process it
- If no matching connector exists, the automated option should be disabled for that organization (falls back to manual)
- The enrichment trigger must include organization context so the connector can scope its assessment to the right OpenAEV tenant

#### 6.2.3 STIX Bundle Extension

The STIX bundle sent to OpenAEV (`securityCoverageStixBundle`) must include the organization context:

```typescript
// Add organization identity to the bundle
const orgEntity = await storeLoadById(context, user, coverageOrganization.id);
const stixOrg = convertStoreToStix_2_1(orgEntity);
objects.push(stixOrg);
```

This allows OpenAEV to know which tenant/context to use for the assessment.

---

## 7. Frontend Changes

### 7.1 Entity Detail View — Coverage Tab

Replace the current single-coverage display with an **organization-scoped view**:

```
┌─────────────────────────────────────────────────────┐
│  Intrusion Set: APT29                                │
│  ┌─────────────────────────────────────────────────┐ │
│  │ Security Coverage                                │ │
│  │                                                  │ │
│  │  Organization selector: [My Org ▼]               │ │
│  │                                                  │ │
│  │  ┌──────────────────────────────────────┐        │ │
│  │  │ Coverage: APT29 - Bank A             │        │ │
│  │  │ Prevention: 85%  Detection: 72%      │        │ │
│  │  │ Last result: 2026-02-15              │        │ │
│  │  │ Mode: Automated (OpenAEV)            │        │ │
│  │  └──────────────────────────────────────┘        │ │
│  │                                                  │ │
│  │  [+ Add Security Coverage]                       │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

**Behavior:**
- For users in a **single organization**: show their org's coverage directly (similar to today)
- For users in **multiple organizations**: show an org selector dropdown
- For **platform organization** users: show all coverages with org filter, or a comparison view
- The "Add Security Coverage" button only appears if the user's selected org doesn't already have a coverage for this entity

### 7.2 Creation Form Changes

Update `SecurityCoverageCreation.tsx`:

1. **Step 0 (new):** Organization selection
   - Auto-selected if user belongs to a single org
   - Dropdown if user belongs to multiple orgs
   - Platform org users can create on behalf of any org

2. **Step 1:** Mode selection (Manual / Automated)
   - The "Automated" card is enabled/disabled **per organization** — only if a matching OpenAEV connector exists for the selected org

3. **Step 2:** Entity selection
   - Remove the `regardingOf not_eq` filter that blocks already-covered entities
   - Instead, filter: entity must not already have a coverage **for the selected organization**

4. **Step 3:** Details (unchanged)

### 7.3 Coverage List View

In `SecurityCoverages.tsx` (Analyses > Security Coverages):

- Add `coverageOrganization` as a visible and filterable column
- Default filter: show coverages for the user's organizations
- Platform org users see all coverages

### 7.4 Comparison View (Platform Org Users)

A new optional view for platform organization users to **compare coverage results across organizations** for the same entity:

```
┌─────────────────────────────────────────────────────┐
│  APT29 — Coverage Comparison                         │
│                                                      │
│  Metric       │ Bank A │ Hospital B │ Platform Ref   │
│  ─────────────┼────────┼────────────┼──────────────  │
│  Prevention   │  85%   │    62%     │    90%         │
│  Detection    │  72%   │    45%     │    88%         │
│  Vulns        │  91%   │    78%     │    95%         │
│  ─────────────┼────────┼────────────┼──────────────  │
│  Last updated │ Feb 15 │  Feb 14    │   Feb 13       │
│  Mode         │  Auto  │   Auto     │   Manual       │
└─────────────────────────────────────────────────────┘
```

This view is **only available to platform org users** or users with `SETTINGS_SET_ACCESSES` capability, as it crosses organization boundaries.

---

## 8. Access Control & Data Segregation

### 8.1 Rules

| Scenario | Behavior |
|----------|----------|
| User in Org A views Intrusion Set shared with Org A and B | Sees only Org A's coverage |
| Platform org user views same Intrusion Set | Sees all coverages (or filtered by org selector) |
| User in Org A tries to create coverage for Org B | **Denied** — user can only create for their own org(s) |
| User in Org B accesses Report only shared with Org A | Cannot see the Report → cannot create/see coverage |
| OpenAEV connector for Org A pushes results | Only updates Org A's coverage; cannot update Org B's |
| Entity has no org restriction (global) | Each org can still create its own coverage for it |

### 8.2 Organization Filtering on SecurityCoverage

The `objectOrganization` ref on Security Coverage (already present but non-filterable) must be:
1. Made **filterable** (`isFilterable: true`)
2. **Automatically populated** at creation with the `coverageOrganization` value
3. Used by the access control layer to enforce visibility

When organization segregation is enabled, a user in Org A querying `securityCoverages` will only see coverages where `objectOrganization` includes their org — this is already handled by the standard organization filtering in the middleware, provided the coverage is properly tagged.

### 8.3 Coverage ↔ Covered Entity Visibility Mismatch

**Problem:** Org A can see Intrusion Set "APT29" but Org B cannot (not shared). Org A creates a coverage. Later, the Intrusion Set is shared with Org B. Org B now sees the entity but has no coverage for it.

**Solution:** This is the expected behavior. Org B can create its own coverage when it gains access. Coverages are not automatically shared when the covered entity is shared — each org independently decides to assess coverage.

---

## 9. Migration Plan

### 9.1 Database Migration

1. **Add `coverageOrganization` field** to existing Security Coverage entities
2. **Migrate existing coverages:**
   - If platform has a `platform_organization` set: assign existing coverages to the platform organization
   - If no platform organization: assign to a default "Platform" organization or leave nullable during transition
3. **Recompute `standard_id`** for all existing coverages to include the organization component
4. **Update indices** to support filtering by `coverageOrganization`

```javascript
// Migration: 17XXXXXXXXXX-add-coverage-organization.js
export const up = async (next) => {
  // 1. Get platform org
  const settings = await getSettings();
  const platformOrgId = settings.platform_organization;

  // 2. Update all existing Security-Coverage entities
  const coverages = await findAllSecurityCoverages();
  for (const coverage of coverages) {
    // Assign to platform org (or creator's org as fallback)
    await patchEntity(coverage.id, {
      coverageOrganization: platformOrgId || coverage.createdBy?.organization,
    });
    // Recompute standard_id
    await recomputeStandardId(coverage);
  }
};
```

### 9.2 API Backward Compatibility

- The singular `securityCoverage` field on entities is **deprecated but preserved** for 2 minor versions
- It returns the `mySecurityCoverage` result (user's org coverage)
- GraphQL schema marks it as `@deprecated(reason: "Use securityCoverages connection or mySecurityCoverage")`
- Python client `opencti_security_coverage.py` updated to support `coverageOrganization` parameter

### 9.3 Connector Protocol

- OpenAEV connectors must be updated to send `coverageOrganization` in their enrichment payloads
- Backward compatibility: if a connector doesn't send org info, the platform assigns based on the connector's service account org

---

## 10. Configuration

### 10.1 Platform Settings

```yaml
# Existing
xtm:
  openaev_url: "https://openaev.example.com"

# No change needed — multiple connectors can be registered independently
# Each connector instance already has its own URL and service account
```

### 10.2 Connector Registration

Each OpenAEV connector registers with:
- Its own service account (belonging to a specific organization)
- Its own OpenAEV instance URL (or tenant identifier)
- Its own scope (still `Security-Coverage`)

The platform distinguishes connectors by their `connector_id`, and routes enrichment work based on the coverage's `coverageOrganization` matching the connector's org.

---

## 11. Edge Cases

| Edge Case | Resolution |
|-----------|------------|
| User belongs to multiple orgs | Must select which org when creating coverage |
| No OpenAEV connector for an org | Automated option disabled for that org; manual still available |
| Coverage org is deleted | Coverage becomes orphaned; migration task to reassign or archive |
| Entity is unshared from an org | Coverage remains (historical data); marked as "entity access revoked" |
| Platform org user creates coverage | Can choose any org, including platform org itself |
| Connector pushes results for wrong org | Rejected — org mismatch check in enrichment pipeline |
| No org segregation enabled | `coverageOrganization` defaults to platform org; UX hides org selector; behaves like today |

---

## 12. Implementation Phases

### Phase 1: Data Model Foundation
- Add `coverageOrganization` ref field to SecurityCoverage module
- Update identifier definition to include organization
- Write database migration for existing coverages
- Update GraphQL schema (add field, deprecate singular resolvers)

### Phase 2: Backend Logic
- New query functions (`findSecurityCoveragesByCoveredId`, `findMySecurityCoverage`, etc.)
- Update all entity resolvers (Report, IntrusionSet, Campaign, etc.)
- Enrichment routing by organization
- Access control enforcement on coverageOrganization

### Phase 3: Frontend — Core UX
- Organization selector in creation form
- Replace singular coverage display with org-scoped view
- Update coverage list with org column and filter
- Conditional "Add Coverage" button (per org)

### Phase 4: Frontend — Advanced
- Comparison view for platform org users
- Coverage matrix view per org
- Dashboard widgets for multi-org coverage metrics

### Phase 5: Connector Protocol
- Update OpenAEV connector protocol to include org context
- STIX bundle extension with organization identity
- Connector-to-org routing in enrichment pipeline

---

## 13. Open Questions

1. **Should a user be able to create a coverage on behalf of another organization?** Current proposal: only platform org users or users with `SETTINGS_SET_ACCESSES` can do this.

2. **What happens to the attack pattern matrix view?** Each org's coverage would produce its own matrix overlay. The comparison view could show matrices side by side.

3. **Should coverage results be exportable per org in STIX bundles?** Likely yes — the bundle should include the `coverageOrganization` identity.

4. **Rate limiting on OpenAEV connectors:** If multiple orgs request automated coverage for the same entity simultaneously, should we coordinate or let each connector operate independently?

5. **Coverage aggregation:** Should the platform org have a way to compute an "aggregate" coverage across all orgs (e.g., min/max/average scores)?
