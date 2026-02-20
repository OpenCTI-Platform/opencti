# SPEC v2: Multi-Tenant Security Coverage (MSSP) — Single Entity, Aggregated Results

**Status:** Draft v2
**Date:** 2026-02-20
**Supersedes:** SPEC-multi-tenant-security-coverage.md (v1 — N entities per covered object)
**Scope:** OpenCTI Platform + OpenAEV Connector Integration

---

## 1. Executive Summary

This specification describes the evolution of the Security Coverage feature to support **multiple organizations within a single SecurityCoverage entity**. Instead of creating N separate SecurityCoverage entities (one per organization per covered entity), coverage results are **indexed by organization** within a single entity.

This solves the key problems identified in v1:
- **Scaling**: N organizations no longer creates N entities per covered threat
- **Aggregation**: MSSP operators get a unified view with per-org breakdown
- **UX simplicity**: One coverage panel per entity, with an org selector when needed

---

## 2. Why v1 Failed

The v1 approach (one SecurityCoverage entity per org per covered entity) revealed critical issues during testing:

| Problem | Impact |
|---------|--------|
| **Entity explosion** | 50 orgs x 100 intrusion sets = 5,000 SecurityCoverage entities |
| **No aggregated MSSP view** | Platform operator cannot see a consolidated score comparison |
| **Complex segregation** | Each coverage needs its own `objectOrganization` tagging, marking access, etc. |
| **Fragmented UX** | Navigating to an entity shows nothing — coverages are separate, disconnected objects |
| **No natural entity page integration** | The coverage results don't appear on the covered entity's detail page |

---

## 3. New Architecture: Single Entity, Org-Scoped Results

### 3.1 Core Concept

```
                    SecurityCoverage
                   (1 per covered entity)
                          |
          +---------------+---------------+
          |               |               |
   Org A results    Org B results    Platform results
   Prevention: 72%  Prevention: 38%  Prevention: 60%
   Detection: 85%   Detection: 52%   Detection: 70%
   Vulns: 45%       Vulns: 67%       Vulns: 55%
```

- **1 SecurityCoverage** per covered entity (IntrusionSet, Campaign, Incident, Report, Grouping, CaseIncident)
- `coverage_information` becomes an **array of org-scoped result sets**
- The `standard_id` is derived from `objectCovered` only (back to v0 behavior)
- No more `coverageOrganization` ref — orgs are embedded in the results

### 3.2 Data Model

#### `coverage_information` — New Structure

```typescript
// BEFORE (v0/v1): flat array of scores
coverage_information: [
  { coverage_name: "Prevention", coverage_score: 72 },
  { coverage_name: "Detection", coverage_score: 85 },
]

// AFTER (v2): org-scoped array of result sets
coverage_information: [
  {
    organization_id: "uuid-banque-alpha",
    organization_name: "Banque Alpha",       // denormalized for display
    last_result: "2026-02-15T10:00:00Z",
    auto_enrichment: true,
    results: [
      { coverage_name: "Prevention", coverage_score: 72 },
      { coverage_name: "Detection", coverage_score: 85 },
      { coverage_name: "Vulnerabilities", coverage_score: 45 },
    ]
  },
  {
    organization_id: "uuid-hopital-beta",
    organization_name: "Hopital Beta",
    last_result: "2026-02-10T14:30:00Z",
    auto_enrichment: true,
    results: [
      { coverage_name: "Prevention", coverage_score: 38 },
      { coverage_name: "Detection", coverage_score: 52 },
      { coverage_name: "Vulnerabilities", coverage_score: 67 },
    ]
  },
  {
    organization_id: "uuid-mssp-platform",
    organization_name: "MSSP Platform",
    last_result: "2026-02-18T08:00:00Z",
    auto_enrichment: false,
    results: [
      { coverage_name: "Prevention", coverage_score: 60 },
      { coverage_name: "Detection", coverage_score: 70 },
      { coverage_name: "Vulnerabilities", coverage_score: 55 },
    ]
  }
]
```

### 3.3 Identifier

Back to original derivation — only from the covered entity:

```typescript
identifier: {
  definition: {
    [ENTITY_TYPE_SECURITY_COVERAGE]: [
      { src: 'objectCovered' },
    ],
  },
  resolvers: {
    objectCovered(data) { return (data as StoreEntity).standard_id; },
  },
},
```

One covered entity = one SecurityCoverage. No duplication.

---

## 4. GraphQL Schema

### 4.1 Types

```graphql
type CoverageScore {
  coverage_name: String!
  coverage_score: Int!
}

type OrganizationCoverageResult {
  organization_id: ID!
  organization_name: String!
  last_result: DateTime
  auto_enrichment: Boolean!
  results: [CoverageScore!]!
}

type SecurityCoverage implements BasicObject & StixObject & StixCoreObject & StixDomainObject {
  id: ID!
  name: String!
  description: String

  # Covered entity (unchanged)
  objectCovered: StixDomainObject

  # All org-scoped results (full data, filtered by access rights)
  coverage_information: [OrganizationCoverageResult!]!

  # Convenience: results for the current user's org only
  myCoverageResult: OrganizationCoverageResult

  # Common fields
  periodicity: String
  duration: String
  external_uri: String
  coverage_valid_from: DateTime
  coverage_valid_to: DateTime

  # ... other StixDomainObject fields ...
}
```

### 4.2 Mutations

```graphql
input CoverageScoreInput {
  coverage_name: String!
  coverage_score: Int!
}

type Mutation {
  # Create a SecurityCoverage for an entity (idempotent — upserts if one already exists)
  securityCoverageAdd(input: SecurityCoverageAddInput!): SecurityCoverage

  # Push results for a specific organization
  # This is the primary mutation used by OpenAEV connectors and manual input
  securityCoveragePushResults(
    id: ID!                              # SecurityCoverage ID
    organizationId: ID!                  # Which org these results belong to
    results: [CoverageScoreInput!]!      # The scores
    autoEnrichment: Boolean              # Was this from an automated connector?
  ): SecurityCoverage

  # Remove an org's results from a coverage
  securityCoverageRemoveOrgResults(
    id: ID!
    organizationId: ID!
  ): SecurityCoverage

  # Delete the entire coverage
  securityCoverageDelete(id: ID!): ID
}

input SecurityCoverageAddInput {
  name: String!
  objectCovered: String!                 # Covered entity ID
  description: String
  periodicity: String
  duration: String
  external_uri: String
  coverage_valid_from: DateTime
  coverage_valid_to: DateTime
  # Initial results for the creating user's org (optional)
  organizationId: String                 # If not provided, uses user's org
  initialResults: [CoverageScoreInput!]
}
```

### 4.3 On Covered Entity Types

```graphql
type IntrusionSet {
  # Single coverage entity for this intrusion set
  securityCoverage: SecurityCoverage
}

type Campaign {
  securityCoverage: SecurityCoverage
}

type Incident {
  securityCoverage: SecurityCoverage
}

# Same for: Report, Grouping, CaseIncident
```

No need for `securityCoverages` (plural) anymore — there's only ever one.

---

## 5. Backend Logic

### 5.1 Result Filtering by User Organization

The key behavior: `coverage_information` is **filtered at the resolver level** based on the user's access rights.

```typescript
SecurityCoverage: {
  coverage_information: (coverage, _, context) => {
    const user = context.user;
    const allResults = coverage.coverage_information || [];

    // Platform org users or BYPASS: see everything
    if (userHasBypass(user) || userInPlatformOrg(user)) {
      return allResults;
    }

    // Regular users: filter to their org(s) + platform org results
    const userOrgIds = user.organizations.map(o => o.internal_id);
    const platformOrgId = getPlatformOrganizationId();
    const allowedOrgIds = new Set([...userOrgIds, platformOrgId]);

    return allResults.filter(r => allowedOrgIds.has(r.organization_id));
  },

  myCoverageResult: (coverage, _, context) => {
    const user = context.user;
    const userOrgIds = user.organizations.map(o => o.internal_id);
    const allResults = coverage.coverage_information || [];

    // Return the first matching org result
    return allResults.find(r => userOrgIds.includes(r.organization_id)) || null;
  },
}
```

### 5.2 Push Results

```typescript
export const securityCoveragePushResults = async (
  context: AuthContext, user: AuthUser,
  coverageId: string, organizationId: string,
  results: CoverageScoreInput[], autoEnrichment: boolean
) => {
  // Access control: user must belong to the org (or be platform/BYPASS)
  assertUserCanActForOrg(user, organizationId);

  const coverage = await findSecurityCoverageById(context, user, coverageId);
  const existingResults = coverage.coverage_information || [];

  // Get org name for denormalization
  const org = await storeLoadById(context, user, organizationId);

  // Upsert: replace results for this org, keep others
  const newOrgResult = {
    organization_id: organizationId,
    organization_name: org.name,
    last_result: new Date().toISOString(),
    auto_enrichment: autoEnrichment ?? false,
    results,
  };

  const updatedResults = [
    ...existingResults.filter(r => r.organization_id !== organizationId),
    newOrgResult,
  ];

  return patchEntity(context, user, coverageId, {
    coverage_information: updatedResults,
  });
};
```

### 5.3 objectOrganization Auto-Population

When results are pushed for an org, that org is automatically added to `objectOrganization` so the coverage becomes visible to that org's users:

```typescript
// After pushing results, ensure the org can see the coverage
await addOrganizationRestriction(context, user, coverageId, organizationId);
```

---

## 6. Frontend UX

### 6.1 Entity Detail Page — Single Org User

For a user in exactly one organization, the experience is simple:

```
┌─────────────────────────────────────────────────────┐
│  Intrusion Set: Scattered Spider                     │
│  ┌─────────────────────────────────────────────────┐ │
│  │ Security Coverage                                │ │
│  │                                                  │ │
│  │  Organization: Banque Alpha                      │ │
│  │                                                  │ │
│  │  Prevention:     ████████████████░░░░  72%       │ │
│  │  Detection:      █████████████████████ 85%       │ │
│  │  Vulnerabilities: █████████░░░░░░░░░░░ 45%       │ │
│  │                                                  │ │
│  │  Last result: Feb 15, 2026                       │ │
│  │  Mode: Automated (OpenAEV)                       │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

No org selector needed. Clean and familiar.

### 6.2 Entity Detail Page — Multi-Org User

For a user with access to multiple organizations:

```
┌─────────────────────────────────────────────────────┐
│  Intrusion Set: Scattered Spider                     │
│  ┌─────────────────────────────────────────────────┐ │
│  │ Security Coverage                                │ │
│  │                                                  │ │
│  │  Organization: [ Banque Alpha      ▼ ]           │ │
│  │                  ┌──────────────────┐            │ │
│  │                  │ Banque Alpha   ✓ │            │ │
│  │                  │ Hopital Beta     │            │ │
│  │                  │ MSSP Platform    │            │ │
│  │                  └──────────────────┘            │ │
│  │                                                  │ │
│  │  Prevention:     ████████████████░░░░  72%       │ │
│  │  Detection:      █████████████████████ 85%       │ │
│  │  Vulnerabilities: █████████░░░░░░░░░░░ 45%       │ │
│  │                                                  │ │
│  │  Last result: Feb 15, 2026                       │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

Selecting another org switches the displayed results instantly (no page reload — same entity, different result set).

### 6.3 MSSP Aggregated View

For platform org users, an additional **"Compare"** toggle shows all orgs side by side:

```
┌─────────────────────────────────────────────────────┐
│  Intrusion Set: Scattered Spider                     │
│  ┌─────────────────────────────────────────────────┐ │
│  │ Security Coverage              [Single | Compare]│ │
│  │                                                  │ │
│  │  Metric          Banque A  Hôpital B  MSSP Ref   │ │
│  │  ───────────────────────────────────────────────  │ │
│  │  Prevention        72%       38%        60%      │ │
│  │  Detection         85%       52%        70%      │ │
│  │  Vulnerabilities   45%       67%        55%      │ │
│  │  ───────────────────────────────────────────────  │ │
│  │  Last result     Feb 15    Feb 10     Feb 18     │ │
│  │  Mode             Auto      Auto      Manual     │ │
│  │                                                  │ │
│  │  Avg Prevention: 57%  |  Min: 38%  |  Max: 72%  │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### 6.4 Coverage Creation / Adding Org Results

When a SecurityCoverage doesn't exist yet for an entity:
- **"Create Security Coverage"** button creates the coverage and pushes initial results for the user's org

When a SecurityCoverage already exists but the user's org has no results:
- **"Add my organization's assessment"** button pushes results for their org into the existing coverage

When the user's org already has results:
- **"Update results"** or automated enrichment via OpenAEV

---

## 7. OpenAEV Connector Integration

### 7.1 Updated Flow

```
┌──────────────────────────────────────────────────────┐
│                   OpenCTI Platform                    │
│                                                      │
│    SecurityCoverage (APT29)                           │
│    ├─ Banque Alpha results    ◄── OpenAEV Connector A │
│    ├─ Hôpital Beta results    ◄── OpenAEV Connector B │
│    └─ MSSP Platform results   ◄── Manual / Ref        │
│                                                      │
└──────────────────────────────────────────────────────┘
```

Each OpenAEV connector:
1. Receives the SecurityCoverage entity + covered entity STIX bundle
2. Runs its assessment against its own org's security stack
3. Pushes results via `securityCoveragePushResults(id, organizationId, results)`
4. Only its org's results are updated — other orgs' results are untouched

### 7.2 Connector Routing

The connector's service account org determines which org's results it can push:

```typescript
// Connector enrichment handler
const handleEnrichment = async (coverageId, connectorUser) => {
  const connectorOrgId = connectorUser.organizations[0]?.internal_id;
  // Run OpenAEV assessment...
  const results = await runAssessment(coverageId);
  // Push results for the connector's org only
  await securityCoveragePushResults(context, connectorUser, coverageId, connectorOrgId, results);
};
```

---

## 8. Access Control

| Scenario | Behavior |
|----------|----------|
| Single-org user views coverage | Sees only their org's results + platform org results |
| Multi-org user views coverage | Sees all their orgs' results, can switch between them |
| Platform org user views coverage | Sees all org results, can compare |
| User pushes results | Can only push for their own org(s) |
| Connector pushes results | Can only push for its service account's org |
| No org segregation enabled | All results visible, org selector hidden |

### 8.1 objectOrganization Management

The `objectOrganization` field on the SecurityCoverage entity is automatically maintained:
- When org A pushes results → org A is added to `objectOrganization`
- When org A's results are removed → org A is removed from `objectOrganization`
- This ensures the standard org segregation middleware handles visibility correctly

---

## 9. Migration from v1

### 9.1 If v1 Was Deployed (multiple SecurityCoverage entities per covered entity)

```javascript
// Migration: merge N coverage entities into 1 per covered entity
const migration = async () => {
  // Group coverages by covered entity
  const coveragesByEntity = groupBy(allCoverages, c => c.objectCovered.id);

  for (const [coveredId, coverages] of Object.entries(coveragesByEntity)) {
    if (coverages.length <= 1) continue; // already single

    // Keep the first one as the canonical entity
    const canonical = coverages[0];

    // Merge all org results into the canonical entity
    const mergedResults = coverages.map(c => ({
      organization_id: c.coverageOrganization?.id,
      organization_name: c.coverageOrganization?.name,
      last_result: c.coverage_last_result,
      auto_enrichment: !c.auto_enrichment_disable,
      results: c.coverage_information,
    }));

    // Update canonical with merged results
    await patchEntity(canonical.id, { coverage_information: mergedResults });

    // Delete the duplicates
    for (const dup of coverages.slice(1)) {
      await deleteEntity(dup.id);
    }
  }
};
```

### 9.2 From v0 (original single coverage, no org)

```javascript
// Existing coverage_information stays as-is but wrapped in platform org context
const migration = async () => {
  const platformOrgId = await getPlatformOrgId();

  for (const coverage of allCoverages) {
    const wrappedResults = [{
      organization_id: platformOrgId,
      organization_name: "Platform",
      last_result: coverage.coverage_last_result,
      auto_enrichment: !coverage.auto_enrichment_disable,
      results: coverage.coverage_information, // existing scores
    }];

    await patchEntity(coverage.id, { coverage_information: wrappedResults });
  }
};
```

---

## 10. Implementation Phases

### Phase 1: Data Model
- [ ] Restructure `coverage_information` to org-scoped format
- [ ] Remove `coverageOrganization` ref (no longer needed as separate relation)
- [ ] Revert identifier to `objectCovered` only
- [ ] Add `OrganizationCoverageResult` GraphQL type
- [ ] Add `myCoverageResult` resolver
- [ ] Write migration

### Phase 2: Backend Mutations
- [ ] Implement `securityCoveragePushResults` mutation
- [ ] Implement `securityCoverageRemoveOrgResults` mutation
- [ ] Add resolver-level filtering of `coverage_information` by user org
- [ ] Auto-manage `objectOrganization` based on which orgs have results

### Phase 3: Frontend — Core UX
- [ ] Coverage panel on entity detail pages (IntrusionSet, Campaign, Incident, etc.)
- [ ] Single-org view (no selector needed)
- [ ] Multi-org view with org selector dropdown
- [ ] "Add my organization's assessment" button
- [ ] "Create Security Coverage" button for entities without one

### Phase 4: Frontend — MSSP View
- [ ] Compare toggle for platform org users
- [ ] Side-by-side org comparison table
- [ ] Aggregate metrics (avg, min, max across orgs)
- [ ] Coverage list view with org filter column

### Phase 5: Connector Protocol
- [ ] Update OpenAEV connector to use `securityCoveragePushResults`
- [ ] Connector-to-org routing based on service account
- [ ] STIX bundle includes org context

---

## 11. Open Questions

1. **Should platform org reference results be visible to all orgs?** Proposal: yes, platform org results serve as a baseline reference that all orgs can compare against.

2. **Max orgs per coverage?** No hard limit — the `coverage_information` array grows with orgs. For very large MSSP deployments (100+ orgs), consider pagination within the results.

3. **Historical results?** Current design only keeps the latest result per org. Should we keep a history? If yes, `results` becomes `[{ timestamp, scores }]`.

4. **Notification when another org adds results?** Platform org users might want to be notified when a new org pushes results. This could be a trigger/notification.
