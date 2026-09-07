import { describe, it, expect, vi } from 'vitest';

// ── Infrastructure stubs ─────────────────────────────────────────────────────
// buildRestrictedEntity is a pure function, but middleware.ts pulls in a lot of
// infrastructure at import time. Reuse the same stubs as the sibling
// middleware-distribution-unit-test.ts to keep the import graph lightweight.

vi.mock('../../../src/database/engine');
vi.mock('../../../src/database/redis', () => ({ notify: vi.fn(), redisAddDeletions: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../src/database/stream/stream-handler', () => ({
  storeCreateEntityEvent: vi.fn(),
  storeCreateRelationEvent: vi.fn(),
  storeDeleteEvent: vi.fn(),
  storeMergeEvent: vi.fn(),
  storeUpdateEvent: vi.fn(),
}));
vi.mock('../../../src/database/file-search', () => ({
  elUpdateRemovedFiles: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...(actual as object),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
    extendedErrors: false,
    BUS_TOPICS: {},
  };
});

// ── Imports (after mocks) ────────────────────────────────────────────────────

import { buildRestrictedEntity } from '../../../src/database/middleware';

// ── Reproduction of GitHub issue #18026 ──────────────────────────────────────
// https://github.com/OpenCTI-Platform/opencti/issues/18026
//
// When a Sector's created_by_ref (author Organization) is TLP-restricted for the
// requesting user, pycti's get_stix_bundle_or_object_from_entity_id produces an
// invalid STIX 2.1 bundle: the redacted author identity has id: "Restricted"
// instead of a valid `identity--<uuid>` STIX id.
//
// The GraphQL "createdBy" resolver (batchInternalRels in
// src/domain/stixCoreObject.js) returns buildRestrictedEntity(resolve) whenever
// the user cannot access the author entity. pycti later maps this entity's
// GraphQL "standard_id" field directly into the exported STIX object's "id"
// (and into created_by_ref on the child entity), so standard_id must remain a
// valid STIX identifier on the restricted entity.

describe('buildRestrictedEntity (issue #18026)', () => {
  const restrictedOrganization = {
    id: '79d14387-751e-4608-9807-2e8ed9c8711b',
    internal_id: '79d14387-751e-4608-9807-2e8ed9c8711b',
    standard_id: 'identity--d4551de9-4b9c-570e-a51c-d3c321eb9a8d',
    entity_type: 'Organization',
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
    name: 'Restricted Corp',
    description: 'A TLP-restricted organization',
    x_opencti_organization_type: 'vendor',
    representative: { main: 'Restricted Corp', secondary: '' },
  };

  it('keeps a valid STIX standard_id on the restricted entity', () => {
    const restricted = buildRestrictedEntity(restrictedOrganization as any);

    // This is the assertion that fails on the buggy implementation: standard_id
    // gets genericized to the literal string 'Restricted', which is not a valid
    // STIX 2.1 identifier and later ends up as created_by_ref / id in the bundle.
    expect(restricted.standard_id).toBe(restrictedOrganization.standard_id);
    expect(restricted.standard_id).toMatch(/^identity--[0-9a-f-]{36}$/);
  });

  it('still obfuscates sensitive attribute values', () => {
    const restricted = buildRestrictedEntity(restrictedOrganization as any);

    expect(restricted.name).toBe('Restricted');
    expect((restricted as any).description).toBe('Restricted');
    expect(restricted.representative).toEqual({ main: 'Restricted', secondary: 'Restricted' });
  });

  it('preserves identifying/queryable fields', () => {
    const restricted = buildRestrictedEntity(restrictedOrganization as any);

    expect(restricted.id).toBe(restrictedOrganization.internal_id);
    expect(restricted.entity_type).toBe(restrictedOrganization.entity_type);
    expect(restricted.parent_types).toEqual(restrictedOrganization.parent_types);
  });
});
