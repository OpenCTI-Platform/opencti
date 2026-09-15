import { afterAll, describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { elDelete, elFindByIds, elIndex } from '../../../src/database/engine';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../../../src/database/utils';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

// Reproduces, with real ES calls, the payload behavior investigated for the recurring
// "SaaS/ES Circuit Breaker" alert: elLoadById (used by internalLoadById / storeLoadById,
// the platform's default single-entity loader, ~86 call sites) forces `withoutRels: false`,
// so it always returns the full, unbounded `rel_*` denormalization for the entity, no matter
// how many relationships it has. elFindByIds (default `withoutRels: true`) instead excludes
// `rel_*` from `_source` entirely and only fetches a small, curated, bounded set of security/
// business-critical rel types via `docvalue_fields` (see REL_DEFAULT_FETCH in engine.ts).
// This test proves the size gap is real and grows linearly with the number of denormalized
// relationships, with no cap, on a document that mimics a heavily-referenced Report.
describe('elLoadById unbounded rel_* payload vs elFindByIds default exclusion', () => {
  const reportId = uuidv4();
  const RELATION_COUNT = 5000;

  afterAll(async () => {
    await elDelete(INDEX_STIX_DOMAIN_OBJECTS, reportId).catch(() => {});
  });

  it('elLoadById should return a payload that grows with relationship count, while elFindByIds does not', async () => {
    const relIndicatesIds = Array.from({ length: RELATION_COUNT }, () => uuidv4());
    const doc = {
      entity_type: ENTITY_TYPE_CONTAINER_REPORT,
      parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container', ENTITY_TYPE_CONTAINER_REPORT],
      base_type: 'ENTITY',
      internal_id: reportId,
      standard_id: `report--${uuidv4()}`,
      name: 'Heavily-referenced report (test fixture)',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      // Denormalized relationship references, same shape as production `rel_indicates.internal_id`
      'rel_indicates.internal_id': relIndicatesIds,
    };

    await elIndex(INDEX_STIX_DOMAIN_OBJECTS, doc);

    const viaElLoadById = await internalLoadById(testContext, ADMIN_USER, reportId);
    const viaElFindByIds = (await elFindByIds(testContext, ADMIN_USER, reportId) as any[])[0];

    const elLoadByIdSize = JSON.stringify(viaElLoadById).length;
    const elFindByIdsSize = JSON.stringify(viaElFindByIds).length;

    // The unbounded rel_* array must be present via elLoadById...
    expect((viaElLoadById as any)['rel_indicates.internal_id']).toHaveLength(RELATION_COUNT);
    // ...and absent via elFindByIds's default field exclusion.
    expect((viaElFindByIds as any)['rel_indicates.internal_id']).toBeUndefined();

    // The gap is not marginal: it scales with relationship count, uncapped.
    expect(elLoadByIdSize).toBeGreaterThan(elFindByIdsSize * 10);
  });
});
