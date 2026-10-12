import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { connectorDelete, registerConnector } from '../../../src/domain/connector';
import { connector as loadConnector } from '../../../src/database/repository';
import { createWork, deleteWork } from '../../../src/domain/work';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { addLabel } from '../../../src/domain/label';
import { stixDomainObjectAddRelation } from '../../../src/domain/stixDomainObject';
import { createRelation, deleteElementById, patchAttribute } from '../../../src/database/middleware';
import { redisGetWorkTouchedElements } from '../../../src/database/redis';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { ConnectorType } from '../../../src/generated/graphql';

const ENRICHMENT_CONNECTOR_ID = 'aa6d8f3a-1b2c-4d5e-8f90-111111111111';
const OTHER_ENRICHMENT_CONNECTOR_ID = 'aa6d8f3a-1b2c-4d5e-8f90-222222222222';
const IMPORT_CONNECTOR_ID = 'aa6d8f3a-1b2c-4d5e-8f90-333333333333';

describe('Work touched elements tracking', () => {
  let enrichment: any;
  let otherEnrichment: any;
  let importConnector: any;
  // Cleaned up in afterAll, so that a failing assertion does not leak data into later test files
  const createdElements: { id: string; type: string }[] = [];
  const createdWorkIds: string[] = [];

  beforeAll(async () => {
    await registerConnector(testContext, ADMIN_USER, { id: ENRICHMENT_CONNECTOR_ID, name: 'Touched enrichment A', type: ConnectorType.InternalEnrichment, scope: [ENTITY_TYPE_INTRUSION_SET], auto: false }, { active: true });
    await registerConnector(testContext, ADMIN_USER, { id: OTHER_ENRICHMENT_CONNECTOR_ID, name: 'Touched enrichment B', type: ConnectorType.InternalEnrichment, scope: [ENTITY_TYPE_INTRUSION_SET], auto: false }, { active: true });
    await registerConnector(testContext, ADMIN_USER, { id: IMPORT_CONNECTOR_ID, name: 'Touched import', type: ConnectorType.ExternalImport, scope: [] }, { active: true });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    enrichment = await loadConnector(testContext, ADMIN_USER, ENRICHMENT_CONNECTOR_ID);
    otherEnrichment = await loadConnector(testContext, ADMIN_USER, OTHER_ENRICHMENT_CONNECTOR_ID);
    importConnector = await loadConnector(testContext, ADMIN_USER, IMPORT_CONNECTOR_ID);
  });

  afterAll(async () => {
    for (const workId of createdWorkIds) {
      await deleteWork(testContext, ADMIN_USER, workId);
    }
    for (const { id, type } of createdElements) {
      await deleteElementById(testContext, ADMIN_USER, id, type);
    }
    await connectorDelete(testContext, ADMIN_USER, ENRICHMENT_CONNECTOR_ID);
    await connectorDelete(testContext, ADMIN_USER, OTHER_ENRICHMENT_CONNECTOR_ID);
    await connectorDelete(testContext, ADMIN_USER, IMPORT_CONNECTOR_ID);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  /** Create a work, register it for cleanup, and fail the test when it cannot be loaded. */
  const startWork = async (connector: any, sourceId: string) => {
    const work = await createWork(testContext, ADMIN_USER, connector, 'Manual enrichment', sourceId);
    expect(work).toBeDefined();
    createdWorkIds.push((work as { id: string }).id);
    return work as { id: string };
  };

  /** Create an intrusion set with a unique name, and register it for cleanup. */
  const newIntrusionSet = async (context: any, name: string) => {
    const created = await addIntrusionSet(context, ADMIN_USER, { name: `${name} ${Date.now()}` });
    createdElements.push({ id: created.id, type: ENTITY_TYPE_INTRUSION_SET });
    return created;
  };

  it('should record created, updated, ref-changed and related elements of an enrichment work in one list', async () => {
    const existing = await newIntrusionSet(testContext, 'Touched existing');
    const unchanged = await newIntrusionSet(testContext, 'Touched unchanged');
    const work = await startWork(enrichment, existing.standard_id);
    const workerContext = { ...testContext, workId: work.id };

    const created = await newIntrusionSet(workerContext, 'Touched created');
    await patchAttribute(workerContext, ADMIN_USER, existing.id, ENTITY_TYPE_INTRUSION_SET, { description: 'enriched' });
    // Created then updated in the same work: listed once
    await patchAttribute(workerContext, ADMIN_USER, created.id, ENTITY_TYPE_INTRUSION_SET, { description: 'enriched' });
    const label = await addLabel(testContext, ADMIN_USER, { value: `touched-label-${Date.now()}` });
    createdElements.push({ id: label.id, type: ENTITY_TYPE_LABEL });
    const labelled = await newIntrusionSet(testContext, 'Touched labelled');
    await stixDomainObjectAddRelation(workerContext, ADMIN_USER, labelled.id, { toId: label.id, relationship_type: 'object-label' });
    const relation = await createRelation(workerContext, ADMIN_USER, { fromId: created.id, toId: existing.id, relationship_type: 'related-to' });
    // Upsert with identical data: no event, so not recorded
    await addIntrusionSet(workerContext, ADMIN_USER, { name: unchanged.name });

    const touched = await redisGetWorkTouchedElements(work.id);
    expect(touched.touched_ids.sort()).toEqual([created.id, existing.id, labelled.id, relation.id].sort());
    expect(touched.touched_ids).not.toContain(unchanged.id);
  });

  it('should not record anything for a non enrichment work', async () => {
    const work = await startWork(importConnector, 'source');
    await newIntrusionSet({ ...testContext, workId: work.id }, 'Touched by import');
    expect(await redisGetWorkTouchedElements(work.id)).toEqual({ touched_ids: [], touched_ids_truncated: false });
  });

  it('should keep concurrent works separate', async () => {
    const target = await newIntrusionSet(testContext, 'Touched concurrent');
    const workA = await startWork(enrichment, target.standard_id);
    const workB = await startWork(otherEnrichment, target.standard_id);
    const [fromA, fromB] = await Promise.all([
      newIntrusionSet({ ...testContext, workId: workA.id }, 'Touched by A'),
      newIntrusionSet({ ...testContext, workId: workB.id }, 'Touched by B'),
    ]);
    expect((await redisGetWorkTouchedElements(workA.id)).touched_ids).toEqual([fromA.id]);
    expect((await redisGetWorkTouchedElements(workB.id)).touched_ids).toEqual([fromB.id]);
  });

  it('should not fail when the work was deleted', async () => {
    const work = await startWork(enrichment, 'source');
    await deleteWork(testContext, ADMIN_USER, work.id);
    await expect(newIntrusionSet({ ...testContext, workId: work.id }, 'Touched after delete')).resolves.toBeDefined();
  });
});
