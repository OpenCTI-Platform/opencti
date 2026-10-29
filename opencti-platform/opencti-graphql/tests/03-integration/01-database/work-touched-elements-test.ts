import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { connector as loadConnector, connectorDelete, registerConnector } from '../../../src/modules/connector/connector-domain';
import { createWork, deleteWork } from '../../../src/domain/work';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { addLabel } from '../../../src/domain/label';
import { addNote } from '../../../src/domain/note';
import { addReport } from '../../../src/domain/report';
import { stixDomainObjectAddRelation } from '../../../src/domain/stixDomainObject';
import { createRelation, deleteElementById, patchAttribute } from '../../../src/database/middleware';
import { redisGetWorkTouchedElements } from '../../../src/database/redis';
import { internalFindByIds } from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { ConnectorType } from '../../../src/generated/graphql';

const ENRICHMENT_CONNECTOR_ID = 'aa6d8f3a-1b2c-4d5e-8f90-111111111111';
const OTHER_ENRICHMENT_CONNECTOR_ID = 'aa6d8f3a-1b2c-4d5e-8f90-222222222222';
const IMPORT_CONNECTOR_ID = 'aa6d8f3a-1b2c-4d5e-8f90-333333333333';
// Only the enrichments triggered from an investigation are tracked: the id is only stored, no workspace is needed
const INVESTIGATION_ID = 'investigation-touched-test';

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

  /** Create a work of the investigation unless told otherwise, register it for cleanup, and fail the test when it cannot be loaded. */
  const startWork = async (
    connector: any,
    sourceId: string,
    {
      investigationId = INVESTIGATION_ID,
      enrichedEntityId,
    }: { investigationId?: string | null; enrichedEntityId?: string } = {},
  ) => {
    const work = await createWork(testContext, ADMIN_USER, connector, 'Manual enrichment', sourceId, { investigationId, enrichedEntityId });
    expect(work).toBeDefined();
    createdWorkIds.push((work as { id: string }).id);
    return work as { id: string };
  };

  /** Create an intrusion set with a unique name, and register it for cleanup. */
  const newIntrusionSet = async (context: any, name: string, input = {}) => {
    const created = await addIntrusionSet(context, ADMIN_USER, { name: `${name} ${Date.now()}`, ...input });
    createdElements.push({ id: created.id, type: ENTITY_TYPE_INTRUSION_SET });
    return created;
  };

  /** Create a label with a unique value, and register it for cleanup. */
  const newLabel = async (value: string) => {
    const created = await addLabel(testContext, ADMIN_USER, { value: `${value}-${Date.now()}` });
    createdElements.push({ id: created.id, type: ENTITY_TYPE_LABEL });
    return created;
  };

  /** Describe the touched elements of a work: an entity by its id, a relationship by its type and ends. */
  const describeTouched = async (workId: string) => {
    const { touched_ids } = await redisGetWorkTouchedElements(workId);
    const elements = await internalFindByIds(testContext, ADMIN_USER, touched_ids) as any[];
    return elements
      .map((element) => (element.fromId ? `${element.entity_type} ${element.fromId} ${element.toId}` : element.id))
      .sort();
  };

  it('should record created, updated, ref-changed and related elements of an enrichment work in one list', async () => {
    const existing = await newIntrusionSet(testContext, 'Touched existing');
    const unchanged = await newIntrusionSet(testContext, 'Touched unchanged');
    const work = await startWork(enrichment, existing.standard_id, { enrichedEntityId: existing.id });
    const workerContext = { ...testContext, workId: work.id };

    const created = await newIntrusionSet(workerContext, 'Touched created');
    await patchAttribute(workerContext, ADMIN_USER, existing.id, ENTITY_TYPE_INTRUSION_SET, { description: 'enriched' });
    // Created then updated in the same work: listed once
    await patchAttribute(workerContext, ADMIN_USER, created.id, ENTITY_TYPE_INTRUSION_SET, { description: 'enriched' });
    const label = await newLabel('touched-label');
    // A ref of another entity than the enriched one: only that entity is recorded
    const labelled = await newIntrusionSet(testContext, 'Touched labelled');
    await stixDomainObjectAddRelation(workerContext, ADMIN_USER, labelled.id, { toId: label.id, relationship_type: 'object-label' });
    const relation = await createRelation(workerContext, ADMIN_USER, { fromId: created.id, toId: existing.id, relationship_type: 'related-to' });
    // Upsert with identical data: no event, so not recorded
    await addIntrusionSet(workerContext, ADMIN_USER, { name: unchanged.name });

    const touched = await redisGetWorkTouchedElements(work.id);
    expect(touched.touched_ids.sort()).toEqual([created.id, existing.id, labelled.id, relation.id].sort());
    expect(touched.touched_ids).not.toContain(unchanged.id);
  });

  it('should record the refs created on the enriched entity, and only those', async () => {
    const enriched = await newIntrusionSet(testContext, 'Touched enriched');
    const work = await startWork(enrichment, enriched.standard_id, { enrichedEntityId: enriched.id });
    const workerContext = { ...testContext, workId: work.id };
    const addedLabel = await newLabel('touched-added');
    const upsertedLabel = await newLabel('touched-upserted');

    // Ref created on its own, from the enriched entity
    await stixDomainObjectAddRelation(workerContext, ADMIN_USER, enriched.id, { toId: addedLabel.id, relationship_type: 'object-label' });
    // Ref added by an upsert of the enriched entity
    await addIntrusionSet(workerContext, ADMIN_USER, { name: enriched.name, objectLabel: [upsertedLabel.id] });
    // Ref created with a new entity, to the enriched entity
    const note = await addNote(workerContext, ADMIN_USER, { content: `touched note ${Date.now()}`, objects: [enriched.id] });
    createdElements.push({ id: note.id, type: ENTITY_TYPE_CONTAINER_NOTE });
    // Ref created with a new entity, to another entity: not recorded
    const other = await newIntrusionSet(workerContext, 'Touched other', { objectLabel: [addedLabel.id] });

    expect(await describeTouched(work.id)).toEqual([
      enriched.id,
      note.id,
      other.id,
      `object ${note.id} ${enriched.id}`,
      `object-label ${enriched.id} ${addedLabel.id}`,
      `object-label ${enriched.id} ${upsertedLabel.id}`,
    ].sort());
  });

  it('should not record the refs to users of the enriched entity', async () => {
    const report = await addReport(testContext, ADMIN_USER, { name: `Touched assigned ${Date.now()}`, published: '2026-01-01T00:00:00.000Z' });
    createdElements.push({ id: report.id, type: ENTITY_TYPE_CONTAINER_REPORT });
    const work = await startWork(enrichment, report.standard_id, { enrichedEntityId: report.id });

    await stixDomainObjectAddRelation({ ...testContext, workId: work.id }, ADMIN_USER, report.id, { toId: ADMIN_USER.id, relationship_type: 'object-assignee' });

    expect(await describeTouched(work.id)).toEqual([report.id]);
  });

  it('should not record anything for a non enrichment work', async () => {
    const work = await startWork(importConnector, 'source');
    await newIntrusionSet({ ...testContext, workId: work.id }, 'Touched by import');
    expect(await redisGetWorkTouchedElements(work.id)).toEqual({ touched_ids: [] });
  });

  it('should not record anything for an enrichment work outside an investigation', async () => {
    const work = await startWork(enrichment, 'source', { investigationId: null });
    await newIntrusionSet({ ...testContext, workId: work.id }, 'Touched outside investigation');
    expect(await redisGetWorkTouchedElements(work.id)).toEqual({ touched_ids: [] });
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
