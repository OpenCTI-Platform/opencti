import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { connector as loadConnector, connectorDelete, registerConnector } from '../../../src/modules/connector/connector-domain';
import { createWork, deleteWork, loadWorkById, reportExpectation, updateExpectationsNumber, updateProcessedTime } from '../../../src/domain/work';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { deleteElementById, patchAttribute } from '../../../src/database/middleware';
import { redisGetWorkTouchedElements, redisUpdateWorkFigures } from '../../../src/database/redis';
import { resetCacheForEntity } from '../../../src/database/cache';
import { closeOldWorks } from '../../../src/manager/connectorManager';
import { addDraftWorkspace, deleteDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ConnectorType } from '../../../src/generated/graphql';

const ENRICHMENT_CONNECTOR_ID = 'bb6d8f3a-1b2c-4d5e-8f90-111111111111';
const IMPORT_CONNECTOR_ID = 'bb6d8f3a-1b2c-4d5e-8f90-333333333333';

// Shared by every describe of this file: run the file as a whole
let enrichment: any;
let importConnector: any;
const intrusionSetIds: string[] = [];
const workIds: string[] = [];

beforeAll(async () => {
  await registerConnector(testContext, ADMIN_USER, { id: ENRICHMENT_CONNECTOR_ID, name: 'Completion enrichment', type: ConnectorType.InternalEnrichment, scope: [ENTITY_TYPE_INTRUSION_SET], auto: false }, { active: true });
  await registerConnector(testContext, ADMIN_USER, { id: IMPORT_CONNECTOR_ID, name: 'Completion import', type: ConnectorType.ExternalImport, scope: [] }, { active: true });
  resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  enrichment = await loadConnector(testContext, ADMIN_USER, ENRICHMENT_CONNECTOR_ID);
  importConnector = await loadConnector(testContext, ADMIN_USER, IMPORT_CONNECTOR_ID);
});

afterAll(async () => {
  for (const id of workIds) {
    await deleteWork(testContext, ADMIN_USER, id).catch(() => {});
  }
  for (const id of intrusionSetIds) {
    await deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_INTRUSION_SET);
  }
  await connectorDelete(testContext, ADMIN_USER, ENRICHMENT_CONNECTOR_ID);
  await connectorDelete(testContext, ADMIN_USER, IMPORT_CONNECTOR_ID);
  resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
});

/**
 * Creates a work and fails the test when the work cannot be created.
 */
const startWork = async (connectorEntity: any, name: string, sourceId: string, options: Record<string, unknown> = {}) => {
  const work = await createWork(testContext, ADMIN_USER, connectorEntity, name, sourceId, options);
  if (!work) {
    throw new Error('Work creation failed');
  }
  workIds.push(work.id);
  return work;
};

describe('Work completion with touched elements', () => {
  /**
   * Starts a work, performs one creation and one update under it, and declares one expectation.
   */
  const runEnrichment = async (connectorEntity: any, extraContext: Record<string, unknown> = {}) => {
    const target = await addIntrusionSet(testContext, ADMIN_USER, { name: `Completion target ${Date.now()}` });
    intrusionSetIds.push(target.id);
    const work = await startWork(connectorEntity, 'Manual enrichment', target.standard_id);
    const workerContext = { ...testContext, workId: work.id, ...extraContext };
    const created = await addIntrusionSet(workerContext, ADMIN_USER, { name: `Completion created ${Date.now()}` });
    intrusionSetIds.push(created.id);
    await patchAttribute(workerContext, ADMIN_USER, target.id, ENTITY_TYPE_INTRUSION_SET, { description: 'enriched' });
    await updateExpectationsNumber(testContext, ADMIN_USER, work.id, 1);
    return { work, target, created };
  };

  it('should persist touched ids when the worker completes the work', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
    expect((await redisGetWorkTouchedElements(work.id)).touched_ids).toEqual([]);
  });

  it('should persist touched ids when the connector completes the work', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await redisUpdateWorkFigures(work.id); // the worker processed the single expectation
    await updateProcessedTime(testContext, ADMIN_USER, work.id, 'done');
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
    expect((await redisGetWorkTouchedElements(work.id)).touched_ids).toEqual([]);
  });

  it('should keep the ids when completion is processed a second time', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    await updateProcessedTime(testContext, ADMIN_USER, work.id, 'late connector message');
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
  });

  it('should add the ids written after an early completion when the work completes again', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    // The first completion deleted the Redis set, so the late write rebuilds it
    expect((await redisGetWorkTouchedElements(work.id)).touched_ids).toEqual([]);
    const late = await addIntrusionSet({ ...testContext, workId: work.id }, ADMIN_USER, { name: `Completion late ${Date.now()}` });
    intrusionSetIds.push(late.id);
    await updateProcessedTime(testContext, ADMIN_USER, work.id, 'late connector message');
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id, late.id].sort());
  });

  it('should persist touched ids when an old work is force-closed', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    const newer = await startWork(enrichment, 'Manual enrichment', 'newer');
    await redisUpdateWorkFigures(newer.id); // marks the newer work as the connector status
    await closeOldWorks(testContext, enrichment);
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
    expect((await redisGetWorkTouchedElements(work.id)).touched_ids).toEqual([]);
  });

  it('should not record ids for a non enrichment work', async () => {
    const { work } = await runEnrichment(importConnector);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect(completed.touched_ids).toBeUndefined();
  });

  it('should record ids of an enrichment run inside a draft', async () => {
    const draft = await addDraftWorkspace(testContext, ADMIN_USER, { name: `Enrichment draft ${Date.now()}` });
    const target = await addIntrusionSet(testContext, ADMIN_USER, { name: `Draft target ${Date.now()}` });
    intrusionSetIds.push(target.id);
    const work = await startWork(enrichment, 'Manual enrichment in draft', target.standard_id, { draftContext: draft.id });
    const draftWorkerContext = { ...testContext, workId: work.id, draft_context: draft.id };
    const created = await addIntrusionSet(draftWorkerContext, ADMIN_USER, { name: `Draft created ${Date.now()}` });
    await updateExpectationsNumber(testContext, ADMIN_USER, work.id, 1);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.touched_ids).toEqual([created.id]);
    expect(completed.draft_context).toEqual(draft.id);
    await deleteDraftWorkspace(testContext, ADMIN_USER, draft.id);
  });
});

const TLP_RED = 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed';

const JOBS_QUERY = `
  query WorkTouchedJobs($id: String!) {
    stixCoreObject(id: $id) {
      jobs(first: 20) {
        id
        touchedElements { ... on BasicObject { id entity_type } }
      }
    }
  }
`;

describe('Work touched elements in GraphQL', () => {
  it('should expose touched elements filtered by the reader rights', async () => {
    const target = await addIntrusionSet(testContext, ADMIN_USER, { name: `GraphQL target ${Date.now()}` });
    intrusionSetIds.push(target.id);
    const work = await startWork(enrichment, 'Manual enrichment', target.standard_id);
    const workerContext = { ...testContext, workId: work.id };
    const visible = await addIntrusionSet(workerContext, ADMIN_USER, { name: `GraphQL visible ${Date.now()}` });
    const hidden = await addIntrusionSet(workerContext, ADMIN_USER, { name: `GraphQL hidden ${Date.now()}`, objectMarking: [TLP_RED] });
    intrusionSetIds.push(visible.id, hidden.id);
    await updateExpectationsNumber(testContext, ADMIN_USER, work.id, 1);
    await reportExpectation(testContext, ADMIN_USER, work.id);

    const asAdmin = await queryAsAdminWithSuccess({ query: JOBS_QUERY, variables: { id: target.id } });
    const adminJob = asAdmin.data?.stixCoreObject.jobs.find((j: any) => j.id === work.id);
    expect(adminJob.touchedElements.map((e: any) => e.id).sort()).toEqual([visible.id, hidden.id].sort());

    const asEditor = await queryAsUserWithSuccess(USER_EDITOR, { query: JOBS_QUERY, variables: { id: target.id } });
    const editorJob = asEditor.data?.stixCoreObject.jobs.find((j: any) => j.id === work.id);
    expect(editorJob.touchedElements.map((e: any) => e.id)).toEqual([visible.id]);
  });

  it('should return null touched elements when they were never recorded', async () => {
    const target = await addIntrusionSet(testContext, ADMIN_USER, { name: `Import target ${Date.now()}` });
    intrusionSetIds.push(target.id);
    const work = await startWork(importConnector, 'Import', target.standard_id);
    const created = await addIntrusionSet({ ...testContext, workId: work.id }, ADMIN_USER, { name: `Import created ${Date.now()}` });
    intrusionSetIds.push(created.id);
    await updateExpectationsNumber(testContext, ADMIN_USER, work.id, 1);
    await reportExpectation(testContext, ADMIN_USER, work.id);

    const result = await queryAsAdminWithSuccess({ query: JOBS_QUERY, variables: { id: target.id } });
    const job = result.data?.stixCoreObject.jobs.find((j: any) => j.id === work.id);
    expect(job.touchedElements).toBeNull();
  });

  it('should skip deleted elements', async () => {
    const target = await addIntrusionSet(testContext, ADMIN_USER, { name: `Deleted target ${Date.now()}` });
    intrusionSetIds.push(target.id);
    const work = await startWork(enrichment, 'Manual enrichment', target.standard_id);
    const created = await addIntrusionSet({ ...testContext, workId: work.id }, ADMIN_USER, { name: `Deleted created ${Date.now()}` });
    await updateExpectationsNumber(testContext, ADMIN_USER, work.id, 1);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    await deleteElementById(testContext, ADMIN_USER, created.id, ENTITY_TYPE_INTRUSION_SET);

    const result = await queryAsAdminWithSuccess({ query: JOBS_QUERY, variables: { id: target.id } });
    const job = result.data?.stixCoreObject.jobs.find((j: any) => j.id === work.id);
    expect(job.touchedElements).toEqual([]);
  });
});
