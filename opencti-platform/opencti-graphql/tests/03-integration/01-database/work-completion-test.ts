import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { connectorDelete, registerConnector } from '../../../src/domain/connector';
import { connector as loadConnector } from '../../../src/database/repository';
import { createWork, deleteWork, loadWorkById, reportExpectation, updateExpectationsNumber, updateProcessedTime } from '../../../src/domain/work';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { deleteElementById, patchAttribute } from '../../../src/database/middleware';
import { redisGetWorkTouchedElements, redisUpdateWorkFigures } from '../../../src/database/redis';
import { resetCacheForEntity } from '../../../src/database/cache';
import { closeOldWorks } from '../../../src/manager/connectorManager';
import { registerWorkCompletionHook, unregisterWorkCompletionHook } from '../../../src/domain/work-completion';
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
 * Waits for the given duration, to let non awaited completion hooks run.
 */
const sleep = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

describe('Work completion with touched elements', () => {
  afterEach(() => {
    unregisterWorkCompletionHook('test-completion-hook');
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
    expect(completed.touched_ids_truncated).toBe(false);
  });

  it('should persist touched ids when the connector completes the work', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await redisUpdateWorkFigures(work.id); // the worker processed the single expectation
    await updateProcessedTime(testContext, ADMIN_USER, work.id, 'done');
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
  });

  it('should keep the ids when completion is processed a second time', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    await vi.waitFor(async () => expect((await redisGetWorkTouchedElements(work.id)).touched_ids).toEqual([]));
    await updateProcessedTime(testContext, ADMIN_USER, work.id, 'late connector message');
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
  });

  it('should add the ids written after an early completion when the work completes again', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    // Wait for the completion dispatch to delete the Redis set, so the late write rebuilds it
    await vi.waitFor(async () => expect((await redisGetWorkTouchedElements(work.id)).touched_ids).toEqual([]));
    const late = await addIntrusionSet({ ...testContext, workId: work.id }, ADMIN_USER, { name: `Completion late ${Date.now()}` });
    intrusionSetIds.push(late.id);
    await updateProcessedTime(testContext, ADMIN_USER, work.id, 'late connector message');
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id, late.id].sort());
    expect(completed.touched_ids_truncated).toBe(false);
  });

  it('should persist touched ids when an old work is force-closed', async () => {
    const { work, target, created } = await runEnrichment(enrichment);
    const newer = await startWork(enrichment, 'Manual enrichment', 'newer');
    await redisUpdateWorkFigures(newer.id); // marks the newer work as the connector status
    await closeOldWorks(testContext, enrichment);
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect([...completed.touched_ids].sort()).toEqual([created.id, target.id].sort());
  });

  it('should run a registered hook exactly once even when two paths complete the work', async () => {
    const handler = vi.fn(async (..._args: any[]) => {});
    registerWorkCompletionHook({ id: 'test-completion-hook', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    const { work, created } = await runEnrichment(enrichment);
    await redisUpdateWorkFigures(work.id);
    await Promise.all([
      updateProcessedTime(testContext, ADMIN_USER, work.id, 'done'),
      updateProcessedTime(testContext, ADMIN_USER, work.id, 'done again'),
    ]);
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));
    await sleep(500);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0][1]).toMatchObject({ id: work.id });
    expect(handler.mock.calls[0][1].touched_ids).toContain(created.id);
  });

  it('should neither record ids nor run enrichment hooks for a non enrichment work', async () => {
    const handler = vi.fn(async () => {});
    registerWorkCompletionHook({ id: 'test-completion-hook', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    const { work } = await runEnrichment(importConnector);
    await reportExpectation(testContext, ADMIN_USER, work.id);
    const completed: any = await loadWorkById(testContext, ADMIN_USER, work.id);
    expect(completed.status).toEqual('complete');
    expect(completed.touched_ids).toBeUndefined();
    await sleep(500);
    expect(handler).not.toHaveBeenCalled();
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
