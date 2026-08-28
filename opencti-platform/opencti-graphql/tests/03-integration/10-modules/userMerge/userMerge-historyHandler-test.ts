import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { elIndex, elRawDeleteByQuery, elRawGet } from '../../../../src/database/engine';
import * as cache from '../../../../src/database/cache';
import { INDEX_HISTORY, INDEX_INTERNAL_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS } from '../../../../src/database/utils';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeHistoryHandler, USER_MERGE_HISTORY_HANDLER } from '../../../../src/modules/userMerge/userMerge-historyHandler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';
import type { AuthUser } from '../../../../src/types/user';

const SOURCE_ID = 'user--merge-history-source-0000-000000000001';
const TARGET_ID = 'user--merge-history-target-0000-000000000002';
const OTHER_ID = 'user--merge-history-other-0000-0000000000003';

const HISTORY_DOCUMENT_IDS = [
  'merge-test-history-user',
  'merge-test-history-applicant',
  'merge-test-history-creators',
  'merge-test-activity-user',
  'merge-test-pir-history-user',
];
const INTERNAL_DOCUMENT_IDS = ['merge-test-history-attributes', 'merge-test-workflow-instance', 'merge-test-workflow-mention'];

const document = (internalId: string, entityType: string, extra: Record<string, unknown>) => ({
  internal_id: internalId,
  standard_id: internalId,
  entity_type: entityType,
  parent_types: [],
  ...extra,
});

const merge = (dryRun: boolean) => executeUserMerge(
  {} as never,
  SOURCE_ID,
  TARGET_ID,
  { dryRun, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
);

const readDocument = async (internalId: string, index: string) => {
  const found = await elRawGet({ id: internalId, index });
  return (found as { _source: Record<string, unknown> })._source;
};

const changeFor = (
  report: { handlers: { handler: string; changes: { register_row_id: string; entity_type: string; count: number; exact: boolean }[] }[] } | undefined,
  rowId: string,
) => {
  const handler = report?.handlers.find((entry) => entry.handler === USER_MERGE_HISTORY_HANDLER);
  return handler?.changes.find((change) => change.register_row_id === rowId);
};

let registeredHandlers: UserMergeHandler[];

describe('userMerge history handler', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeHistoryHandler);
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map<string, AuthUser>([
      [SOURCE_ID, { id: SOURCE_ID, allowed_marking: [], organizations: [], groups: [], capabilities: [] } as unknown as AuthUser],
      [TARGET_ID, { id: TARGET_ID, allowed_marking: [], organizations: [], groups: [], capabilities: [] } as unknown as AuthUser],
    ]));
    await elIndex(INDEX_HISTORY, document('merge-test-history-user', 'History', { user_id: SOURCE_ID }));
    await elIndex(INDEX_HISTORY, document('merge-test-history-applicant', 'History', { user_id: OTHER_ID, applicant_id: SOURCE_ID }));
    await elIndex(INDEX_HISTORY, document('merge-test-history-creators', 'History', {
      user_id: OTHER_ID,
      context_data: { creator_ids: [SOURCE_ID, OTHER_ID] },
    }));
    await elIndex(INDEX_HISTORY, document('merge-test-activity-user', 'Activity', { user_id: SOURCE_ID }));
    await elIndex(INDEX_HISTORY, document('merge-test-pir-history-user', 'PirHistory', { user_id: SOURCE_ID }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-history-attributes', 'Sync', {
      user_id: OTHER_ID,
      i_attributes: [
        { name: 'description', user_id: SOURCE_ID },
        { name: 'name', user_id: OTHER_ID },
      ],
    }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-workflow-instance', 'WorkflowInstance', {
      currentState: 'review',
      history: JSON.stringify([
        { state: 'new', user_id: SOURCE_ID, timestamp: '2026-01-01T00:00:00.000Z', event: 'initialization' },
        { state: 'review', user_id: OTHER_ID, timestamp: '2026-01-02T00:00:00.000Z', event: 'transition', comment: SOURCE_ID },
      ]),
    }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-workflow-mention', 'WorkflowInstance', {
      currentState: 'new',
      history: JSON.stringify([
        { state: 'new', user_id: OTHER_ID, timestamp: '2026-01-01T00:00:00.000Z', event: 'initialization', comment: SOURCE_ID },
      ]),
    }));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    await elRawDeleteByQuery({
      index: READ_INDEX_HISTORY,
      refresh: true,
      body: { query: { ids: { values: HISTORY_DOCUMENT_IDS } } },
    });
    await elRawDeleteByQuery({
      index: READ_INDEX_INTERNAL_OBJECTS,
      refresh: true,
      body: { query: { ids: { values: INTERNAL_DOCUMENT_IDS } } },
    });
  });

  it('should count what it would rewrite without writing anything', async () => {
    const result = await merge(true);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(changeFor(result.report, 'history.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'activity.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'pir-history.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'activity-history-pir-history.applicant-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'history.context-data-attribution')?.count).toEqual(1);
    expect(changeFor(result.report, 'basic-object.i-attributes-user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'workflow-instance.history-user-id')?.count).toEqual(1);
    expect(result.report?.total_updated).toEqual(0);
    const untouched = await readDocument('merge-test-history-user', INDEX_HISTORY) as { user_id: string };
    expect(untouched.user_id).toEqual(SOURCE_ID);
  });

  it('should report every count as exact', async () => {
    const result = await merge(true);
    const handler = result.report?.handlers.find((entry) => entry.handler === USER_MERGE_HISTORY_HANDLER);
    expect(handler?.changes.every((change) => change.exact)).toBe(true);
  });

  it('should keep the user_id of one history type out of the others', async () => {
    const result = await merge(true);
    expect(changeFor(result.report, 'history.user-id')?.entity_type).toEqual('History');
    expect(changeFor(result.report, 'activity.user-id')?.entity_type).toEqual('Activity');
  });

  it('should rewrite every matched reference', async () => {
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.total_updated).toEqual(7);
    const history = await readDocument('merge-test-history-user', INDEX_HISTORY) as { user_id: string };
    const activity = await readDocument('merge-test-activity-user', INDEX_HISTORY) as { user_id: string };
    const pirHistory = await readDocument('merge-test-pir-history-user', INDEX_HISTORY) as { user_id: string };
    const applicant = await readDocument('merge-test-history-applicant', INDEX_HISTORY) as { user_id: string; applicant_id: string };
    expect(history.user_id).toEqual(TARGET_ID);
    expect(activity.user_id).toEqual(TARGET_ID);
    expect(pirHistory.user_id).toEqual(TARGET_ID);
    expect(applicant.applicant_id).toEqual(TARGET_ID);
    expect(applicant.user_id).toEqual(OTHER_ID);
  });

  it('should replace rather than append inside the context data', async () => {
    const creators = await readDocument('merge-test-history-creators', INDEX_HISTORY) as { context_data: { creator_ids: string[] } };
    expect(creators.context_data.creator_ids.sort()).toEqual([OTHER_ID, TARGET_ID].sort());
  });

  it('should rewrite only the attribute entries pointing at the source', async () => {
    const attributes = await readDocument('merge-test-history-attributes', INDEX_INTERNAL_OBJECTS) as {
      i_attributes: { name: string; user_id: string }[];
    };
    expect(attributes.i_attributes).toEqual([
      { name: 'description', user_id: TARGET_ID },
      { name: 'name', user_id: OTHER_ID },
    ]);
  });

  it('should rewrite the serialized workflow history without touching free text', async () => {
    const instance = await readDocument('merge-test-workflow-instance', INDEX_INTERNAL_OBJECTS) as { history: string };
    const entries = JSON.parse(instance.history) as { user_id: string; comment?: string }[];
    expect(entries.map((entry) => entry.user_id)).toEqual([TARGET_ID, OTHER_ID]);
    expect(entries[1].comment).toEqual(SOURCE_ID);
  });

  it('should leave a workflow history naming the source outside the attribution key alone', async () => {
    const instance = await readDocument('merge-test-workflow-mention', INDEX_INTERNAL_OBJECTS) as { history: string };
    const entries = JSON.parse(instance.history) as { user_id: string; comment?: string }[];
    expect(entries).toEqual([
      { state: 'new', user_id: OTHER_ID, timestamp: '2026-01-01T00:00:00.000Z', event: 'initialization', comment: SOURCE_ID },
    ]);
  });

  it('should be a no-op when replayed', async () => {
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.total_updated).toEqual(0);
    const creators = await readDocument('merge-test-history-creators', INDEX_HISTORY) as { context_data: { creator_ids: string[] } };
    expect(creators.context_data.creator_ids.sort()).toEqual([OTHER_ID, TARGET_ID].sort());
  });
});
