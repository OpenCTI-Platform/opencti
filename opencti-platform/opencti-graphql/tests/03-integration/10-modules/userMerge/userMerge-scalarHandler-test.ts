import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { elIndex, elRawDeleteByQuery, elRawGet } from '../../../../src/database/engine';
import * as cache from '../../../../src/database/cache';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../../../src/database/utils';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeScalarHandler, USER_MERGE_SCALAR_HANDLER } from '../../../../src/modules/userMerge/userMerge-scalarHandler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';
import type { AuthUser } from '../../../../src/types/user';

const SOURCE_ID = 'user--merge-source-0000-0000-000000000001';
const TARGET_ID = 'user--merge-target-0000-0000-000000000002';
const OTHER_ID = 'user--merge-other-0000-0000-0000000000003';

const TEST_DOCUMENT_IDS = [
  'merge-test-sync-1',
  'merge-test-sync-2',
  'merge-test-work-done',
  'merge-test-work-running',
  'merge-test-connector',
  'merge-test-creators',
];

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

const readDocument = async (internalId: string) => {
  const found = await elRawGet({ id: internalId, index: INDEX_INTERNAL_OBJECTS });
  return (found as { _source: Record<string, unknown> })._source;
};

const changeFor = (report: { handlers: { handler: string; changes: { register_row_id: string; count: number }[] }[] } | undefined, rowId: string) => {
  const handler = report?.handlers.find((entry) => entry.handler === USER_MERGE_SCALAR_HANDLER);
  return handler?.changes.find((change) => change.register_row_id === rowId);
};

let registeredHandlers: UserMergeHandler[];

describe('userMerge scalar handler', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeScalarHandler);
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map<string, AuthUser>([
      [SOURCE_ID, { id: SOURCE_ID, allowed_marking: [], organizations: [], groups: [], capabilities: [] } as unknown as AuthUser],
      [TARGET_ID, { id: TARGET_ID, allowed_marking: [], organizations: [], groups: [], capabilities: [] } as unknown as AuthUser],
    ]));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-sync-1', 'Sync', { user_id: SOURCE_ID }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-sync-2', 'Sync', { user_id: OTHER_ID }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-work-done', 'work', { user_id: SOURCE_ID, status: 'complete' }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-work-running', 'work', { user_id: SOURCE_ID, status: 'progress' }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-connector', 'Connector', { connector_user_id: SOURCE_ID }));
    await elIndex(INDEX_INTERNAL_OBJECTS, document('merge-test-creators', 'Sync', { user_id: OTHER_ID, creator_id: [SOURCE_ID, OTHER_ID] }));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    await elRawDeleteByQuery({
      index: READ_INDEX_INTERNAL_OBJECTS,
      refresh: true,
      body: { query: { ids: { values: TEST_DOCUMENT_IDS } } },
    });
  });

  it('should count what it would rewrite without writing anything', async () => {
    const result = await merge(true);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(changeFor(result.report, 'sync.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'work-terminal.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'work-active.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'connector.user-id')?.count).toEqual(1);
    expect(changeFor(result.report, 'basic-object.creator-id')?.count).toEqual(1);
    expect(result.report?.total_updated).toEqual(0);
    const untouched = await readDocument('merge-test-sync-1') as { user_id: string };
    expect(untouched.user_id).toEqual(SOURCE_ID);
  });

  it('should report a target left running as an alert rather than a failure', async () => {
    const result = await merge(true);
    const handler = result.report?.handlers.find((entry) => entry.handler === USER_MERGE_SCALAR_HANDLER);
    const alertRows = handler?.alerts.map((alert) => alert.register_row_id);
    expect(alertRows).toContain('work-active.user-id');
  });

  it('should rewrite every matched reference', async () => {
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.total_updated).toEqual(5);
    const sync = await readDocument('merge-test-sync-1') as { user_id: string };
    const workDone = await readDocument('merge-test-work-done') as { user_id: string };
    const workRunning = await readDocument('merge-test-work-running') as { user_id: string };
    const connector = await readDocument('merge-test-connector') as { connector_user_id: string };
    expect(sync.user_id).toEqual(TARGET_ID);
    expect(workDone.user_id).toEqual(TARGET_ID);
    expect(workRunning.user_id).toEqual(TARGET_ID);
    expect(connector.connector_user_id).toEqual(TARGET_ID);
  });

  it('should leave documents referencing another user alone', async () => {
    const other = await readDocument('merge-test-sync-2') as { user_id: string };
    expect(other.user_id).toEqual(OTHER_ID);
  });

  it('should replace rather than append on a multiple field', async () => {
    const creators = await readDocument('merge-test-creators') as { creator_id: string[] };
    expect(creators.creator_id.sort()).toEqual([OTHER_ID, TARGET_ID].sort());
  });

  it('should be a no-op when replayed', async () => {
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.total_updated).toEqual(0);
    const creators = await readDocument('merge-test-creators') as { creator_id: string[] };
    expect(creators.creator_id.sort()).toEqual([OTHER_ID, TARGET_ID].sort());
  });
});
