import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { elIndex, elRawDeleteByQuery, elRawGet } from '../../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addUser } from '../../../../src/modules/user/user-domain';
import { deleteMergeableUser } from './userMerge-testFixtures';
import { INDEX_HISTORY, READ_INDEX_HISTORY } from '../../../../src/database/utils';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeHistoryPayloadHandler } from '../../../../src/modules/userMerge/userMerge-historyPayloadHandler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const SOURCE_EMAIL = 'usermerge-payload-source@opencti.invalid';
const TARGET_EMAIL = 'usermerge-payload-target@opencti.invalid';
const OTHER_ID = 'user--merge-payload-other-0000-0000000000003';

/** Well before the merge: the handler only rewrites what predates the pair it runs on. */
const PAST = '2026-01-01T00:00:00.000Z';

let SOURCE_ID: string;
let TARGET_ID: string;

const CHANGES_DOCUMENT = 'merge-test-payload-changes';
const MEMBERS_CHANGE_DOCUMENT = 'merge-test-payload-members-change';
const FILTERS_CHANGE_DOCUMENT = 'merge-test-payload-filters-change';
const OTHER_CHANGE_DOCUMENT = 'merge-test-payload-other-change';
const RAW_PAYLOAD_DOCUMENT = 'merge-test-payload-raw';
const DOCUMENT_IDS = [CHANGES_DOCUMENT, MEMBERS_CHANGE_DOCUMENT, FILTERS_CHANGE_DOCUMENT, OTHER_CHANGE_DOCUMENT, RAW_PAYLOAD_DOCUMENT];

const document = (internalId: string, entityType: string, contextData: Record<string, unknown>) => ({
  internal_id: internalId,
  standard_id: internalId,
  entity_type: entityType,
  parent_types: [],
  timestamp: PAST,
  user_id: OTHER_ID,
  context_data: contextData,
});

const merge = (dryRun: boolean) => executeUserMerge(
  testContext,
  SOURCE_ID,
  TARGET_ID,
  { dryRun, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
);

const readDocument = async (internalId: string) => {
  const found = await elRawGet({ id: internalId, index: INDEX_HISTORY });
  return (found as { _source: { context_data: Record<string, unknown> } })._source.context_data;
};

let registeredHandlers: UserMergeHandler[];
let dryRunResult: Awaited<ReturnType<typeof merge>>;

// Values an object or a filter attribute records serialized in `raw`: the selection has to reach
// the id inside them as well as a plain one.
const members = (id: string) => JSON.stringify([{ id, access_right: 'view' }]);
const filters = (id: string) => JSON.stringify({ mode: 'and', filters: [{ key: ['creator_id'], values: [id] }], filterGroups: [] });
const changeOf = (field: string, raw: string) => [{ field, changes_added: [{ raw }], changes_removed: [] }];

const countOf = (result: typeof dryRunResult) => (result.report?.handlers ?? [])
  .flatMap((outcome) => outcome.changes)
  .filter((change) => change.register_row_id === 'history.context-data-payload')
  .reduce((sum, change) => sum + change.count, 0);

describe('userMerge history payload handler', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeHistoryPayloadHandler);
    const source = await addUser(testContext, ADMIN_USER, { name: 'usermerge-payload-source', password: 'usermerge', user_email: SOURCE_EMAIL, prevent_default_groups: true });
    const target = await addUser(testContext, ADMIN_USER, { name: 'usermerge-payload-target', password: 'usermerge', user_email: TARGET_EMAIL, prevent_default_groups: true });
    SOURCE_ID = source.id;
    TARGET_ID = target.id;
    // The shape the history manager writes for an update event: one entry per changed field,
    // each value keeping the id it resolved and the label it resolved to.
    await elIndex(INDEX_HISTORY, document(CHANGES_DOCUMENT, 'History', {
      message: 'Update 1 elements',
      entity_type: 'Report',
      entity_name: 'usermerge payload report',
      history_changes: [{
        field: 'Report--objectAssignee',
        changes_added: [{ raw: SOURCE_ID, translated: `{"${SOURCE_ID}":"usermerge-payload-source"}` }],
        changes_removed: [],
      }],
    }));
    await elIndex(INDEX_HISTORY, document(MEMBERS_CHANGE_DOCUMENT, 'History', {
      message: 'Update 1 elements',
      entity_type: 'Report',
      history_changes: changeOf('Report--authorized_members', members(SOURCE_ID)),
    }));
    await elIndex(INDEX_HISTORY, document(FILTERS_CHANGE_DOCUMENT, 'History', {
      message: 'Update 1 elements',
      entity_type: 'Trigger',
      history_changes: changeOf('Trigger--filters', filters(SOURCE_ID)),
    }));
    await elIndex(INDEX_HISTORY, document(OTHER_CHANGE_DOCUMENT, 'History', {
      message: 'Update 1 elements',
      entity_type: 'Report',
      history_changes: changeOf('Report--objectAssignee', OTHER_ID),
    }));
    // The raw payload the activity listener records is retained: neither exposed nor resolved.
    await elIndex(INDEX_HISTORY, document(RAW_PAYLOAD_DOCUMENT, 'Activity', {
      message: 'creates a stream',
      entity_type: 'Report',
      input: { objectAssignee: [SOURCE_ID] },
      filters: filters(SOURCE_ID),
    }));
    dryRunResult = await merge(true);
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    await elRawDeleteByQuery({
      index: READ_INDEX_HISTORY,
      refresh: true,
      body: { query: { ids: { values: DOCUMENT_IDS } } },
    });
    await deleteMergeableUser(SOURCE_ID);
    await deleteMergeableUser(TARGET_ID);
  });

  // The selection only reads the records whose changes name the source, nothing else.
  it('should plan the records whose recorded changes name the source', () => {
    expect(countOf(dryRunResult)).toEqual(3);
  });

  it('should rewrite the source id carried by a recorded change', async () => {
    const contextData = await readDocument(CHANGES_DOCUMENT) as {
      history_changes: { changes_added: { raw: string }[] }[];
    };
    expect(contextData.history_changes[0].changes_added[0].raw).toEqual(TARGET_ID);
  });

  it('should rewrite the source id a recorded change carries as a label map key', async () => {
    const contextData = await readDocument(CHANGES_DOCUMENT) as {
      history_changes: { changes_added: { translated: string }[] }[];
    };
    const translated = JSON.parse(contextData.history_changes[0].changes_added[0].translated);
    expect(Object.keys(translated)).toEqual([TARGET_ID]);
  });

  it('should rewrite the source id inside a serialized object change', async () => {
    const contextData = await readDocument(MEMBERS_CHANGE_DOCUMENT) as { history_changes: { changes_added: { raw: string }[] }[] };
    expect(contextData.history_changes[0].changes_added[0].raw).toEqual(members(TARGET_ID));
  });

  it('should rewrite the source id inside a serialized filters change', async () => {
    const contextData = await readDocument(FILTERS_CHANGE_DOCUMENT) as { history_changes: { changes_added: { raw: string }[] }[] };
    expect(contextData.history_changes[0].changes_added[0].raw).toEqual(filters(TARGET_ID));
  });

  it('should leave a change naming another account untouched', async () => {
    const contextData = await readDocument(OTHER_CHANGE_DOCUMENT) as { history_changes: { changes_added: { raw: string }[] }[] };
    expect(contextData.history_changes[0].changes_added[0].raw).toEqual(OTHER_ID);
  });

  it('should leave the raw payload of a record as recorded', async () => {
    const contextData = await readDocument(RAW_PAYLOAD_DOCUMENT) as { input: { objectAssignee: string[] }; filters: string };
    expect(contextData.input.objectAssignee).toEqual([SOURCE_ID]);
    expect(contextData.filters).toEqual(filters(SOURCE_ID));
  });

  it('should be a no-op when replayed', async () => {
    expect(countOf(await merge(true))).toEqual(0);
  });
});
