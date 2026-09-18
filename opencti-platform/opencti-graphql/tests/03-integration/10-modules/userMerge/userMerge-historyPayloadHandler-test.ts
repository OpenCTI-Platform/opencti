import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { elIndex, elRawDeleteByQuery, elRawGet } from '../../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addUser } from '../../../../src/domain/user';
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
const INPUT_DOCUMENT = 'merge-test-payload-input';
const DOCUMENT_IDS = [CHANGES_DOCUMENT, INPUT_DOCUMENT];

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
    // The shape the activity listener writes, which the same row also covers.
    await elIndex(INDEX_HISTORY, document(INPUT_DOCUMENT, 'Activity', {
      message: 'creates a report',
      entity_type: 'Report',
      input: { objectAssignee: [SOURCE_ID] },
    }));
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

  it('should rewrite the source id carried by a recorded input', async () => {
    const contextData = await readDocument(INPUT_DOCUMENT) as { input: { objectAssignee: string[] } };
    expect(contextData.input.objectAssignee).toEqual([TARGET_ID]);
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
});
