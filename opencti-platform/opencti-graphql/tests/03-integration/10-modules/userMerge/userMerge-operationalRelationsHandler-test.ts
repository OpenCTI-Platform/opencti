import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addIncident } from '../../../../src/domain/incident';
import { addDraftWorkspace, deleteDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import { addUser } from '../../../../src/modules/user/user-domain';
import { deleteMergeableUser } from './userMerge-testFixtures';
import { createEntity, deleteElementById, stixLoadById, updateAttribute } from '../../../../src/database/middleware';
import { elRawSearch } from '../../../../src/database/engine';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS } from '../../../../src/database/utils';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext } from '../../../../src/types/user';
import { buildRefRelationKey } from '../../../../src/schema/general';
import { ENTITY_TYPE_INCIDENT } from '../../../../src/schema/stixDomainObject';
import { RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../../../src/schema/stixRefRelationship';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeOperationalRelationsHandler } from '../../../../src/modules/userMerge/userMerge-operationalRelationsHandler';
import { userMergeBlobsHandler } from '../../../../src/modules/userMerge/userMerge-blobsHandler';
import { USER_MERGE_DRAFT_PATCH_TARGET } from '../../../../src/modules/userMerge/userMerge-blobTargets';
import { EditOperation } from '../../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const SOURCE_EMAIL = 'usermerge-operational-source@opencti.invalid';
const TARGET_EMAIL = 'usermerge-operational-target@opencti.invalid';
const TARGET_NAME = 'userMerge operational target user';

let sourceId: string;
let targetId: string;
let sourceStandardId: string;
let targetStandardId: string;

const created: string[] = [];
const silentIncidents: string[] = [];
const createdDrafts: string[] = [];

const merge = (dryRun: boolean) => executeUserMerge(
  testContext,
  sourceId,
  targetId,
  { dryRun, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
);

const createIncident = async (name: string, input: Record<string, string[]>) => {
  const incident = await addIncident(testContext, ADMIN_USER, { name, ...input });
  created.push(incident.id);
  return incident;
};

const createDraft = async (name: string, input: Record<string, string[]>) => {
  const draft = await addDraftWorkspace(testContext, ADMIN_USER, { name, ...input });
  createdDrafts.push(draft.id);
  return draft;
};

const refsOf = async (entityId: string, relationshipType: string, entityType: string = ENTITY_TYPE_INCIDENT, context: AuthContext = testContext): Promise<string[]> => {
  const entity = await storeLoadById<BasicStoreEntity>(context, ADMIN_USER, entityId, entityType);
  return (entity as unknown as Record<string, string[]>)[relationshipType] ?? [];
};

const trashedReferences = async (userId: string): Promise<number> => {
  const response = await elRawSearch(testContext, ADMIN_USER, [], {
    index: [INDEX_DELETED_OBJECTS],
    size: 0,
    body: {
      query: {
        bool: {
          should: [
            { nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': userId } } } },
            { term: { [`${buildRefRelationKey(RELATION_OBJECT_ASSIGNEE)}.keyword`]: userId } },
            { term: { [`${buildRefRelationKey(RELATION_OBJECT_PARTICIPANT)}.keyword`]: userId } },
          ],
          minimum_should_match: 1,
        },
      },
    },
  });
  return response.hits.total.value;
};

const countOf = (report: { handlers: { changes: { detail?: string; count: number }[] }[] } | undefined, detail: string): number => {
  return (report?.handlers ?? [])
    .flatMap((outcome) => outcome.changes)
    .filter((change) => change.detail === detail)
    .reduce((sum, change) => sum + change.count, 0);
};

let registeredHandlers: UserMergeHandler[];

describe('userMerge operational relations handler', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeOperationalRelationsHandler);
    const source = await addUser(testContext, ADMIN_USER, { name: 'userMerge operational source user', password: 'userMerge', user_email: SOURCE_EMAIL });
    const target = await addUser(testContext, ADMIN_USER, { name: TARGET_NAME, password: 'userMerge', user_email: TARGET_EMAIL });
    sourceId = source.id;
    targetId = target.id;
    sourceStandardId = source.standard_id;
    targetStandardId = target.standard_id;
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    for (let i = 0; i < created.length; i += 1) {
      const incident = await storeLoadById(testContext, ADMIN_USER, created[i], ENTITY_TYPE_INCIDENT);
      if (incident) {
        await deleteElementById(testContext, ADMIN_USER, created[i], ENTITY_TYPE_INCIDENT);
      }
    }
    // Silent like their creation.
    for (let i = 0; i < silentIncidents.length; i += 1) {
      await deleteElementById(testContext, SYSTEM_USER, silentIncidents[i], ENTITY_TYPE_INCIDENT, { publishStreamEvent: false });
    }
    for (let i = 0; i < createdDrafts.length; i += 1) {
      await deleteDraftWorkspace(testContext, ADMIN_USER, createdDrafts[i]);
    }
    await deleteMergeableUser(sourceId);
    await deleteMergeableUser(targetId);
  });

  it('should re-point an assignee the target does not hold', async () => {
    const incident = await createIncident('userMerge operational assignee', { objectAssignee: [sourceId] });
    const dryRun = await merge(true);
    expect(dryRun.status).toEqual(UserMergeStatus.Success);
    expect(countOf(dryRun.report, 're-pointed to the target')).toEqual(1);
    expect(dryRun.report?.total_updated).toEqual(0);
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await refsOf(incident.id, RELATION_OBJECT_ASSIGNEE)).toEqual([targetId]);
  });

  it('should re-point a participant the target does not hold', async () => {
    const incident = await createIncident('userMerge operational participant', { objectParticipant: [sourceId] });
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await refsOf(incident.id, RELATION_OBJECT_PARTICIPANT)).toEqual([targetId]);
  });

  it('should re-point an assignee carried by a draft workspace', async () => {
    const draft = await createDraft('userMerge operational draft', { objectAssignee: [sourceId] });
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await refsOf(draft.id, RELATION_OBJECT_ASSIGNEE, ENTITY_TYPE_DRAFT_WORKSPACE)).toEqual([targetId]);
  });

  it('should drop the source edge when the target is already assigned', async () => {
    const incident = await createIncident('userMerge operational both', { objectAssignee: [sourceId, targetId] });
    const dryRun = await merge(true);
    expect(countOf(dryRun.report, 'already held by the target, source edge dropped')).toEqual(1);
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await refsOf(incident.id, RELATION_OBJECT_ASSIGNEE)).toEqual([targetId]);
  });

  it('should rewrite the deleted copies left in the trash', async () => {
    const incident = await createIncident('userMerge operational trashed', { objectAssignee: [sourceId] });
    await deleteElementById(testContext, ADMIN_USER, incident.id, ENTITY_TYPE_INCIDENT);
    expect(await trashedReferences(sourceId)).toBeGreaterThan(0);
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await trashedReferences(sourceId)).toEqual(0);
    expect(await trashedReferences(targetId)).toBeGreaterThan(0);
  });

  // A draft is read in its own context, which the live path never enters. Validating it replays
  // the draft patch for an edited entity, and sends a created one with its draft relations. The
  // blobs handler, which rewrites the patch, has no integration suite of its own: it borrows this
  // pair rather than creating two more users, whose individuals would shift the raw stream counters.
  describe('inside a draft', () => {
    const DRAFTED = 'rewritten inside a draft';
    const DRAFT_DEDUPLICATED = 'already held by the target inside a draft, source edge dropped';

    beforeAll(() => {
      registerUserMergeHandler(userMergeBlobsHandler);
    });

    afterAll(() => {
      resetUserMergeHandlers();
      registerUserMergeHandler(userMergeOperationalRelationsHandler);
    });

    // Silent, so the stream never carries these incidents and the raw stream counters stay put.
    const createSilentIncident = async (name: string, input: Record<string, string[]> = {}) => {
      const incident = await createEntity(testContext, SYSTEM_USER, { name, ...input }, ENTITY_TYPE_INCIDENT, { publishStreamEvent: false });
      silentIncidents.push(incident.id);
      return incident;
    };

    const draftContextOf = async (name: string): Promise<AuthContext> => {
      const draft = await createDraft(name, {});
      return { ...testContext, draft_context: draft.id };
    };

    const assign = (draftContext: AuthContext, entityId: string, userId: string, operation: EditOperation) => {
      return updateAttribute(draftContext, ADMIN_USER, entityId, ENTITY_TYPE_INCIDENT, [{ key: 'objectAssignee', value: [userId], operation }]);
    };

    const patchOf = async (draftContext: AuthContext, entityId: string) => {
      const copy = await storeLoadById<BasicStoreEntity>(draftContext, ADMIN_USER, entityId, ENTITY_TYPE_INCIDENT);
      return JSON.parse(copy.draft_change?.draft_updates_patch ?? '{}');
    };

    // What validating the draft sends for an entity it created.
    const stixAssigneesOf = async (draftContext: AuthContext, entityId: string): Promise<string[]> => {
      const stix = await stixLoadById(draftContext, ADMIN_USER, entityId) as unknown as { extensions: Record<string, { assignee_ids?: string[] }> };
      return stix.extensions[STIX_EXT_OCTI].assignee_ids ?? [];
    };

    it('should rewrite an assignee added inside a draft, in the patch and in the draft copy', async () => {
      const incident = await createSilentIncident('userMerge operational draft edit');
      const draftContext = await draftContextOf('userMerge operational draft edit');
      await assign(draftContext, incident.id, sourceId, EditOperation.Add);
      expect((await patchOf(draftContext, incident.id)).objectAssignee.added_value).toEqual([sourceStandardId]);

      const dryRun = await merge(true);
      expect(countOf(dryRun.report, USER_MERGE_DRAFT_PATCH_TARGET.path)).toEqual(1);
      // The draft relation and the entity copy carrying it.
      expect(countOf(dryRun.report, DRAFTED)).toEqual(2);
      const result = await merge(false);
      expect(result.status).toEqual(UserMergeStatus.Success);
      expect((await patchOf(draftContext, incident.id)).objectAssignee.added_value).toEqual([targetStandardId]);
      expect(await refsOf(incident.id, RELATION_OBJECT_ASSIGNEE, ENTITY_TYPE_INCIDENT, draftContext)).toEqual([targetId]);
      expect(await stixAssigneesOf(draftContext, incident.id)).toEqual([targetId]);

      const replay = await merge(true);
      expect(countOf(replay.report, USER_MERGE_DRAFT_PATCH_TARGET.path)).toEqual(0);
      expect(countOf(replay.report, DRAFTED)).toEqual(0);
    });

    it('should hand an entity created inside a draft to the target', async () => {
      const draftContext = await draftContextOf('userMerge operational draft creation');
      const created = await createEntity(draftContext, ADMIN_USER, { name: 'userMerge operational draft creation', objectAssignee: [sourceId] }, ENTITY_TYPE_INCIDENT);
      expect(await stixAssigneesOf(draftContext, created.id)).toEqual([sourceId]);

      const result = await merge(false);
      expect(result.status).toEqual(UserMergeStatus.Success);
      expect(await stixAssigneesOf(draftContext, created.id)).toEqual([targetId]);
      // A connection carries the name of its element next to its id.
      const relations = await elRawSearch(testContext, ADMIN_USER, [], {
        index: [READ_INDEX_DRAFT_OBJECTS],
        body: { query: { nested: { path: 'connections', query: { term: { 'connections.internal_id.keyword': created.id } } } } },
      });
      const userSides = relations.hits.hits.flatMap((hit: { _source: { connections: { role: string }[] } }) => hit._source.connections)
        .filter((connection: { role: string }) => connection.role === `${RELATION_OBJECT_ASSIGNEE}_to`);
      expect(userSides).toEqual([expect.objectContaining({ internal_id: targetId, name: TARGET_NAME })]);
    });

    it('should drop the draft edge when the draft already holds the target', async () => {
      const incident = await createSilentIncident('userMerge operational draft both', { objectAssignee: [targetId] });
      const draftContext = await draftContextOf('userMerge operational draft both');
      await assign(draftContext, incident.id, sourceId, EditOperation.Add);

      const dryRun = await merge(true);
      expect(countOf(dryRun.report, DRAFT_DEDUPLICATED)).toEqual(1);
      const result = await merge(false);
      expect(result.status).toEqual(UserMergeStatus.Success);
      expect(await stixAssigneesOf(draftContext, incident.id)).toEqual([targetId]);
      expect(await refsOf(incident.id, RELATION_OBJECT_ASSIGNEE, ENTITY_TYPE_INCIDENT, draftContext)).toEqual([targetId]);
    });

    it('should rewrite a live assignment the draft copy carries', async () => {
      const incident = await createSilentIncident('userMerge operational draft copy', { objectAssignee: [sourceId] });
      const draftContext = await draftContextOf('userMerge operational draft copy');
      await updateAttribute(draftContext, ADMIN_USER, incident.id, ENTITY_TYPE_INCIDENT, [{ key: 'description', value: ['edited in a draft'] }]);

      const result = await merge(false);
      expect(result.status).toEqual(UserMergeStatus.Success);
      expect(await refsOf(incident.id, RELATION_OBJECT_ASSIGNEE)).toEqual([targetId]);
      expect(await refsOf(incident.id, RELATION_OBJECT_ASSIGNEE, ENTITY_TYPE_INCIDENT, draftContext)).toEqual([targetId]);
    });

    // Validation applies the add before the remove: a swap left as both would unassign the target.
    it('should keep the target assigned when a draft swapped the source for it', async () => {
      const incident = await createSilentIncident('userMerge operational draft swap', { objectAssignee: [sourceId] });
      const draftContext = await draftContextOf('userMerge operational draft swap');
      await assign(draftContext, incident.id, sourceId, EditOperation.Remove);
      await assign(draftContext, incident.id, targetId, EditOperation.Add);

      const result = await merge(false);
      expect(result.status).toEqual(UserMergeStatus.Success);
      const patch = (await patchOf(draftContext, incident.id)).objectAssignee;
      expect(patch.added_value).toEqual([targetStandardId]);
      expect(patch.removed_value).toEqual([]);
    });
  });

  it('should be a no-op when nothing references the source user', async () => {
    const result = await merge(false);
    expect(result.report?.total_updated).toEqual(0);
  });
});
