import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as cache from '../../../../src/database/cache';
import { addIncident } from '../../../../src/domain/incident';
import { addDraftWorkspace, deleteDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import { addUser, userDelete } from '../../../../src/domain/user';
import { deleteElementById } from '../../../../src/database/middleware';
import { elRawSearch } from '../../../../src/database/engine';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { INDEX_DELETED_OBJECTS } from '../../../../src/database/utils';
import { buildRefRelationKey } from '../../../../src/schema/general';
import { ENTITY_TYPE_INCIDENT } from '../../../../src/schema/stixDomainObject';
import { RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../../../src/schema/stixRefRelationship';
import type { BasicStoreEntity } from '../../../../src/types/store';
import type { AuthUser } from '../../../../src/types/user';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeOperationalRelationsHandler } from '../../../../src/modules/userMerge/userMerge-operationalRelationsHandler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const SOURCE_EMAIL = 'usermerge-operational-source@opencti.invalid';
const TARGET_EMAIL = 'usermerge-operational-target@opencti.invalid';

let sourceId: string;
let targetId: string;

const created: string[] = [];
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

const refsOf = async (entityId: string, relationshipType: string, entityType: string = ENTITY_TYPE_INCIDENT): Promise<string[]> => {
  const entity = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, entityId, entityType);
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
    const target = await addUser(testContext, ADMIN_USER, { name: 'userMerge operational target user', password: 'userMerge', user_email: TARGET_EMAIL });
    sourceId = source.id;
    targetId = target.id;
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map<string, AuthUser>([
      [sourceId, { id: sourceId, user_email: SOURCE_EMAIL } as unknown as AuthUser],
      [targetId, { id: targetId, user_email: TARGET_EMAIL } as unknown as AuthUser],
    ]));
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
    for (let i = 0; i < createdDrafts.length; i += 1) {
      await deleteDraftWorkspace(testContext, ADMIN_USER, createdDrafts[i]);
    }
    await userDelete(testContext, ADMIN_USER, sourceId);
    await userDelete(testContext, ADMIN_USER, targetId);
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

  it('should be a no-op when nothing references the source user', async () => {
    const result = await merge(false);
    expect(result.report?.total_updated).toEqual(0);
  });
});
