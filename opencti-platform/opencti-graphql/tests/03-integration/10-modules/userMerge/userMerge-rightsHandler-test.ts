import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as cache from '../../../../src/database/cache';
import { addGroup } from '../../../../src/domain/grant';
import { addUser, assignGroupToUser, userAddRelation, userDelete } from '../../../../src/domain/user';
import { addOrganization } from '../../../../src/modules/organization/organization-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { deleteElementById } from '../../../../src/database/middleware';
import { fullRelationsList } from '../../../../src/database/middleware-loader';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../../../../src/schema/internalRelationship';
import { ENTITY_TYPE_GROUP } from '../../../../src/schema/internalObject';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeRightsHandler, USER_MERGE_RIGHTS_HANDLER } from '../../../../src/modules/userMerge/userMerge-rightsHandler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';
import type { AuthUser } from '../../../../src/types/user';

const SUFFIX = 'userMergeRights';

let sourceId: string;
let targetId: string;
let sourceGroupId: string;
let targetGroupId: string;
let organizationId: string;

const merge = (dryRun: boolean, rightsStrategy: UserMergeRightsStrategy) => executeUserMerge(
  testContext,
  sourceId,
  targetId,
  { dryRun, rightsStrategy, acknowledgeExposureChange: false },
);

const changeFor = (
  report: { handlers: { handler: string; changes: { register_row_id: string; detail?: string; count: number }[] }[] } | undefined,
  rowId: string,
  detail: string,
) => {
  const handler = report?.handlers.find((entry) => entry.handler === USER_MERGE_RIGHTS_HANDLER);
  return handler?.changes.find((change) => change.register_row_id === rowId && change.detail === detail);
};

const relationsOf = async (userId: string, relationshipType: string) => {
  const relations = await fullRelationsList(testContext, ADMIN_USER, relationshipType, { fromId: userId });
  return relations.map((relation) => relation.toId);
};

let registeredHandlers: UserMergeHandler[];

describe('userMerge rights handler', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeRightsHandler);
    const sourceGroup = await addGroup(testContext, ADMIN_USER, { name: `${SUFFIX}-source-group` });
    const targetGroup = await addGroup(testContext, ADMIN_USER, { name: `${SUFFIX}-target-group` });
    const organization = await addOrganization(testContext, ADMIN_USER, { name: `${SUFFIX}-organization` });
    sourceGroupId = sourceGroup.id;
    targetGroupId = targetGroup.id;
    organizationId = organization.id;
    const source = await addUser(testContext, ADMIN_USER, { name: `${SUFFIX}-source`, password: SUFFIX, user_email: `${SUFFIX}-source@opencti.invalid`, prevent_default_groups: true });
    const target = await addUser(testContext, ADMIN_USER, { name: `${SUFFIX}-target`, password: SUFFIX, user_email: `${SUFFIX}-target@opencti.invalid`, prevent_default_groups: true });
    sourceId = source.id;
    targetId = target.id;
    await assignGroupToUser(testContext, ADMIN_USER, sourceId, sourceGroup.name);
    await assignGroupToUser(testContext, ADMIN_USER, targetId, targetGroup.name);
    await userAddRelation(testContext, ADMIN_USER, sourceId, { relationship_type: RELATION_PARTICIPATE_TO, toId: organizationId });
    // The engine reads the two users from the cache, which is not refreshed inside a test run.
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map<string, AuthUser>([
      [sourceId, { id: sourceId, user_email: `${SUFFIX}-source@opencti.invalid`, allowed_marking: [], organizations: [], capabilities: [] } as unknown as AuthUser],
      [targetId, { id: targetId, user_email: `${SUFFIX}-target@opencti.invalid`, allowed_marking: [], organizations: [], capabilities: [] } as unknown as AuthUser],
    ]));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    await userDelete(testContext, ADMIN_USER, sourceId);
    await userDelete(testContext, ADMIN_USER, targetId);
    await deleteElementById(testContext, ADMIN_USER, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    await deleteElementById(testContext, ADMIN_USER, sourceGroupId, ENTITY_TYPE_GROUP);
    await deleteElementById(testContext, ADMIN_USER, targetGroupId, ENTITY_TYPE_GROUP);
  });

  it('should drop the source memberships and grant nothing under the strict strategy', async () => {
    const result = await merge(true, UserMergeRightsStrategy.Strict);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(changeFor(result.report, 'member-of.connections', 'removed from the source')?.count).toEqual(1);
    expect(changeFor(result.report, 'member-of.connections', 'granted to the target')?.count).toEqual(0);
    expect(changeFor(result.report, 'participate-to.connections', 'granted to the target')?.count).toEqual(0);
  });

  it('should grant the source memberships to the target under the union strategy', async () => {
    const result = await merge(true, UserMergeRightsStrategy.Union);
    expect(changeFor(result.report, 'member-of.connections', 'granted to the target')?.count).toEqual(1);
    expect(changeFor(result.report, 'participate-to.connections', 'granted to the target')?.count).toEqual(1);
  });

  it('should write nothing during a dry run', async () => {
    expect(await relationsOf(sourceId, RELATION_MEMBER_OF)).toEqual([sourceGroupId]);
    expect(await relationsOf(targetId, RELATION_MEMBER_OF)).toEqual([targetGroupId]);
  });

  it('should move the memberships to the target and leave the source with none', async () => {
    const result = await merge(false, UserMergeRightsStrategy.Union);
    expect(result.status).toEqual(UserMergeStatus.Success);
    const targetGroups = await relationsOf(targetId, RELATION_MEMBER_OF);
    expect(targetGroups.sort()).toEqual([sourceGroupId, targetGroupId].sort());
    expect(await relationsOf(targetId, RELATION_PARTICIPATE_TO)).toEqual([organizationId]);
    expect(await relationsOf(sourceId, RELATION_MEMBER_OF)).toEqual([]);
    expect(await relationsOf(sourceId, RELATION_PARTICIPATE_TO)).toEqual([]);
  });

  it('should be a no-op when replayed', async () => {
    const result = await merge(false, UserMergeRightsStrategy.Union);
    expect(result.report?.total_updated).toEqual(0);
    const targetGroups = await relationsOf(targetId, RELATION_MEMBER_OF);
    expect(targetGroups.sort()).toEqual([sourceGroupId, targetGroupId].sort());
  });
});
