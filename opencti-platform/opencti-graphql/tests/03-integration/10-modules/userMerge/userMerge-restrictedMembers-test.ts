import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { testContext } from '../../../utils/testQuery';
import * as cache from '../../../../src/database/cache';
import { addGroup } from '../../../../src/domain/grant';
import { addUser, userDelete } from '../../../../src/domain/user';
import { addCaseRfi } from '../../../../src/modules/case/case-rfi/case-rfi-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../../src/modules/case/case-rfi/case-rfi-types';
import { deleteElementById } from '../../../../src/database/middleware';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_GROUP } from '../../../../src/schema/internalObject';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER } from '../../../../src/utils/access';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeRightsHandler } from '../../../../src/modules/userMerge/userMerge-rightsHandler';
import type { UserMergeRestrictedMember } from '../../../../src/modules/userMerge/userMerge-restrictedMembers';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';
import type { AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntity } from '../../../../src/types/store';

const SUFFIX = 'userMergeRestricted';

let sourceId: string;
let targetId: string;
let sharedGroupId: string;
let sourceGroupId: string;
let otherUserId: string;
let caseId: string;

const merge = () => executeUserMerge(
  testContext,
  sourceId,
  targetId,
  { dryRun: false, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
);

const membersOf = async (): Promise<UserMergeRestrictedMember[]> => {
  const entity = await storeLoadById<BasicStoreEntity>(testContext, SYSTEM_USER, caseId, ENTITY_TYPE_CONTAINER_CASE_RFI);
  return (entity?.restricted_members ?? []) as UserMergeRestrictedMember[];
};

const entryOf = (members: UserMergeRestrictedMember[], id: string, restriction: string[] | undefined) => {
  const key = [...(restriction ?? [])].sort().join(',');
  return members.find((member) => member.id === id && [...(member.groups_restriction_ids ?? [])].sort().join(',') === key);
};

let registeredHandlers: UserMergeHandler[];

describe('userMerge restricted members transfer', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeRightsHandler);
    const sharedGroup = await addGroup(testContext, SYSTEM_USER, { name: `${SUFFIX}-shared-group` });
    const sourceGroup = await addGroup(testContext, SYSTEM_USER, { name: `${SUFFIX}-source-group` });
    sharedGroupId = sharedGroup.id;
    sourceGroupId = sourceGroup.id;
    // Without this, the three accounts join the platform default groups, and the rights handler
    // then counts memberships and authorities that come from fixture objects shared with the rest
    // of the integration suite. A count moving between the dry pass and the real one aborts the
    // merge, so the test only owns what it creates itself.
    const source = await addUser(testContext, SYSTEM_USER, { name: `${SUFFIX}-source`, password: SUFFIX, user_email: `${SUFFIX}-source@opencti.invalid`, prevent_default_groups: true });
    const target = await addUser(testContext, SYSTEM_USER, { name: `${SUFFIX}-target`, password: SUFFIX, user_email: `${SUFFIX}-target@opencti.invalid`, prevent_default_groups: true });
    const other = await addUser(testContext, SYSTEM_USER, { name: `${SUFFIX}-other`, password: SUFFIX, user_email: `${SUFFIX}-other@opencti.invalid`, prevent_default_groups: true });
    sourceId = source.id;
    targetId = target.id;
    otherUserId = other.id;
    const caseRfi = await addCaseRfi(testContext, SYSTEM_USER, {
      name: `${SUFFIX}-case`,
      authorized_members: [
        // Same restriction on both users: the two entries have to collapse into one.
        { id: targetId, access_right: MEMBER_ACCESS_RIGHT_VIEW, groups_restriction_ids: [sharedGroupId] },
        { id: sourceId, access_right: MEMBER_ACCESS_RIGHT_ADMIN, groups_restriction_ids: [sharedGroupId] },
        // Restriction the target does not hold: the entry has to be carried over as it is.
        { id: sourceId, access_right: MEMBER_ACCESS_RIGHT_EDIT, groups_restriction_ids: [sourceGroupId] },
        // Unrestricted entry, a rule of its own beside the restricted ones.
        { id: sourceId, access_right: MEMBER_ACCESS_RIGHT_VIEW },
        { id: otherUserId, access_right: MEMBER_ACCESS_RIGHT_ADMIN },
      ],
    });
    caseId = caseRfi.id;
    // The engine reads the two users from the cache, which is not refreshed inside a test run.
    // The target holds the management capability, otherwise the transfer raises a blocking alert.
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map<string, AuthUser>([
      [sourceId, { id: sourceId, user_email: `${SUFFIX}-source@opencti.invalid`, allowed_marking: [], organizations: [], groups: [], capabilities: [] } as unknown as AuthUser],
      [targetId, {
        id: targetId,
        user_email: `${SUFFIX}-target@opencti.invalid`,
        allowed_marking: [],
        organizations: [],
        groups: [],
        capabilities: [{ name: KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS }],
      } as unknown as AuthUser],
    ]));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    await deleteElementById(testContext, SYSTEM_USER, caseId, ENTITY_TYPE_CONTAINER_CASE_RFI);
    await userDelete(testContext, SYSTEM_USER, sourceId);
    await userDelete(testContext, SYSTEM_USER, targetId);
    await userDelete(testContext, SYSTEM_USER, otherUserId);
    await deleteElementById(testContext, SYSTEM_USER, sharedGroupId, ENTITY_TYPE_GROUP);
    await deleteElementById(testContext, SYSTEM_USER, sourceGroupId, ENTITY_TYPE_GROUP);
  });

  it('should collapse the shared restriction and carry the others over', async () => {
    const result = await merge();
    expect(result.status).toEqual(UserMergeStatus.Success);
    const members = await membersOf();
    expect(members.filter((member) => member.id === sourceId)).toHaveLength(0);
    expect(entryOf(members, targetId, [sharedGroupId])?.access_right).toEqual(MEMBER_ACCESS_RIGHT_ADMIN);
    expect(entryOf(members, targetId, [sourceGroupId])?.access_right).toEqual(MEMBER_ACCESS_RIGHT_EDIT);
    expect(entryOf(members, targetId, undefined)?.access_right).toEqual(MEMBER_ACCESS_RIGHT_VIEW);
    expect(entryOf(members, otherUserId, undefined)?.access_right).toEqual(MEMBER_ACCESS_RIGHT_ADMIN);
    expect(members).toHaveLength(4);
  });

  it('should be a no-op when replayed', async () => {
    const before = await membersOf();
    const result = await merge();
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await membersOf()).toEqual(before);
  });
});
