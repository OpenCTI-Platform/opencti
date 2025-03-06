import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { now } from 'moment';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { AMBER_GROUP, GREEN_GROUP, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';
import { DEFAULT_ROLE, SYSTEM_USER } from '../../../src/utils/access';
import type { CaseRfiAddInput } from '../../../src/generated/graphql';
import { addCaseRfi, findById as findRfiById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import type { Group } from '../../../src/types/group';
import { internalDeleteElementById } from '../../../src/database/middleware';

describe('Middleware test coverage on restricted_members configuration', () => {
  let userPlatformOrgGreenGroup: AuthUser;
  let userPlatformOrgAmberGroup: AuthUser;
  let userTestOrgGreenGroup: AuthUser;
  let userTestOrgAmberGroup: AuthUser;
  let greenGroup: Group;
  let amberGroup: Group;

  let platformOrganizationEntity: BasicStoreEntityOrganization;
  let testOrganizationEntity: BasicStoreEntityOrganization;

  const idToDelete: string[] = [];

  beforeAll(async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);

    platformOrganizationEntity = await getOrganizationEntity(PLATFORM_ORGANIZATION);
    testOrganizationEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    greenGroup = await getGroupEntity(GREEN_GROUP);
    amberGroup = await getGroupEntity(AMBER_GROUP);

    userPlatformOrgGreenGroup = getFakeAuthUser('userPlatformOrgGreenGroup');
    userPlatformOrgGreenGroup.groups = [greenGroup];
    userPlatformOrgGreenGroup.roles = [DEFAULT_ROLE];
    userPlatformOrgGreenGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userPlatformOrgGreenGroup.organizations = [platformOrganizationEntity];

    userPlatformOrgAmberGroup = getFakeAuthUser('userPlatformOrgAmberGroup');
    userPlatformOrgAmberGroup.groups = [amberGroup];
    userPlatformOrgAmberGroup.roles = [DEFAULT_ROLE];
    userPlatformOrgAmberGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userPlatformOrgAmberGroup.organizations = [platformOrganizationEntity];

    userTestOrgGreenGroup = getFakeAuthUser('userTestOrgGreenGroup');
    userTestOrgGreenGroup.groups = [greenGroup];
    userTestOrgGreenGroup.roles = [DEFAULT_ROLE];
    userTestOrgGreenGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userTestOrgGreenGroup.organizations = [testOrganizationEntity];

    userTestOrgAmberGroup = getFakeAuthUser('userTestOrgAmberGroup');
    userTestOrgAmberGroup.groups = [amberGroup];
    userTestOrgAmberGroup.roles = [DEFAULT_ROLE];
    userTestOrgAmberGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userTestOrgAmberGroup.organizations = [testOrganizationEntity];
  });

  afterAll(async () => {
    for (let i = 0; i < idToDelete.length; i += 1) {
      await internalDeleteElementById(testContext, SYSTEM_USER, idToDelete[i]);
    }
    await enableCEAndUnSetOrganization();
  });

  it('should RFI with intersection group X org authorized members works', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI nominal intersection org X group',
      created: now(),
      restricted_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin',
          groups_restriction_ids: [greenGroup.id]
        }
      ],
      revoked: false
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    console.log('ANGIE - RFI created:', requestForInformation);
    idToDelete.push(requestForInformation.id);

    // Only user that is both in green group and platform org should be allowed
    const result_userPlatformOrgGreenGroup = await findRfiById(testContext, userPlatformOrgGreenGroup, requestForInformation.id);
    expect(result_userPlatformOrgGreenGroup).toBeDefined();
    expect(result_userPlatformOrgGreenGroup.restricted_members).toBeDefined();

    const result_userPlatformOrgAmberGroup = await findRfiById(testContext, userPlatformOrgAmberGroup, requestForInformation.id);
    console.log('ANGIE - result_userPlatformOrgAmberGroup:', result_userPlatformOrgAmberGroup);
    expect(result_userPlatformOrgAmberGroup).toBeUndefined();
  });

  it.todo('[>=6.6 & <6.9] on renaming authorized_members to restricted_members - should deprecated authorized_members still works', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'Deprecated CaseRFI nominal intersection org X group',
      created: now(),
      authorized_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin'
        }
      ],
      revoked: false
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    idToDelete.push(requestForInformation.id);
    const result = await findRfiById(testContext, userPlatformOrgGreenGroup, requestForInformation.id);
    expect(result).toBeDefined();
    expect(result.restricted_members).toBeDefined();
    if (result.restricted_members) {
      const firstMember = result?.restricted_members[0];
      expect(firstMember.id).toBe(platformOrganizationEntity.id);
    }
  });
});
