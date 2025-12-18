import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { AMBER_GROUP, GREEN_GROUP, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';
import { DEFAULT_ROLE, SYSTEM_USER } from '../../../src/utils/access';
import type { CaseRfiAddInput } from '../../../src/generated/graphql';
import { addCaseRfi, findById as findRfiById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import type { Group } from '../../../src/types/group';
import { internalDeleteElementById } from '../../../src/database/middleware';
import { now } from '../../../src/utils/format';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

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
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);

    platformOrganizationEntity = await getOrganizationEntity(PLATFORM_ORGANIZATION);
    testOrganizationEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    greenGroup = await getGroupEntity(GREEN_GROUP);
    amberGroup = await getGroupEntity(AMBER_GROUP);

    userPlatformOrgGreenGroup = getFakeAuthUser('userPlatformOrgGreenGroup');
    userPlatformOrgGreenGroup.groups = [greenGroup];
    userPlatformOrgGreenGroup.roles = [DEFAULT_ROLE];
    userPlatformOrgGreenGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    userPlatformOrgGreenGroup.organizations = [platformOrganizationEntity];

    userPlatformOrgAmberGroup = getFakeAuthUser('userPlatformOrgAmberGroup');
    userPlatformOrgAmberGroup.groups = [amberGroup];
    userPlatformOrgAmberGroup.roles = [DEFAULT_ROLE];
    userPlatformOrgAmberGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    userPlatformOrgAmberGroup.organizations = [platformOrganizationEntity];

    userTestOrgGreenGroup = getFakeAuthUser('userTestOrgGreenGroup');
    userTestOrgGreenGroup.groups = [greenGroup];
    userTestOrgGreenGroup.roles = [DEFAULT_ROLE];
    userTestOrgGreenGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    userTestOrgGreenGroup.organizations = [testOrganizationEntity];

    userTestOrgAmberGroup = getFakeAuthUser('userTestOrgAmberGroup');
    userTestOrgAmberGroup.groups = [amberGroup];
    userTestOrgAmberGroup.roles = [DEFAULT_ROLE];
    userTestOrgAmberGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    userTestOrgAmberGroup.organizations = [testOrganizationEntity];
  });

  afterAll(async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    for (let i = 0; i < idToDelete.length; i += 1) {
      await internalDeleteElementById(testContext, SYSTEM_USER, idToDelete[i], ENTITY_TYPE_CONTAINER_CASE_RFI); // +5 RFI deleted
    }
    await unSetOrganization();
  });

  it('should User in intersection group X org has access', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI nominal intersection org X group',
      created: now(),
      authorized_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin',
          groups_restriction_ids: [greenGroup.id],
        },
      ],
      revoked: false,
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    idToDelete.push(requestForInformation.id);

    // Only user that is both in green group and platform org should be allowed
    const result_userPlatformOrgGreenGroup = await findRfiById(testContext, userPlatformOrgGreenGroup, requestForInformation.id);
    expect(result_userPlatformOrgGreenGroup).toBeDefined();
    expect(result_userPlatformOrgGreenGroup.restricted_members).toBeDefined();

    const result_userPlatformOrgAmberGroup = await findRfiById(testContext, userPlatformOrgAmberGroup, requestForInformation.id);
    expect(result_userPlatformOrgAmberGroup).toBeUndefined();
  });
  it('Should everyone has access if no restricted member and no org platform', async () => {
    // disable org sharing
    await unSetOrganization();
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI no restricted members',
      created: now(),
      revoked: false,
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    idToDelete.push(requestForInformation.id);

    // All Users should be allowed
    const result_userPlatformOrgGreenGroup = await findRfiById(testContext, userPlatformOrgGreenGroup, requestForInformation.id);
    expect(result_userPlatformOrgGreenGroup).toBeDefined();
    const result_userTestOrgGreenGroup = await findRfiById(testContext, userTestOrgGreenGroup, requestForInformation.id);
    expect(result_userTestOrgGreenGroup).toBeDefined();

    // enable EE and org sharing
    await setOrganization(PLATFORM_ORGANIZATION);
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });
  it('Should User not in group X org but in additional User restricted member has access', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI and additonal User restricted member',
      created: now(),
      authorized_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin',
          groups_restriction_ids: [greenGroup.id],
        },
        {
          id: userTestOrgAmberGroup.id,
          access_right: 'admin',
        },
      ],
      revoked: false,
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    idToDelete.push(requestForInformation.id);

    const result_userTestOrgAmberGroup = await findRfiById(testContext, userTestOrgAmberGroup, requestForInformation.id);
    expect(result_userTestOrgAmberGroup).toBeDefined();
    expect(result_userTestOrgAmberGroup.restricted_members).toBeDefined();
  });
  it('Should User not in group X org but in additional Group restricted member has access', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI and additonal Group restricted member',
      created: now(),
      authorized_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin',
          groups_restriction_ids: [greenGroup.id],
        },
        {
          id: amberGroup.id,
          access_right: 'admin',
        },
      ],
      revoked: false,
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    idToDelete.push(requestForInformation.id);

    const result_userTestOrgAmberGroup = await findRfiById(testContext, userTestOrgAmberGroup, requestForInformation.id);
    expect(result_userTestOrgAmberGroup).toBeDefined();
    expect(result_userTestOrgAmberGroup.restricted_members).toBeDefined();
  });
  it('Should User not in group X org but in additional Org restricted member has access', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI and additonal Org restricted member',
      created: now(),
      authorized_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin',
          groups_restriction_ids: [greenGroup.id],
        },
        {
          id: testOrganizationEntity.id,
          access_right: 'admin',
        },
      ],
      revoked: false,
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    idToDelete.push(requestForInformation.id);

    const result_userTestOrgAmberGroup = await findRfiById(testContext, userTestOrgAmberGroup, requestForInformation.id);
    expect(result_userTestOrgAmberGroup).toBeDefined();
    expect(result_userTestOrgAmberGroup.restricted_members).toBeDefined();
  });
});
