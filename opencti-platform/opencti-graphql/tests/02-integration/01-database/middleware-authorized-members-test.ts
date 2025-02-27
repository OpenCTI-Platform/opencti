import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { now } from 'moment';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { AMBER_GROUP, GREEN_GROUP, PLATFORM_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';
import { DEFAULT_ROLE, SYSTEM_USER } from '../../../src/utils/access';
import type { CaseRfiAddInput } from '../../../src/generated/graphql';
import { addCaseRfi, findById } from '../../../src/modules/case/case-rfi/case-rfi-domain';
import type { Group } from '../../../src/types/group';

describe('Middleware test coverage on organization sharing verification', () => {
  let userGreenGroup: AuthUser;
  let userAmberGroup: AuthUser;
  let greenGroup: Group;
  let amberGroup: Group;

  let platformOrganizationEntity: BasicStoreEntityOrganization;

  beforeAll(async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);

    platformOrganizationEntity = await getOrganizationEntity(PLATFORM_ORGANIZATION);
    greenGroup = await getGroupEntity(GREEN_GROUP);
    amberGroup = await getGroupEntity(AMBER_GROUP);

    userGreenGroup = getFakeAuthUser('userGreenGroup');
    userGreenGroup.groups = [greenGroup];
    userGreenGroup.roles = [DEFAULT_ROLE];
    userGreenGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userGreenGroup.inside_platform_organization = true;
    userGreenGroup.organizations = [platformOrganizationEntity];

    userAmberGroup = getFakeAuthUser('userAmberGroup');
    userAmberGroup.groups = [amberGroup];
    userAmberGroup.roles = [DEFAULT_ROLE];
    userAmberGroup.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userAmberGroup.inside_platform_organization = true;
    userAmberGroup.organizations = [platformOrganizationEntity];
  });

  afterAll(async () => {
    await enableCEAndUnSetOrganization();
  });

  it('should RFI under group X org authorized members be protected', async () => {
    const rfiInput: CaseRfiAddInput = {
      name: 'CaseRFI no group restriction IDs',
      created: now(),
      authorized_members: [
        {
          id: platformOrganizationEntity.id,
          access_right: 'admin',
          groups_restriction_ids: [greenGroup.id]
        },
        {
          id: USER_EDITOR.id,
          access_right: 'view',
        },
      ],
      revoked: false
    };
    const requestForInformation = await addCaseRfi(testContext, SYSTEM_USER, rfiInput);
    const result = await findById(testContext, userAmberGroup, requestForInformation.id);
    console.log({ result }); // TODO remove
    expect(result).toBeNull();
  });
  it('should RFI under group X org authorized members be protected', async () => {

  });
});
