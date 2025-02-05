import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { now } from 'moment';
import { GraphQLError } from 'graphql/index';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { ADMIN_USER, PLATFORM_ORGANIZATION, testContext, TEST_ORGANIZATION, GREEN_GROUP } from '../../utils/testQuery';
import type { ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { type BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { addThreatActorIndividual } from '../../../src/modules/threatActorIndividual/threatActorIndividual-domain';
import type { AuthUser } from '../../../src/types/user';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { isFeatureEnabled, ORGA_SHARING_REQUEST_FF } from '../../../src/config/conf';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { DEFAULT_ROLE } from '../../../src/utils/access';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';

describe('Middleware test coverage on organization sharing verification', () => {
  let userInPlatformOrg: AuthUser;
  let userInExternalOrg: AuthUser;
  let externalOrganizationEntity: BasicStoreEntityOrganization;
  let platformOrganizationEntity: BasicStoreEntityOrganization;

  beforeAll(async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);

    platformOrganizationEntity = await getOrganizationEntity(PLATFORM_ORGANIZATION);
    externalOrganizationEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    const greenGroup = await getGroupEntity(GREEN_GROUP);

    userInPlatformOrg = getFakeAuthUser('userInPlatformOrgId');
    userInPlatformOrg.groups = [greenGroup];
    userInPlatformOrg.roles = [DEFAULT_ROLE];
    userInPlatformOrg.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userInPlatformOrg.inside_platform_organization = true;
    userInPlatformOrg.organizations = [platformOrganizationEntity];

    userInExternalOrg = getFakeAuthUser('userInPlatformOrgId');
    userInExternalOrg.groups = [greenGroup];
    userInExternalOrg.roles = [DEFAULT_ROLE];
    userInExternalOrg.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }];
    userInExternalOrg.inside_platform_organization = false;
    userInExternalOrg.organizations = [externalOrganizationEntity];
  });

  afterAll(async () => {
    await enableCEAndUnSetOrganization();
  });

  describe('Trying to create an existing entity that is not shared to user should raise a dedicated exception.', () => {
    it('Should raise an AccessRequiredError when entity exists in another organization than the user-s one.', async () => {
      const threatActorIndividualName = `Testing org segregation ${now()}`;
      const inputOne: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by user in org platform'
      };
      const threatActor = await addThreatActorIndividual(testContext, userInPlatformOrg, inputOne);

      expect(threatActor.id).toBeDefined();
      try {
        const inputNext: ThreatActorIndividualAddInput = {
          name: threatActorIndividualName,
          description: 'Created by external user'
        };
        await addThreatActorIndividual(testContext, userInExternalOrg, inputNext);
        expect(true, 'An exception should been raised before this line').toBeFalsy();
      } catch (e) {
        const exception = e as GraphQLError;
        if (isFeatureEnabled(ORGA_SHARING_REQUEST_FF)) {
          expect(exception.message).toBe('Restricted entity already exists, user can request access');
        } else {
          expect(exception.message).toBe('Restricted entity already exists');
        }
      }
      await stixDomainObjectDelete(testContext, ADMIN_USER, threatActor.id);
    });

    it('Should raise an UnsupportedError when entity exists in higher marking than the user-s one.', async () => {
      const threatActorIndividualName = `Testing marking segregation ${now()}`;
      const inputOne: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by user with TLP:RED',
        objectMarking: [MARKING_TLP_RED]
      };
      const threatActor = await addThreatActorIndividual(testContext, ADMIN_USER, inputOne);
      const inputNext: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created again by user with less marking',
      };
      try {
        await addThreatActorIndividual(testContext, userInPlatformOrg, inputNext);
        expect(true, 'An exception should been raised before this line').toBeFalsy();
      } catch (e) {
        const exception = e as GraphQLError;
        expect(exception.message).toBe('Restricted entity already exists');
      }
      await stixDomainObjectDelete(testContext, ADMIN_USER, threatActor.id);
    });
  });
});
