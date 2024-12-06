import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { now } from 'moment';
import { GraphQLError } from 'graphql/index';
import { enableCEAndUnSetOrganization, enableEEAndSetPlatformOrganization, getOrganizationEntity } from '../../utils/testQueryHelper';
import { ADMIN_USER, PLATFORM_ORGANIZATION, EXTERNAL_ORGANIZATION, testContext, getUserIdByEmail, EXTERNAL_USER_ANALYST, USER_DISINFORMATION_ANALYST } from '../../utils/testQuery';
import type { ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { type BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { addThreatActorIndividual } from '../../../src/modules/threatActorIndividual/threatActorIndividual-domain';
import type { AuthUser } from '../../../src/types/user';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { isFeatureEnabled, ORGA_SHARING_REQUEST_FF } from '../../../src/config/conf';
import { findById as findUserById } from '../../../src/domain/user';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';

describe('Middleware test coverage on organization sharing verification', () => {
  let userInPlatformOrg: AuthUser;
  let userInExternalOrg: AuthUser;
  let externalOrganizationEntity: BasicStoreEntityOrganization;
  let platformOrganizationEntity: BasicStoreEntityOrganization;

  beforeAll(async () => {
    await enableEEAndSetPlatformOrganization();

    platformOrganizationEntity = await getOrganizationEntity(PLATFORM_ORGANIZATION);
    externalOrganizationEntity = await getOrganizationEntity(EXTERNAL_ORGANIZATION);
    expect(platformOrganizationEntity?.id).toBeDefined();
    expect(externalOrganizationEntity?.id).toBeDefined();

    const userInPlatformOrgId = await getUserIdByEmail(USER_DISINFORMATION_ANALYST.email);
    userInPlatformOrg = await findUserById(testContext, ADMIN_USER, userInPlatformOrgId);
    expect(userInPlatformOrg?.id, 'USER_DISINFORMATION_ANALYST is badly configured').toBeDefined();
    expect(userInPlatformOrg?.organizations.length, 'USER_DISINFORMATION_ANALYST organizations is badly configured').toBe(1);
    const userInPlatformOrgOrganization = userInPlatformOrg?.organizations[0] as BasicStoreEntityOrganization;
    expect(userInPlatformOrgOrganization.name, 'USER_DISINFORMATION_ANALYST organizations is badly configured').toBe(PLATFORM_ORGANIZATION.name);

    const userInExternalOrgId = await getUserIdByEmail(EXTERNAL_USER_ANALYST.email);
    userInExternalOrg = await findUserById(testContext, ADMIN_USER, userInExternalOrgId);
    expect(userInExternalOrg?.id, 'EXTERNAL_USER_ANALYST is badly configured').toBeDefined();
    expect(userInExternalOrg?.organizations.length, 'EXTERNAL_USER_ANALYST organizations is badly configured').toBe(1);
    const userInExternalOrgOrganization = userInExternalOrg?.organizations[0] as BasicStoreEntityOrganization;
    expect(userInExternalOrgOrganization.name, 'EXTERNAL_USER_ANALYST organizations is badly configured').toBe(EXTERNAL_ORGANIZATION.name);
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
