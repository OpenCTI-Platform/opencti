import { describe, expect, it } from 'vitest';
import { now } from 'moment';
import { GraphQLError } from 'graphql/index';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { ADMIN_USER, GREEN_DISINFORMATION_ANALYST_GROUP, PLATFORM_ORGANIZATION, testContext } from '../../utils/testQuery';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import type { InternalRelationshipAddInput, OrganizationAddInput, ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { addUser, assignOrganizationToUser, findById as findUserById, userAddRelation, userDelete } from '../../../src/domain/user';
import { type BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { addThreatActorIndividual } from '../../../src/modules/threatActorIndividual/threatActorIndividual-domain';
import { addOrganizationRestriction } from '../../../src/domain/stix';
import type { AuthUser } from '../../../src/types/user';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../../src/modules/entitySetting/entitySetting-types';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { isFeatureEnabled, ORGA_SHARING_REQUEST_FF } from '../../../src/config/conf';

describe('Middleware test coverage on organization sharing verification', () => {
  let externalOrg: BasicStoreEntityOrganization;
  let userInPlatformOrg: AuthUser;
  let userInExternalOrg: AuthUser;

  describe('Trying to create an existing entity that is not shared to user should raise a dedicated exception.', () => {
    it('INIT - Should set platform organization and create one user in organization, one in another organization', async () => {
      await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
      const org: OrganizationAddInput = {
        name: 'ITWomen'
      };
      externalOrg = await addOrganization(testContext, ADMIN_USER, org);

      resetCacheForEntity(ENTITY_TYPE_ENTITY_SETTING);

      const userInExternalOrgInput = {
        password: 'changeme',
        user_email: 'grace.hopper@opencti.ext',
        name: 'Grace Hopper',
        firstname: 'Grace',
        lastname: 'Hopper'
      };
      const userInExternalOrgEntity = await addUser(testContext, ADMIN_USER, userInExternalOrgInput);
      await assignOrganizationToUser(testContext, ADMIN_USER, userInExternalOrgEntity.internal_id, externalOrg.id);

      // Marking: TLP:GREEN
      const userToGroupInput: InternalRelationshipAddInput = {
        relationship_type: 'member-of',
        toId: GREEN_DISINFORMATION_ANALYST_GROUP.id
      };
      await userAddRelation(testContext, ADMIN_USER, userInExternalOrgEntity.internal_id, userToGroupInput);
      userInExternalOrg = await findUserById(testContext, ADMIN_USER, userInExternalOrgEntity.id);
      expect(userInExternalOrg.inside_platform_organization).toBeFalsy();

      const userInPlatformOrgInput = {
        password: 'changeme',
        user_email: 'alan.turing@opencti.ext',
        name: 'Alan Turing',
        firstname: 'Alan',
        lastname: 'Turing'
      };
      const userInPlatformOrgEntity = await addUser(testContext, ADMIN_USER, userInPlatformOrgInput);
      await assignOrganizationToUser(testContext, ADMIN_USER, userInPlatformOrgEntity.internal_id, PLATFORM_ORGANIZATION.id);
      await userAddRelation(testContext, ADMIN_USER, userInPlatformOrgEntity.internal_id, userToGroupInput);
      userInPlatformOrg = await findUserById(testContext, ADMIN_USER, userInPlatformOrgEntity.id);
      expect(userInPlatformOrg.inside_platform_organization).toBeTruthy();
    });

    it('Should raise an AccessRequiredError when entity exists in another organization than the user-s one.', async () => {
      const threatActorIndividualName = `Testing org segregagtion ${now()}`;
      const inputOne: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by user in org platform'
      };
      const threatActor = await addThreatActorIndividual(testContext, userInPlatformOrg, inputOne);
      await addOrganizationRestriction(testContext, ADMIN_USER, threatActor.id, PLATFORM_ORGANIZATION.id);

      const inputNext: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by external user'
      };
      try {
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
    });

    it('Should raise an UnsupportedError when entity exists in higher marking than the user-s one.', async () => {
      const threatActorIndividualName = `Testing marking segregation ${now()}`;
      const inputOne: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by user with TLP:RED',
        objectMarking: [MARKING_TLP_RED]
      };
      await addThreatActorIndividual(testContext, ADMIN_USER, inputOne);
      // await waitInSec(300);
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
    });

    it('CLEANUP - Should remove user and platform orga', async () => {
      await userDelete(testContext, ADMIN_USER, userInExternalOrg.id);
      await userDelete(testContext, ADMIN_USER, userInPlatformOrg.id);
      await enableCEAndUnSetOrganization();
    });
  });
});
