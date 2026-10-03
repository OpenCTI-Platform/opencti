import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import { now } from 'moment';
import { GraphQLError } from 'graphql';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { ADMIN_USER, PLATFORM_ORGANIZATION, testContext, TEST_ORGANIZATION, GREEN_GROUP, inPlatformContext } from '../../utils/testQuery';
import type { StixCoreRelationshipAddInput, ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { type BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { addThreatActorIndividual } from '../../../src/modules/threatActorIndividual/threatActorIndividual-domain';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../../src/modules/threatActorIndividual/threatActorIndividual-types';
import type { AuthUser } from '../../../src/types/user';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { DEFAULT_ROLE } from '../../../src/utils/access';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { RELATION_GRANTED_TO } from '../../../src/schema/stixRefRelationship';
import { addStixCoreRelationship, stixCoreRelationshipDelete } from '../../../src/domain/stixCoreRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../src/schema/general';

describe('Middleware test coverage on organization sharing verification', () => {
  let userInPlatformOrg: AuthUser;
  let userInExternalOrg: AuthUser;
  let serviceAccountInExternalOrg: AuthUser;
  let serviceAccountWithoutOrg: AuthUser;
  let externalOrganizationEntity: BasicStoreEntityOrganization;
  let platformOrganizationEntity: BasicStoreEntityOrganization;

  beforeAll(async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);

    platformOrganizationEntity = await getOrganizationEntity(PLATFORM_ORGANIZATION);
    externalOrganizationEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    const greenGroup = await getGroupEntity(GREEN_GROUP);

    userInPlatformOrg = getFakeAuthUser('userInPlatformOrgId');
    userInPlatformOrg.groups = [greenGroup];
    userInPlatformOrg.roles = [DEFAULT_ROLE];
    userInPlatformOrg.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    userInPlatformOrg.organizations = [platformOrganizationEntity];

    userInExternalOrg = getFakeAuthUser('userInExternalOrg');
    userInExternalOrg.groups = [greenGroup];
    userInExternalOrg.roles = [DEFAULT_ROLE];
    userInExternalOrg.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    userInExternalOrg.organizations = [externalOrganizationEntity];

    // Service accounts are always considered inside the platform organization,
    // but their explicitly assigned organizations must still be applied on created data.
    serviceAccountInExternalOrg = getFakeAuthUser('serviceAccountInExternalOrg');
    serviceAccountInExternalOrg.groups = [greenGroup];
    serviceAccountInExternalOrg.roles = [DEFAULT_ROLE];
    serviceAccountInExternalOrg.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    serviceAccountInExternalOrg.organizations = [externalOrganizationEntity];
    serviceAccountInExternalOrg.user_service_account = true;

    // Service account without any organization, data created should not be shared with anyone.
    serviceAccountWithoutOrg = getFakeAuthUser('serviceAccountWithoutOrg');
    serviceAccountWithoutOrg.groups = [greenGroup];
    serviceAccountWithoutOrg.roles = [DEFAULT_ROLE];
    serviceAccountWithoutOrg.capabilities = [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }];
    serviceAccountWithoutOrg.organizations = [];
    serviceAccountWithoutOrg.user_service_account = true;
  });

  afterAll(async () => {
    await unSetOrganization();
  });

  describe('Trying to create an existing entity that is not shared to user should raise a dedicated exception.', () => {
    it('Should raise an AccessRequiredError when entity exists in another organization than the user-s one.', async () => {
      const threatActorIndividualName = `Testing org segregation ${now()}`;
      const inputOne: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by user in org platform',
      };
      const threatActor = await addThreatActorIndividual(inPlatformContext, userInPlatformOrg, inputOne);

      expect(threatActor.id).toBeDefined();
      try {
        const inputNext: ThreatActorIndividualAddInput = {
          name: threatActorIndividualName,
          description: 'Created by external user',
        };
        await addThreatActorIndividual(testContext, userInExternalOrg, inputNext);
        expect(true, 'An exception should been raised before this line').toBeFalsy();
      } catch (e) {
        const exception = e as GraphQLError;
        expect(exception.message).toBe('Restricted entity already exists');
      }
      await stixDomainObjectDelete(testContext, ADMIN_USER, threatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    });

    it('Should raise an UnsupportedError when entity exists in higher marking than the user-s one.', async () => {
      const threatActorIndividualName = `Testing marking segregation ${now()}`;
      const inputOne: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created by user with TLP:RED',
        objectMarking: [MARKING_TLP_RED],
      };
      const threatActor = await addThreatActorIndividual(testContext, ADMIN_USER, inputOne);
      const inputNext: ThreatActorIndividualAddInput = {
        name: threatActorIndividualName,
        description: 'Created again by user with less marking',
      };
      try {
        await addThreatActorIndividual(inPlatformContext, userInPlatformOrg, inputNext);
        expect(true, 'An exception should been raised before this line').toBeFalsy();
      } catch (e) {
        const exception = e as GraphQLError;
        expect(exception.message).toBe('Restricted entity already exists');
      }
      await stixDomainObjectDelete(testContext, ADMIN_USER, threatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    });
  });

  describe('Data created by a service account should be shared with its explicit organizations.', () => {
    it('Should share created entity with the organization assigned to the service account.', async () => {
      const input: ThreatActorIndividualAddInput = {
        name: `Service account organization propagation ${now()}`,
        description: 'Created by a service account member of an external organization',
      };
      const threatActor = await addThreatActorIndividual(inPlatformContext, serviceAccountInExternalOrg, input);
      expect(threatActor.id).toBeDefined();

      const createdThreatActor = await storeLoadById(testContext, ADMIN_USER, threatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
      // The organization assigned to the service account should be granted on the created entity
      expect(createdThreatActor[RELATION_GRANTED_TO]).toContain(externalOrganizationEntity.internal_id);

      await stixDomainObjectDelete(testContext, ADMIN_USER, threatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    });

    it('Should share created relationship with the organization assigned to the service account.', async () => {
      const fromThreatActor = await addThreatActorIndividual(inPlatformContext, serviceAccountInExternalOrg, {
        name: `Service account relationship source ${now()}`,
      });
      const toThreatActor = await addThreatActorIndividual(inPlatformContext, serviceAccountInExternalOrg, {
        name: `Service account relationship target ${now()}`,
      });

      const relationInput: StixCoreRelationshipAddInput = {
        relationship_type: 'related-to',
        fromId: fromThreatActor.id,
        toId: toThreatActor.id,
      };
      const relationship = await addStixCoreRelationship(inPlatformContext, serviceAccountInExternalOrg, relationInput);
      expect(relationship.id).toBeDefined();

      const createdRelationship = await storeLoadById(testContext, ADMIN_USER, relationship.id, ABSTRACT_STIX_CORE_RELATIONSHIP);
      // The organization assigned to the service account should be granted on the created relationship
      expect(createdRelationship[RELATION_GRANTED_TO]).toContain(externalOrganizationEntity.internal_id);

      await stixCoreRelationshipDelete(testContext, ADMIN_USER, relationship.id);
      await stixDomainObjectDelete(testContext, ADMIN_USER, fromThreatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
      await stixDomainObjectDelete(testContext, ADMIN_USER, toThreatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    });

    it('Should not share created entity when the service account has no organization.', async () => {
      const input: ThreatActorIndividualAddInput = {
        name: `Service account without organization ${now()}`,
        description: 'Created by a service account without any organization',
      };
      const threatActor = await addThreatActorIndividual(inPlatformContext, serviceAccountWithoutOrg, input);
      expect(threatActor.id).toBeDefined();

      const createdThreatActor = await storeLoadById(testContext, ADMIN_USER, threatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
      // No organization is assigned to the service account, so nothing should be granted on the created entity
      expect(createdThreatActor[RELATION_GRANTED_TO] ?? []).toHaveLength(0);

      await stixDomainObjectDelete(testContext, ADMIN_USER, threatActor.id, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
    });
  });
});
