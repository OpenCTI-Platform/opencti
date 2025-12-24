import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import { now } from 'moment';
import { GraphQLError } from 'graphql/index';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { ADMIN_USER, PLATFORM_ORGANIZATION, testContext, TEST_ORGANIZATION, GREEN_GROUP, inPlatformContext } from '../../utils/testQuery';
import type { ThreatActorIndividualAddInput } from '../../../src/generated/graphql';
import { type BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { addThreatActorIndividual } from '../../../src/modules/threatActorIndividual/threatActorIndividual-domain';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../../src/modules/threatActorIndividual/threatActorIndividual-types';
import type { AuthUser } from '../../../src/types/user';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { DEFAULT_ROLE } from '../../../src/utils/access';
import { getFakeAuthUser, getGroupEntity, getOrganizationEntity } from '../../utils/domainQueryHelper';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

describe('Middleware test coverage on organization sharing verification', () => {
  let userInPlatformOrg: AuthUser;
  let userInExternalOrg: AuthUser;
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
  });

  afterAll(async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
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
});
