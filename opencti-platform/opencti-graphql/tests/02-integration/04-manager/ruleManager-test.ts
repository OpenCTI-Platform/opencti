import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { getRules, setRuleActivation } from '../../../src/domain/rules';
import ParticipateToPartsRule from '../../../src/rules/participate-to-parts/ParticipateToPartsRule';
import { EVENT_TYPE_CREATE, waitInSec } from '../../../src/database/utils';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { addSector } from '../../../src/domain/sector';
import { addUser, findById as findUserById } from '../../../src/domain/user';
import type { AuthUser } from '../../../src/types/user';
import type { UserAddInput } from '../../../src/generated/graphql';
import { addStixCoreRelationship } from '../../../src/domain/stixCoreRelationship';
import { stixLoadById } from '../../../src/database/middleware';
import { RULE_MANAGER_USER } from '../../../src/utils/access';
import { buildInternalEvent, rulesApplyHandler } from '../../../src/manager/ruleManager';
import type { StixCoreObject } from '../../../src/types/stix-2-1-common';
import type { RuleRuntime } from '../../../src/types/rules';
import type { BasicStoreEntity } from '../../../src/types/store';

describe('ParticipateToPartsRule tests', () => {
  it('should sector not be added as organisation on users', async () => {
    // GIVEN an Organization A that has relation "part of" with a sector
    // GIVEN an Organization A that has relation "part of" with an organization B
    // AND ParticipateToPartsRule is enabled
    // AND a user that is in the organization "Organization A"
    await setRuleActivation(testContext, ADMIN_USER, ParticipateToPartsRule.id, true);
    const ruleRuntimeAll: RuleRuntime[] = await getRules(testContext, ADMIN_USER);
    const testOrgA = await addOrganization(testContext, ADMIN_USER, { name: 'RuleTestOrgA' });
    const testOrgB = await addOrganization(testContext, ADMIN_USER, { name: 'RuleTestOrgB' });
    const testSector = await addSector(testContext, ADMIN_USER, { name: 'SectorTestOrg' });
    await addStixCoreRelationship(testContext, ADMIN_USER, { fromId: testOrgA.id, toId: testOrgB.id, relationship_type: 'part-of' });
    await addStixCoreRelationship(testContext, ADMIN_USER, { fromId: testOrgA.id, toId: testSector.id, relationship_type: 'part-of' });

    const userInput: UserAddInput = {
      name: `User for ParticipateToPartsRule ${Date.now()}`,
      password: 'youshallnotbeinsector',
      user_email: 'user.ParticipateToPartsRule@opencti.invalid',
      objectOrganization: [testOrgA.id]
    };
    const userInOrgA: AuthUser = await addUser(testContext, ADMIN_USER, userInput);

    // WHEN the ParticipateToPartsRule is applied
    const orgAData: StixCoreObject = await stixLoadById(testContext, RULE_MANAGER_USER, testOrgA.id) as StixCoreObject;
    const eventOrgAData = buildInternalEvent(EVENT_TYPE_CREATE, orgAData);
    const orgBData: StixCoreObject = await stixLoadById(testContext, RULE_MANAGER_USER, testOrgB.id) as StixCoreObject;
    const eventOrgBData = buildInternalEvent(EVENT_TYPE_CREATE, orgBData);
    const sectorData: StixCoreObject = await stixLoadById(testContext, RULE_MANAGER_USER, testSector.id) as StixCoreObject;
    const eventSectorData = buildInternalEvent(EVENT_TYPE_CREATE, sectorData);

    await rulesApplyHandler(testContext, RULE_MANAGER_USER, [eventOrgAData, eventOrgBData, eventSectorData], ruleRuntimeAll.filter((rule) => rule.id === ParticipateToPartsRule.id));
    await waitInSec(2); // need to wait ES data update

    // THEN Organization B has rel with user
    // AND Sector has no relation with user
    const userAuth = await findUserById(testContext, ADMIN_USER, userInOrgA.id);
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testOrgA.id).length).toBe(1); // Direct organization
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testOrgB.id).length).toBe(1); // Organization because of rule OrgB --part of --> OrgA
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testSector.id).length).toBe(0); // Sector not there even if Sector --part of --> OrgA
    expect(userAuth.organizations.length).toBe(2);
  });
});
