import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { getActivatedRules, getRules, setRuleActivation } from '../../../src/domain/rules';
import ParticipateToPartsRule from '../../../src/rules/participate-to-parts/ParticipateToPartsRule';
import { EVENT_TYPE_CREATE, READ_RELATIONSHIPS_INDICES } from '../../../src/database/utils';
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
import type { BasicStoreRelation } from '../../../src/types/store';
import { listAllRelations } from '../../../src/database/middleware-loader';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';

describe('ParticipateToPartsRule tests', () => {
  let allActivatedRules: RuleRuntime[];
  beforeAll(async () => {
    // Disable all rules
    allActivatedRules = await getActivatedRules(testContext, ADMIN_USER);
    for (let i = 0; i < allActivatedRules.length; i += 1) {
      const rule = allActivatedRules[i];
      await setRuleActivation(testContext, ADMIN_USER, rule.id, false);
    }
  });

  afterAll(async () => {
    // BACK to what it was before test
    // await setRuleActivation(testContext, ADMIN_USER, ParticipateToPartsRule.id, false);
    for (let i = 0; i < allActivatedRules.length; i += 1) {
      const rule = allActivatedRules[i];
      await setRuleActivation(testContext, ADMIN_USER, rule.id, true);
    }
  });

  it('should sector not be added as organisation on users', async () => {
    // ----------------
    // GIVEN an Organization A that has relation "part of" with a sector
    // GIVEN an Organization A that has relation "part of" with an organization B
    // AND ParticipateToPartsRule is enabled
    // AND a user that is in the organization "Organization A"
    const ruleRuntimeAll: RuleRuntime[] = await getRules(testContext, ADMIN_USER);
    const testOrgA = await addOrganization(testContext, ADMIN_USER, { name: 'RuleTestOrgA' });
    const testOrgB = await addOrganization(testContext, ADMIN_USER, { name: 'RuleTestOrgB' });
    const testSector = await addSector(testContext, ADMIN_USER, { name: 'SectorTestOrg' });
    const relPartOfOrg = await addStixCoreRelationship(testContext, ADMIN_USER, { fromId: testOrgA.id, toId: testOrgB.id, relationship_type: 'part-of' });
    const relPartOfSector = await addStixCoreRelationship(testContext, ADMIN_USER, { fromId: testOrgA.id, toId: testSector.id, relationship_type: 'part-of' });

    const userInput: UserAddInput = {
      name: `User for ParticipateToPartsRule ${Date.now()}`,
      password: 'youshallnotbeinsector',
      user_email: 'user.ParticipateToPartsRule@opencti.invalid',
      objectOrganization: [testOrgA.id]
    };
    const userInOrgA: AuthUser = await addUser(testContext, ADMIN_USER, userInput);

    // ----------------
    // WHEN rule is applied on event "create participate-to from user to orgA"
    // (Triggering manually rule on this event)
    const userRelationsParticipateTo = await listAllRelations(testContext, ADMIN_USER, RELATION_PARTICIPATE_TO, { fromId: userInOrgA.internal_id, toId: testOrgA.internal_id });
    expect(userRelationsParticipateTo.length).toBe(1); // at this point the only rel should be user --> orgA since rule are disabled
    const relUserParticipateToOrgAData = await stixLoadById(testContext, RULE_MANAGER_USER, userRelationsParticipateTo[0].id) as StixCoreObject;
    const eventRelUserParticipateToOrgAData = buildInternalEvent(EVENT_TYPE_CREATE, relUserParticipateToOrgAData);
    const relPartOfOrgStix = await stixLoadById(testContext, RULE_MANAGER_USER, relPartOfOrg.id) as StixCoreObject;
    const eventPartOfOrg = buildInternalEvent(EVENT_TYPE_CREATE, relPartOfOrgStix);
    const relPartOfSectorStix = await stixLoadById(testContext, RULE_MANAGER_USER, relPartOfSector.id) as StixCoreObject;
    const eventPartOfSector = buildInternalEvent(EVENT_TYPE_CREATE, relPartOfSectorStix);

    // Apply rule on all relation creation events
    await rulesApplyHandler(testContext, RULE_MANAGER_USER, [eventRelUserParticipateToOrgAData, eventPartOfOrg, eventPartOfSector], ruleRuntimeAll.filter((rule) => rule.id === ParticipateToPartsRule.id));

    // ----------------
    // THEN Organization B has rel with user
    // AND Sector has no relation with user
    const userAuthAfter = await findUserById(testContext, ADMIN_USER, userInOrgA.id);

    const allUserRelations = await listAllRelations<BasicStoreRelation>(testContext, userAuthAfter, [RELATION_PARTICIPATE_TO], { indices: READ_RELATIONSHIPS_INDICES });
    const currentUserParticipateTo = allUserRelations.filter((rel) => rel.fromId === userAuthAfter.id);

    expect(currentUserParticipateTo.filter((rel) => rel.toId === testOrgA.id).length).toBe(1); // Direct organization
    expect(currentUserParticipateTo.filter((rel) => rel.toId === testOrgB.id).length).toBe(1); // Organization because of rule OrgB --part of --> OrgA
    expect(currentUserParticipateTo.filter((rel) => rel.toId === testSector.id).length).toBe(0); // Sector not there even if Sector --part of --> OrgA
  });
});
