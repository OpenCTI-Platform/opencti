import { describe, it } from 'vitest';
import { buildInternalEvent, rulesApplyHandler } from '../../../src/manager/ruleManager';
import type { DataEvent } from '../../../src/types/event';
import type { RuleRuntime } from '../../../src/types/rules';
import { testContext } from '../../utils/testQuery';
import { RULE_MANAGER_USER } from '../../../src/utils/access';
import { setRuleActivation } from '../../../src/domain/rules';
import ParticipateToPartsRule from '../../../src/rules/participate-to-parts/ParticipateToPartsRule';
import { stixLoadById } from '../../../src/database/middleware';
import { EVENT_TYPE_CREATE } from '../../../src/database/utils';
import StixCoreObject from '../../data/filter-keys-schema/stix-core-object';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { addSector } from '../../../src/domain/sector';

describe('ParticipateToPartsRule tests', () => {
  it('should sector not be added as organisation on users', async () => {
    // GIVEN an Organization that has relation "part of" with a sector
    // AND ParticipateToPartsRule is enabled

    const testOrg = await addOrganization(testContext, RULE_MANAGER_USER, { name: 'RuleTestOrg' });
    const testSector = await addSector(testContext, RULE_MANAGER_USER, { name: 'SectorTestOrg' });

    await setRuleActivation(testContext, RULE_MANAGER_USER, ParticipateToPartsRule.id, true);

    const events: Array<DataEvent> = [];
    const forRules: Array<RuleRuntime> = [];

    const data = await stixLoadById(testContext, RULE_MANAGER_USER, elementId) as StixCoreObject;
    const event = buildInternalEvent(EVENT_TYPE_CREATE, data);

    await rulesApplyHandler(testContext, RULE_MANAGER_USER, events, forRules);
  });
});
