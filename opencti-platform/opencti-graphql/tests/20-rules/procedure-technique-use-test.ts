import { describe, expect, it } from 'vitest';
import { addCampaign } from '../../src/domain/campaign';
import { addIntrusionSet } from '../../src/domain/intrusionSet';
import { addAttackPattern } from '../../src/domain/attackPattern';
import { addProcedure } from '../../src/modules/procedure/procedure-domain';
import { createRelation, deleteElementById } from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { RELATION_USES } from '../../src/schema/stixCoreRelationship';
import { RULE_PREFIX } from '../../src/schema/general';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET } from '../../src/schema/stixDomainObject';
import { ENTITY_TYPE_PROCEDURE } from '../../src/modules/procedure/procedure-types';
import ProcedureTechniqueUseRule from '../../src/rules/procedure-technique-use/ProcedureTechniqueUseRule';
import { activateRule, disableRule, getInferences, inferenceLookup } from '../utils/rule-utils';
import { FIVE_MINUTES, testContext, TEN_SECONDS } from '../utils/testQuery';
import { wait } from '../../src/database/utils';

const RULE = RULE_PREFIX + 'procedure_technique_use';

// Only the inferences of this rule, so inferences left by other rules never change the counts.
const ruleInferences = async () => {
  const inferences = await getInferences(RELATION_USES) as unknown as Array<Record<string, unknown>>;
  return inferences.filter((inference) => Array.isArray(inference[RULE]) && (inference[RULE] as unknown[]).length > 0);
};

describe('Procedure technique use rule', () => {
  it('should infer usage of the techniques a used procedure implements', async () => {
    // ---- Create the dataset
    const campaign = await addCampaign(testContext, SYSTEM_USER, { name: 'Procedure rule campaign' });
    const intrusionSet = await addIntrusionSet(testContext, SYSTEM_USER, { name: 'Procedure rule intrusion set' });
    const ap1 = await addAttackPattern(testContext, SYSTEM_USER, { name: 'Procedure rule technique 1', x_mitre_id: 'T9901' });
    const ap2 = await addAttackPattern(testContext, SYSTEM_USER, { name: 'Procedure rule technique 2', x_mitre_id: 'T9902' });
    const p1 = await addProcedure(testContext, SYSTEM_USER, { name: 'Procedure rule procedure', techniques: [ap1.id, ap2.id] });
    const campaignUsesP1 = await createRelation(testContext, SYSTEM_USER, { fromId: campaign.id, toId: p1.id, relationship_type: RELATION_USES });
    // ---- Before activation
    expect(await ruleInferences()).toHaveLength(0);
    await activateRule(ProcedureTechniqueUseRule.id);
    // ---- Rescan: Campaign uses AP1 and AP2, one explanation each, confidence 100
    const afterActivation = await ruleInferences();
    const campaignToAp1 = await inferenceLookup(afterActivation, campaign.standard_id, ap1.standard_id, RELATION_USES);
    expect(campaignToAp1).not.toBeNull();
    expect(campaignToAp1[RULE].length).toBe(1);
    expect(campaignToAp1.confidence).toBe(100);
    const campaignToAp2 = await inferenceLookup(afterActivation, campaign.standard_id, ap2.standard_id, RELATION_USES);
    expect(campaignToAp2).not.toBeNull();
    expect(campaignToAp2[RULE].length).toBe(1);
    // ---- Live: Intrusion-Set uses P1 after activation
    const intrusionSetUsesP1 = await createRelation(testContext, SYSTEM_USER, { fromId: intrusionSet.id, toId: p1.id, relationship_type: RELATION_USES });
    await wait(TEN_SECONDS);
    const afterLive = await ruleInferences();
    expect(await inferenceLookup(afterLive, intrusionSet.standard_id, ap1.standard_id, RELATION_USES)).not.toBeNull();
    expect(await inferenceLookup(afterLive, intrusionSet.standard_id, ap2.standard_id, RELATION_USES)).not.toBeNull();
    // The procedure itself never gets a uses to the technique
    expect(await inferenceLookup(afterLive, p1.standard_id, ap1.standard_id, RELATION_USES)).toBeNull();
    // ---- Disable
    await disableRule(ProcedureTechniqueUseRule.id);
    expect(await ruleInferences()).toHaveLength(0);
    // ---- Clean
    await deleteElementById(testContext, SYSTEM_USER, intrusionSetUsesP1.internal_id, RELATION_USES);
    await deleteElementById(testContext, SYSTEM_USER, campaignUsesP1.internal_id, RELATION_USES);
    await deleteElementById(testContext, SYSTEM_USER, p1.internal_id, ENTITY_TYPE_PROCEDURE);
    await deleteElementById(testContext, SYSTEM_USER, ap1.internal_id, ENTITY_TYPE_ATTACK_PATTERN);
    await deleteElementById(testContext, SYSTEM_USER, ap2.internal_id, ENTITY_TYPE_ATTACK_PATTERN);
    await deleteElementById(testContext, SYSTEM_USER, intrusionSet.internal_id, ENTITY_TYPE_INTRUSION_SET);
    await deleteElementById(testContext, SYSTEM_USER, campaign.internal_id, ENTITY_TYPE_CAMPAIGN);
  }, FIVE_MINUTES);
});
