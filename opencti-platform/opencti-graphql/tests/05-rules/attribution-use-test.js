import { expect, it, describe } from 'vitest';
import { shutdownModules, startModules } from '../../src/modules';
import { addThreatActor } from '../../src/domain/threatActor';
import { SYSTEM_USER } from '../../src/utils/access';
import { createRelation, internalDeleteElementById } from '../../src/database/middleware';
import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../src/schema/stixCoreRelationship';
import { RULE_PREFIX } from '../../src/schema/general';
import AttributionUseRule from '../../src/rules/attribution-use/AttributionUseRule';
import { activateRule, disableRule, getInferences, inferenceLookup } from '../utils/rule-utils';
import { FIVE_MINUTES, testContext, TEN_SECONDS } from '../utils/testQuery';
import { wait } from '../../src/database/utils';

const RULE = RULE_PREFIX + AttributionUseRule.id;
const APT41 = 'intrusion-set--d12c5319-f308-5fef-9336-20484af42084';
const PARADISE_RANSOMWARE = 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714';
const SPELEVO = 'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85';
const TLP_CLEAR_ID = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';

describe('Attribute use rule', () => {
  it(
    'Should rule successfully activated',
    async () => {
      // Start
      await startModules();
      await wait(2 * TEN_SECONDS); // Wait for all managers to be started
      // ---- Create the dataset
      // 01. Create a threat actor
      const threat = await addThreatActor(testContext, SYSTEM_USER, { name: 'MY TREAT ACTOR' });
      const MY_THREAT = threat.standard_id;
      // 02. Create require relation
      // APT41 -> attributed to -> MY TREAT ACTOR
      await createRelation(testContext, SYSTEM_USER, {
        fromId: APT41,
        toId: threat.id,
        start_time: '2020-01-20T20:30:00.000Z',
        stop_time: '2020-02-29T14:00:00.000Z',
        confidence: 10,
        relationship_type: RELATION_ATTRIBUTED_TO,
        objectMarking: [TLP_CLEAR_ID],
      });
      // ---- Rule execution
      // Check that no inferences exists
      const beforeActivationRelations = await getInferences(RELATION_USES);
      expect(beforeActivationRelations.length).toBe(0);
      // Activate rules
      await activateRule(AttributionUseRule.id);
      // Check database state
      const afterActivationRelations = await getInferences(RELATION_USES);
      expect(afterActivationRelations.length).toBe(1);
      const myThreatToParadise = await inferenceLookup(afterActivationRelations, MY_THREAT, PARADISE_RANSOMWARE, RELATION_USES);
      expect(myThreatToParadise).not.toBeNull();
      expect(myThreatToParadise[RULE].length).toBe(1);
      expect(myThreatToParadise.confidence).toBe(20); // AVG 2 relations (30 + 10) = 20
      expect(myThreatToParadise.start_time).toBe('2020-02-28T23:00:00.000Z');
      expect(myThreatToParadise.stop_time).toBe('2020-02-29T14:00:00.000Z');
      // Create new element to trigger a live event
      // ---- base
      // APT41 -> uses -> Spelevo (start: 2020-01-10T20:30:00.000Z, stop: 2020-02-19T14:00:00.000Z, confidence: 30)
      const aptUseSpelevo = await createRelation(testContext, SYSTEM_USER, {
        fromId: APT41,
        toId: SPELEVO,
        start_time: '2020-01-10T20:30:00.000Z',
        stop_time: '2020-02-28T14:00:00.000Z',
        confidence: 90,
        relationship_type: RELATION_USES,
        objectMarking: [TLP_CLEAR_ID],
      });
      await wait(TEN_SECONDS); // let some time to rule manager to create the elements
      // Check the inferences
      const afterLiveRelations = await getInferences(RELATION_USES);
      expect(afterLiveRelations.length).toBe(2);
      const myThreatToSpelevo = await inferenceLookup(afterLiveRelations, MY_THREAT, SPELEVO, RELATION_USES);
      expect(myThreatToSpelevo).not.toBeNull();
      expect(myThreatToSpelevo[RULE].length).toBe(1);
      expect(myThreatToSpelevo.confidence).toBe(50); // AVG 2 relations (90 + 10) = 50
      expect(myThreatToSpelevo.start_time).toBe('2020-01-20T20:30:00.000Z');
      expect(myThreatToSpelevo.stop_time).toBe('2020-02-28T14:00:00.000Z');
      // Disable the rule
      await disableRule(AttributionUseRule.id);
      // Check the number of inferences
      const afterDisableRelations = await getInferences(RELATION_USES);
      expect(afterDisableRelations.length).toBe(0);
      // Clean
      await internalDeleteElementById(testContext, SYSTEM_USER, aptUseSpelevo.internal_id);
      await internalDeleteElementById(testContext, SYSTEM_USER, threat.internal_id);
      // Stop
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
