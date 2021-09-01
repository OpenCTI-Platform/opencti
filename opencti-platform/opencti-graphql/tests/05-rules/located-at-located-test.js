import { shutdownModules, startModules } from '../../src/modules';
import { FIVE_MINUTES, sleep } from '../utils/testQuery';
import {
  createRelation,
  deleteElement,
  internalLoadById,
  listEntities,
  listRelations,
} from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { ENTITY_TYPE_TASK } from '../../src/schema/internalObject';
import { READ_INDEX_INFERRED_RELATIONSHIPS } from '../../src/database/utils';
import { RELATION_LOCATED_AT } from '../../src/schema/stixCoreRelationship';
import { setRuleActivation } from '../../src/manager/ruleManager';
import { LocatedAtLocatedRule } from '../../src/rules/located-at-located/LocatedAtLocatedRule';
import { addCity } from '../../src/domain/city';

const FRANCE = 'location--b8d0549f-de06-5ebd-a6e9-d31a581dba5d';
const HIETZING = 'location--ce920c5b-03ea-576d-ac1d-701d9d7a1bed';
const WESTERN_EUROPE = 'location--a25f43bf-3e2d-55fe-ba09-c63a210f169d';
const EUROPE = 'location--2e9ef300-a1ab-5c9f-9297-dde66b71cae2';
const TLP_WHITE = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';

describe('Located at located rule', () => {
  const inferenceLookup = async (inferences, fromStandardId, toStandardId, type) => {
    for (let index = 0; index < inferences.length; index += 1) {
      const inference = inferences[index];
      const from = await internalLoadById(SYSTEM_USER, inference.fromId);
      const to = await internalLoadById(SYSTEM_USER, inference.toId);
      const sameFrom = from.standard_id === fromStandardId;
      const sameTo = to.standard_id === toStandardId;
      const sameType = inference.relationship_type === type;
      if (sameFrom && sameTo && sameType) {
        return inference;
      }
    }
    return null;
  };
  const getInferences = (type) => {
    const relArgs = { indices: [READ_INDEX_INFERRED_RELATIONSHIPS], connectionFormat: false };
    return listRelations(SYSTEM_USER, type, relArgs);
  };
  const changeRule = async (ruleId, active) => {
    // Change the status
    await setRuleActivation(SYSTEM_USER, ruleId, active);
    // Wait for rule to finish activation
    let ruleActivated = false;
    while (ruleActivated !== true) {
      const tasks = await listEntities(SYSTEM_USER, [ENTITY_TYPE_TASK], { connectionFormat: false });
      const allDone = tasks.filter((t) => !t.completed).length === 0;
      tasks.forEach((t) => {
        expect(t.errors.length).toBe(0);
      });
      ruleActivated = allDone;
      // Wait for eventual inferences of inferences to be created
      await sleep(5000);
    }
  };
  const activateRule = async (ruleId) => changeRule(ruleId, true);
  const disableRule = (ruleId) => changeRule(ruleId, false);

  // eslint-disable-next-line prettier/prettier
  it('Should rule successfully activated', async () => {
      await startModules();
      // Check that no inferences exists
      const beforeActivationRelations = await getInferences(RELATION_LOCATED_AT);
      expect(beforeActivationRelations.length).toBe(0);
      // ---- base
      // HIETZING > located-in > FRANCE
      // FRANCE > located-in > WESTERN EUROPE
      // WESTERN EUROPE > located-in > EUROPE
      // ---- inferences that will be created
      // HIETZING > located-in > WESTERN EUROPE
      // HIETZING > located-in > EUROPE (2 explanations)
      // FRANCE > located-in > EUROPE
      // Activate rules
      await activateRule(LocatedAtLocatedRule.id);
      // Check database state
      const afterActivationRelations = await getInferences(RELATION_LOCATED_AT);
      expect(afterActivationRelations.length).toBe(3);
      // eslint-disable-next-line prettier/prettier
      const hietzingToWesternEurope = await inferenceLookup(afterActivationRelations, HIETZING, WESTERN_EUROPE, RELATION_LOCATED_AT);
      expect(hietzingToWesternEurope.length).not.toBeNull();
      const hietzingToEurope = await inferenceLookup(afterActivationRelations, HIETZING, EUROPE, RELATION_LOCATED_AT);
      expect(hietzingToEurope.length).not.toBeNull();
      expect(hietzingToEurope.i_rule_location_location.length).toBe(2);
      const franceToEurope = await inferenceLookup(afterActivationRelations, FRANCE, EUROPE, RELATION_LOCATED_AT);
      expect(franceToEurope.length).not.toBeNull();
      // Create new element to trigger a live event
      // ---- base
      // PARIS > located-in > FRANCE
      // ---- inferences that will be created
      // PARIS > located-in > WESTERN EUROPE
      // PARIS > located-in > EUROPE (2 explanations)
      const paris = await addCity(SYSTEM_USER, { name: 'Paris' });
      const parisLocatedToFrance = await createRelation(SYSTEM_USER, {
        fromId: paris.id,
        toId: FRANCE,
        relationship_type: RELATION_LOCATED_AT,
        objectMarking: [TLP_WHITE],
      });
      await sleep(2000); // let some time to rule manager to create the elements
      // Check the inferences
      const afterLiveRelations = await getInferences(RELATION_LOCATED_AT);
      expect(afterLiveRelations.length).toBe(5);
      // Inferences must have the markings of the initial one

      // Remove the relation must remove the inferences
      await deleteElement(SYSTEM_USER, parisLocatedToFrance);
      await sleep(2000); // let some time to rule manager to delete the elements
      const afterRelDeletionRelations = await getInferences(RELATION_LOCATED_AT);
      expect(afterRelDeletionRelations.length).toBe(3);
      // Recreate the relation
      await createRelation(SYSTEM_USER, {
        fromId: paris.id,
        toId: FRANCE,
        relationship_type: RELATION_LOCATED_AT,
      });
      await sleep(2000); // let some time to rule manager to create the elements
      const afterRecreationRelations = await getInferences(RELATION_LOCATED_AT);
      expect(afterRecreationRelations.length).toBe(5);
      // Remove the city
      await deleteElement(SYSTEM_USER, paris);
      await sleep(2000); // let some time to rule manager to delete the elements
      const afterParisDeletionRelations = await getInferences(RELATION_LOCATED_AT);
      expect(afterParisDeletionRelations.length).toBe(3);
      // Disable the rule
      await disableRule(LocatedAtLocatedRule.id);
      // Check the number of inferences
      const afterDisableRelations = await getInferences(RELATION_LOCATED_AT);
      expect(afterDisableRelations.length).toBe(0);
      // Stop modules
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
