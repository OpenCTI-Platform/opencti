// 'If **indicator A** has `revoked` **false** and **indicator A** is `sighted` in ' +
// '**identity B**, then create **Incident C** `related-to` **indicator A** and ' +
// '`targets` **identity B**.';

import { expect, it, describe } from 'vitest';
import * as R from 'ramda';
import { FIVE_MINUTES, testContext, TEN_SECONDS } from '../utils/testQuery';
import { shutdownModules, startModules } from '../../src/modules';
import { activateRule, disableRule, getInferences } from '../utils/rule-utils';
import { patchAttribute } from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INDICATOR } from '../../src/schema/stixDomainObject';
import RuleSightingIncident from '../../src/rules/sighting-incident/SightingIncidentRule';
import { RELATION_RELATED_TO, RELATION_TARGETS } from '../../src/schema/stixCoreRelationship';
import { internalLoadById, listRelations } from '../../src/database/middleware-loader';
import { RELATION_OBJECT_MARKING } from '../../src/schema/stixMetaRelationship';
import { wait } from '../../src/database/utils';

const TLP_CLEAR_ID = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';
const ONE_CLAP = 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752'; // indicator A

describe('Sighting incident rule', () => {
  const assertInferencesSize = async (type, expected) => {
    await wait(TEN_SECONDS); // let some time to rule manager to create the elements
    const inferences = await getInferences(type);
    expect(inferences.length).toBe(expected);
    return inferences;
  };

  it(
    'Should rule successfully activated',
    async () => {
      // ---- 01. Test live behaviors
      await startModules();
      await wait(2 * TEN_SECONDS); // Wait for all managers to be started
      await activateRule(RuleSightingIncident.id);
      // Check default state
      // All sighted indicators are revoked
      await assertInferencesSize(ENTITY_TYPE_INCIDENT, 0);
      // Update the valid until to change the revoked to false
      await patchAttribute(testContext, SYSTEM_USER, ONE_CLAP, ENTITY_TYPE_INDICATOR, { valid_until: '2124-02-17T23:00:00.000Z' });
      const inferences = await assertInferencesSize(ENTITY_TYPE_INCIDENT, 1);
      const inference = R.head(inferences);
      expect(inference).not.toBeNull();
      expect((inference[RELATION_OBJECT_MARKING] || []).length).toBe(1);
      const clear = await internalLoadById(testContext, SYSTEM_USER, TLP_CLEAR_ID);
      expect(R.head(inference[RELATION_OBJECT_MARKING])).toBe(clear.internal_id);
      expect(inference.first_seen).toBe('2016-08-06T20:08:31.000Z');
      expect(inference.last_seen).toBe('2016-08-07T20:08:31.000Z');
      const relArgs = { fromId: inference.id, connectionFormat: false };
      const related = await listRelations(testContext, SYSTEM_USER, RELATION_RELATED_TO, relArgs);
      expect(related.length).toBe(1);
      const targets = await listRelations(testContext, SYSTEM_USER, RELATION_TARGETS, relArgs);
      expect(targets.length).toBe(1);
      // ---- 02. Test rescan behavior
      await disableRule(RuleSightingIncident.id);
      await activateRule(RuleSightingIncident.id);
      await assertInferencesSize(ENTITY_TYPE_INCIDENT, 1);
      // Invalidate the rule with < valid until
      await patchAttribute(testContext, SYSTEM_USER, ONE_CLAP, ENTITY_TYPE_INDICATOR, { valid_until: '2017-02-17T23:00:00.000Z' });
      await assertInferencesSize(ENTITY_TYPE_INCIDENT, 0);
      // Disable the rule
      await disableRule(RuleSightingIncident.id);
      await assertInferencesSize(ENTITY_TYPE_INCIDENT, 0);
      // Stop modules
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
