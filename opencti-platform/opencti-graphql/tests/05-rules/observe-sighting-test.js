// 'If **observed-data A** (`created-by` **identity X**) have `object` **observable B** and **indicator C** ' +
// 'is `based-on` **observable B**, then **indicator C** is `sighted` in **identity X**.';

import { expect, it, describe } from 'vitest';
import { FIVE_MINUTES, testContext, TEN_SECONDS } from '../utils/testQuery';
import RuleObserveSighting from '../../src/rules/observed-sighting/ObserveSightingRule';
import { RULE_PREFIX } from '../../src/schema/general';
import { shutdownModules, startModules } from '../../src/modules';
import { activateRule, disableRule, getInferences, inferenceLookup } from '../utils/rule-utils';
import { createRelation, internalDeleteElementById, patchAttribute } from '../../src/database/middleware';
import { SYSTEM_USER } from '../../src/utils/access';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../src/schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../src/schema/stixSightingRelationship';
import { RELATION_BASED_ON } from '../../src/schema/stixCoreRelationship';
import { wait } from '../../src/database/utils';

const RULE = RULE_PREFIX + RuleObserveSighting.id;
const TLP_CLEAR_ID = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';
const OBSERVED_DATA = 'observed-data--7d258c31-9a26-4543-aecb-2abc5ed366be'; // observed-data A
const OBSERVED_FILE = 'file--702e320e-43b6-552a-b7e7-d045bf9c887d'; // observable B
const ANSSI = 'identity--18fe5225-fee1-5627-ad3e-20c14435b024'; // Organization X
const MITRE = 'identity--f11b0831-e7e6-5214-9431-ccf054e53e94'; // Organization X
const CBRICKSDOC = 'indicator--c5c0c0f9-dfa1-5b7d-a12a-ea95072d3e45'; // indicator C

describe('Observed sighting rule', () => {
  const fetchInferences = async () => {
    console.log(`${new Date().toISOString()} >> Waiting 10 sec`);
    await wait(TEN_SECONDS); // let some time to rule manager to create the elements
    return getInferences(STIX_SIGHTING_RELATIONSHIP);
  };

  it(
    'Should rule successfully activated',
    async () => {
      // ---- 01. Test live behaviors
      await startModules();
      await wait(2 * TEN_SECONDS); // Wait for all managers to be started
      await activateRule(RuleObserveSighting.id);
      // Check default state
      let inferences = await fetchInferences();
      expect(inferences.length).toBe(0);
      // OBSERVED_DATA have no created-by Organization (must be updated)
      await patchAttribute(testContext, SYSTEM_USER, OBSERVED_DATA, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { createdBy: ANSSI });
      inferences = await fetchInferences();
      expect(inferences.length).toBe(0);
      // PARADISE_RANSOMWARE is not based on an Indicator (relation must be created)
      const cbrickToFile = await createRelation(testContext, SYSTEM_USER, {
        fromId: CBRICKSDOC,
        toId: OBSERVED_FILE,
        revoked: false,
        x_opencti_detection: false,
        start_time: '2020-01-10T00:00:00.000Z',
        stop_time: '2020-02-20T00:00:00.000Z',
        confidence: 100,
        relationship_type: RELATION_BASED_ON,
        objectMarking: [TLP_CLEAR_ID],
      });
      const afterLiveRelations = await fetchInferences();
      expect(afterLiveRelations.length).toBe(1);
      const cbrickToAnssi = await inferenceLookup(afterLiveRelations, CBRICKSDOC, ANSSI, STIX_SIGHTING_RELATIONSHIP);
      expect(cbrickToAnssi).not.toBeNull();
      expect(cbrickToAnssi[RULE].length).toBe(1);
      expect(cbrickToAnssi.first_seen).toBe('2020-02-25T09:02:29.040Z');
      expect(cbrickToAnssi.last_seen).toBe('2020-02-25T09:02:29.040Z');
      expect(cbrickToAnssi.attribute_count).toBe(1);
      expect(cbrickToAnssi.confidence).toBe(15);
      expect(cbrickToAnssi.i_inference_weight).toBe(1);
      expect((cbrickToAnssi.object_marking_refs || []).length).toBe(0);
      // Change the organization
      await patchAttribute(testContext, SYSTEM_USER, OBSERVED_DATA, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { createdBy: MITRE });
      const afterOrgaRelations = await fetchInferences();
      expect(afterOrgaRelations.length).toBe(1);
      const cbrickToMitre = await inferenceLookup(afterOrgaRelations, CBRICKSDOC, MITRE, STIX_SIGHTING_RELATIONSHIP);
      expect(cbrickToMitre).not.toBeNull();
      // Invalidate the rule with x_opencti_detection = true
      await patchAttribute(testContext, SYSTEM_USER, CBRICKSDOC, ENTITY_TYPE_INDICATOR, { x_opencti_detection: true });
      inferences = await fetchInferences();
      expect(inferences.length).toBe(1);
      // ---- 02. Test rescan behavior
      // Disable the rule
      await disableRule(RuleObserveSighting.id);
      await activateRule(RuleObserveSighting.id);
      const afterRescan = await fetchInferences();
      expect(afterRescan.length).toBe(1);
      const cbrickToMitreRescan = await inferenceLookup(afterRescan, CBRICKSDOC, MITRE, STIX_SIGHTING_RELATIONSHIP);
      expect(cbrickToMitreRescan).not.toBeNull();
      expect(cbrickToMitreRescan[RULE].length).toBe(1);
      expect(cbrickToMitreRescan.first_seen).toBe('2020-02-25T09:02:29.040Z');
      expect(cbrickToMitreRescan.last_seen).toBe('2020-02-25T09:02:29.040Z');
      expect(cbrickToMitreRescan.attribute_count).toBe(1);
      expect(cbrickToMitreRescan.confidence).toBe(15);
      expect(cbrickToMitreRescan.i_inference_weight).toBe(1);
      expect((cbrickToMitreRescan.object_marking_refs || []).length).toBe(0);
      // Cleanup
      await internalDeleteElementById(testContext, SYSTEM_USER, cbrickToFile.internal_id);
      inferences = await fetchInferences();
      expect(inferences.length).toBe(0);
      // Disable the rule
      await disableRule(RuleObserveSighting.id);
      // Stop modules
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
