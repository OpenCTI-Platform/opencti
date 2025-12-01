import { describe, it, expect } from 'vitest';
import {
  checkDecayExclusionRules,
  type ResolvedDecayExclusionRule,
} from '../../../src/modules/decayRule/exclusions/decayExclusionRule-domain';
import {
  type BasicStoreEntityDecayExclusionRule,
} from '../../../src/modules/decayRule/exclusions/decayExclusionRule-types'
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const decayExclusionRuleEmptyFilterGroupModel = {
  id: 'emptyFilterGroup id',
  name: 'emptyFilterGroup name',
  description: 'emptyFilterGroup description',
  created_at: new Date(),
  decay_exclusion_filters: '{"mode":"and","filters":[],"filterGroups":[]}',
  active: true,
} as BasicStoreEntityDecayExclusionRule;

const decayExclusionRuleWithMatchingFilterGroupModel = {
  id: 'matchingFilterGroup id',
  name: 'matchingFilterGroup name',
  description: 'matchingFilterGroup description',
  created_at: new Date(),
  decay_exclusion_filters: '{"mode":"and","filters":[{"key":["objectMarking"],"operator":"eq","values":["14baccf5-f87d-4dae-bca5-5e0e90062dbb"],"mode":"or"},{"key":["objectLabel"],"operator":"eq","values":["97699018-9db6-4a47-9528-dd3145d78b4d"],"mode":"or"},{"key":["pattern_type"],"operator":"eq","values":["stix","tanium-signal"],"mode":"or"}],"filterGroups":[]}',
  active: true,
} as BasicStoreEntityDecayExclusionRule;

const decayExclusionRuleWithNoMatchingRuleModel = {
  id: 'noMatchingFilterGroup id',
  name: 'noMatchingFilterGroup name',
  description: 'noMatchingFilterGroup description',
  created_at: new Date(),
  decay_exclusion_filters: '{"mode":"and","filters":[{"key":["indicator_types"],"operator":"eq","values":["compromised"],"mode":"or"},{"key":["objectMarking"],"operator":"eq","values":["14gredf5-f87d-4dae-bca5-5e0e90062dbb"],"mode":"or"}],"filterGroups":[]}',
  active: true,
} as BasicStoreEntityDecayExclusionRule;

const resolvedIndicator = {
  _index: 'test_stix_domain_objects',
  pattern_type: 'stix',
  pattern: "[ipv4-addr:value = '36.76.6.46']",
  name: 'test 44',
  description: '',
  indicator_types: [],
  valid_from: null,
  valid_until: null,
  confidence: 100,
  x_opencti_score: null,
  x_opencti_detection: false,
  x_opencti_main_observable_type: 'IPv4-Addr',
  x_mitre_platforms: [],
  killChainPhases: [],
  objectMarking: null,
  objectLabel: null,
  externalReferences: [],
  createObservables: false,
  entity_type: 'Indicator'
} as ResolvedDecayExclusionRule;

const decayExclusionRuleModelList = [
  decayExclusionRuleEmptyFilterGroupModel,
  decayExclusionRuleWithMatchingFilterGroupModel,
  decayExclusionRuleWithNoMatchingRuleModel,
];

describe('Decay Exclusion Rule', () => {
  describe('checkDecayExclusionRules', () => {
    describe('If there is a list of exclusion rules with at least one matching rule', async () => {
      const exclusionRule = await checkDecayExclusionRules(testContext, ADMIN_USER, resolvedIndicator, decayExclusionRuleModelList);

      it('should match an exclusion rule', () => {
        expect(exclusionRule?.id).toBeDefined();
      });
    });
    describe('If there is a rule with an empty filterGroup', async () => {
      const exclusionRule = await checkDecayExclusionRules(testContext, ADMIN_USER, resolvedIndicator, [decayExclusionRuleEmptyFilterGroupModel]);

      it('should match an exclusion rule', () => {
        expect(exclusionRule?.id).toBeDefined();
      });
    });

    describe('If there is only no matching exclusion rule', async () => {
      const exclusionRule = await checkDecayExclusionRules(testContext, ADMIN_USER, resolvedIndicator, [decayExclusionRuleWithNoMatchingRuleModel]);

      it('should not find any exclusion rule', () => {
        expect(exclusionRule).toBe(null);
      });
    });
  });
});
