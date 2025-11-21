import { describe, it, expect } from 'vitest';
import { checkDecayExclusionRules, type DecayExclusionRuleModel } from '../../../src/modules/decayRule/exclusions/decayExclusionRule-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const observableType = 'IPV4';

const decayExclusionRuleActiveModel = {
  id: 'test1 id',
  name: 'test1 name',
  description: 'test1 description',
  created_at: new Date(),
  decay_exclusion_observable_types: ['IPV4', 'Report', 'test'],
  active: true,
};

const decayExclusionRuleActiveModel2 = {
  id: 'test1.1 id',
  name: 'test1.1 name',
  description: 'test1.1 description',
  created_at: new Date(),
  decay_exclusion_observable_types: ['IPV6', 'Report', 'test'],
  active: true,
};

const decayExclusionRuleInactiveModel = {
  id: 'test2 id',
  name: 'test2 name',
  description: 'test2 description',
  created_at: new Date(),
  decay_exclusion_observable_types: ['IPV6', 'Report', 'test'],
  active: false,
};

const decayExclusionRuleModelList: DecayExclusionRuleModel[] = [
  decayExclusionRuleActiveModel,
  decayExclusionRuleInactiveModel,
];

describe('Decay Exclusion Rule', () => {
  describe('checkDecayExclusionRules', () => {
    describe('If there is an active with a matching observable type and an inactive rule on the list', async () => {
      const { exclusionRule, hasExclusionRuleMatching, } = checkDecayExclusionRules(observableType, decayExclusionRuleModelList);

      it('should have hasExclusionRuleMatching to be true ', () => {
        expect(hasExclusionRuleMatching).toBe(true);
      });

      it('should have exclusionRule id to be test1 id ', () => {
        expect(exclusionRule?.id).toBe('test1 id');
      });
    });

    describe('If there is only an inactive rule on the list', async () => {
      const { exclusionRule, hasExclusionRuleMatching, } = checkDecayExclusionRules(observableType, [decayExclusionRuleInactiveModel]);

      it('should have hasExclusionRuleMatching to be false ', () => {
        expect(hasExclusionRuleMatching).toBe(false);
      });

      it('should have exclusionRule to be null ', () => {
        expect(exclusionRule).toBe(null);
      });
    });
    describe('If these is an active list but with no matching observable type', async () => {
      const { exclusionRule, hasExclusionRuleMatching, } = checkDecayExclusionRules(observableType, [decayExclusionRuleActiveModel2]);

      it('should have hasExclusionRuleMatching to be false ', () => {
        expect(hasExclusionRuleMatching).toBe(false);
      });

      it('should have exclusionRule to be null ', () => {
        expect(exclusionRule).toBe(null);
      });
    });
  });
});
