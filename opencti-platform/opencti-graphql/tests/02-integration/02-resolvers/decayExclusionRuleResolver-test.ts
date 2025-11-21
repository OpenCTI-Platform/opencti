import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import type { DecayExclusionRuleModel } from '../../../src/modules/decayRule/exclusions/decayExclusionRule-domain';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ENTITY_IPV6_ADDR, ENTITY_IPV4_ADDR } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

export const DECAY_EXCLUSION_RULE_LIST_QUERY = gql`
  query decayExclusionRules($first: Int, $filters: FilterGroup) {
    decayExclusionRules(first: $first, filters: $filters) {
      edges {
        node {
          id
          name
          created_at
          decay_exclusion_observable_types
          active
        }
      }
    }
  }
`;

export const DECAY_EXCLUSION_RULE_CREATE = gql`
  mutation decayExclusionRuleAdd($input: DecayExclusionRuleAddInput!) {
    decayExclusionRuleAdd(input: $input) {
      id
      name
      created_at
      decay_exclusion_observable_types
      active
    }
  }
`;

const DECAY_EXCLUSION_RULE_UPDATE = gql`
  mutation decayExclusionRuleFieldPatch($id: ID!, $input: [EditInput!]!) {
    decayExclusionRuleFieldPatch(id: $id, input: $input) {
      id
      name
      created_at
      decay_exclusion_observable_types
      active
    }
  }
`;

const DECAY_EXCLUSION_RULE_DELETE = gql`
  mutation decayExclusionRuleDelete($id: ID!) {
    decayExclusionRuleDelete(id: $id)
  }
`;

describe('Decay Exclusion Rule', () => {
  let createdDecayExclusionRule_1: DecayExclusionRuleModel | null = null;
  let createdDecayExclusionRule_2: DecayExclusionRuleModel | null = null;

  describe('Create', async () => {
    const createInput = {
      name: 'test name 1',
      decay_exclusion_observable_types: ['ENTITY_IPV4_ADDR', 'ENTITY_IPV6_ADDR'],
      active: true,
    };
    const createInput2 = {
      name: 'test name 2',
      decay_exclusion_observable_types: ['ENTITY_TYPE_CONTAINER_REPORT', 'ENTITY_IPV6_ADDR'],
      active: false,
    };

    beforeAll(async () => {
      const decayExclusionRule = await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_CREATE,
        variables: { input: createInput }
      });
      const decayExclusionRule2 = await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_CREATE,
        variables: { input: createInput2 }
      });
      createdDecayExclusionRule_1 = decayExclusionRule.data?.decayExclusionRuleAdd as DecayExclusionRuleModel;
      createdDecayExclusionRule_2 = decayExclusionRule2.data?.decayExclusionRuleAdd as DecayExclusionRuleModel;
    });

    it('should create a decay exclusion rule', () => {
      expect(createdDecayExclusionRule_1?.id).toBeDefined();
      expect(createdDecayExclusionRule_1?.name).toBe('test name 1');
    });

    it('should create another decay exclusion rule', () => {
      expect(createdDecayExclusionRule_2?.id).toBeDefined();
      expect(createdDecayExclusionRule_2?.name).toBe('test name 2');
    });
  });

  describe('Find List', () => {
    it('should find a decay exclusion rule list', async () => {
      const decayExclusionRuleList = await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_LIST_QUERY,
        variables: { first: 10 }
      });

      expect(decayExclusionRuleList).toBeDefined();
      expect(decayExclusionRuleList?.data?.decayExclusionRules?.edges.length).toBe(2);
    });
  });
  describe('Update', () => {
    it('should edit the name of the decay exclusion rule', async () => {
      const result = await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_UPDATE,
        variables: {
          id: createdDecayExclusionRule_1?.id,
          input: {
            key: 'name',
            value: 'updated name 1',
          }
        }
      });

      expect(result?.data?.decayExclusionRuleFieldPatch).toBeDefined();
      expect(result?.data?.decayExclusionRuleFieldPatch?.name).toBe('updated name 1');
    });
  });
  describe('Delete', () => {
    beforeAll(async () => {
      await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_DELETE,
        variables: { id: createdDecayExclusionRule_1?.id }
      });
      await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_DELETE,
        variables: { id: createdDecayExclusionRule_2?.id }
      });
    });

    it('should have deleted the both decay exclusion rule', async () => {
      const decayExclusionRuleList = await queryAsAdminWithSuccess({
        query: DECAY_EXCLUSION_RULE_LIST_QUERY,
        variables: { first: 10 }
      });

      expect(decayExclusionRuleList).toBeDefined();
      expect(decayExclusionRuleList?.data?.decayExclusionRules?.edges.length).toBe(0);
    });
  });
});
