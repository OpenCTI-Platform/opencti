import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import type { StoreEntityDecayExclusionRule } from '../../../src/modules/decayRule/exclusions/decayExclusionRule-types';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

export const DECAY_EXCLUSION_RULE_LIST_QUERY = gql`
  query decayExclusionRules($first: Int, $filters: FilterGroup) {
    decayExclusionRules(first: $first, filters: $filters) {
      edges {
        node {
          id
          name
          created_at
          decay_exclusion_filters
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
      decay_exclusion_filters
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
      decay_exclusion_filters
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
  let createdDecayExclusionRule_1: StoreEntityDecayExclusionRule | null = null;
  let createdDecayExclusionRule_2: StoreEntityDecayExclusionRule | null = null;

  describe('Create', async () => {
    const createInput = {
      name: 'test name 1',
      decay_exclusion_filters: '{"mode":"and","filters":[],"filterGroups":[]}',
      active: true,
    };
    const createInput2 = {
      name: 'test name 2',
      decay_exclusion_filters: '{"mode":"and","filters":[{"key":["objectMarking"],"operator":"eq","values":["14baccf5-f87d-4dae-bca5-5e0e90062dbb"],"mode":"or"},{"key":["objectLabel"],"operator":"eq","values":["97699018-9db6-4a47-9528-dd3145d78b4d"],"mode":"or"},{"key":["pattern_type"],"operator":"eq","values":["stix","tanium-signal"],"mode":"or"}],"filterGroups":[]}',
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
      createdDecayExclusionRule_1 = decayExclusionRule.data?.decayExclusionRuleAdd as StoreEntityDecayExclusionRule;
      createdDecayExclusionRule_2 = decayExclusionRule2.data?.decayExclusionRuleAdd as StoreEntityDecayExclusionRule;
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
