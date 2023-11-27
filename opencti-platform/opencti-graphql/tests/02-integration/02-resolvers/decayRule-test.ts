import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { ENTITY_FINANCIAL_ACCOUNT, ENTITY_EMAIL_ADDR, ENTITY_EMAIL_MESSAGE, ENTITY_IPV6_ADDR, ENTITY_SOFTWARE } from '../../../src/schema/stixCyberObservable';
import {
  BUILT_IN_DECAY_RULE_IP_URL,
  type DecayRuleConfiguration,
  FALLBACK_DECAY_RULE,
  findDecayRuleForIndicator,
  initDecayRules
} from '../../../src/modules/decayRule/decayRule-domain';
import type { AuthContext } from '../../../src/types/user';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import type { BasicStoreEntityEdge } from '../../../src/types/store';
import type { BasicStoreEntityDecayRule } from '../../../src/modules/decayRule/decayRule-types';
import { logApp } from '../../../src/config/conf';

export const INDICATOR_WITH_DECAY_RULE_READ_QUERY = gql`
  query indicator($id: String!) {
    indicator(id: $id) {
      id
      standard_id
      name
      description
      decay_base_score
      decay_base_score_date
      decay_applied_rule {
        decay_rule_id
        decay_lifetime
        decay_pound
        decay_points
        decay_revoke_score
      }
    }
  }
`;

export const DECAY_RULE_READ_QUERY = gql`
  query decayRule($id: String!) {
    decayRule(id: $id) {
      id
      active
      decay_lifetime
      decay_observable_types
      decay_points
      decay_pound
      decay_revoke_score
      description
      name
      order
      appliedIndicatorsCount
      decaySettingsChartData {
        live_score_serie {
          updated_at
          score
        }
      }
    }
  }
`;

const CREATE_QUERY = gql`
  mutation decayRuleAdd($input: DecayRuleAddInput!) {
    decayRuleAdd(input: $input) {
      id
      active
      decay_lifetime
      decay_observable_types
      decay_points
      decay_pound
      decay_revoke_score
      description
      name
      order
    }
  }
`;

const DECAY_RULE_LIST_QUERY = gql`
  query decayRule(
    $first: Int
    $after: ID
    $filters: FilterGroup
    $search: String
  ) {
    decayRules(
      first: $first
      after: $after
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          order
          built_in
          decay_lifetime
          decay_observable_types
          decay_revoke_score
        }
      }
    }
  }
`;

const DELETE_QUERY = gql`
  mutation decayRuleDelete($id: ID!) {
    decayRuleDelete(id: $id)
  }
`;

// To help when built-in decay rule are changing
const TEST_IP_DECAY_RULE = BUILT_IN_DECAY_RULE_IP_URL;
const TEST_FALLBACK_DECAY_RULE = FALLBACK_DECAY_RULE;
describe('DecayRule resolver standard behavior', () => {
  const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'decay-integration-test', otp_mandatory: false };
  let customDecayRuleId = '';
  const indicatorsToCleanup: string [] = [];
  let defaultDecayRuleId: string = '';

  it('should initDecayRules not fail', async () => {
    await initDecayRules(adminContext, ADMIN_USER);
  });

  it('should list built-in decay rules', async () => {
    const getAllBuiltInDecayRules = await queryAsAdminWithSuccess({ query: DECAY_RULE_LIST_QUERY, variables: { first: 10 } });

    const allRules: [] = getAllBuiltInDecayRules.data?.decayRules.edges;
    expect(allRules, 'Built-in decay rules not found').toBeDefined();
    if (allRules) {
      allRules.forEach((rule: BasicStoreEntityEdge<BasicStoreEntityDecayRule>) => {
        const decayRule: DecayRuleConfiguration = rule.node;
        expect(decayRule.id).toBeDefined();
        expect(decayRule.name).toBeDefined();
        expect(decayRule.decay_lifetime).toBeDefined();
        expect(decayRule.decay_observable_types).toBeDefined();
        expect(decayRule.decay_revoke_score).toBeDefined();
        expect(decayRule.order).toBeDefined();
        logApp.info('One built-in decay rule is', { decayRule });
        if (decayRule.name === TEST_FALLBACK_DECAY_RULE.name) {
          defaultDecayRuleId = decayRule.id || '';
        }
      });
    }
  });

  it('should DecayRule be created', async () => {
    // Create the decayRule
    const DECAY_RULE_TO_CREATE = {
      input: {
        active: true,
        decay_lifetime: 42,
        decay_observable_types: [ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_ADDR],
        decay_points: [90, 15, 45, -1], // disorder and negative number in purpose, to check of ordering is done correctly.
        decay_pound: 0.5,
        decay_revoke_score: 10,
        description: 'Decay rule for email message and email address.',
        name: 'decay rule email',
        order: 12,
      },
    };
    const decayRule = await queryAsAdminWithSuccess({
      query: CREATE_QUERY,
      variables: DECAY_RULE_TO_CREATE,
    });
    expect(decayRule.data?.decayRuleAdd).toBeDefined();
    const customDecayRule = decayRule.data?.decayRuleAdd;
    if (customDecayRule) {
      expect(customDecayRule.id).toBeDefined();
      customDecayRuleId = customDecayRule.id;
    }
    logApp.info('[TEST]Custom decay rule is', { customDecayRule });

    // Verify that this decay rule is find for observable
    const indicatorDecayRule = await findDecayRuleForIndicator(adminContext, ENTITY_EMAIL_ADDR);
    expect(indicatorDecayRule).toBeDefined();
    expect(indicatorDecayRule.name).toBe('decay rule email');
    expect(indicatorDecayRule.decay_points, 'Decay point should be ordered and positive numbers.').toStrictEqual([90, 45, 15]);

    // Verify that other observable got the right decay rule
    // No built-in for ENTITY_SOFTWARE, so should be FALLBACK
    const indicatorDecayRuleOther = await findDecayRuleForIndicator(adminContext, ENTITY_SOFTWARE);
    expect(indicatorDecayRuleOther).toBeDefined();
    expect(indicatorDecayRuleOther.name).toBe(TEST_FALLBACK_DECAY_RULE.name);

    const indicatorDecayRuleIP = await findDecayRuleForIndicator(adminContext, ENTITY_IPV6_ADDR);
    expect(indicatorDecayRuleIP).toBeDefined();
    expect(indicatorDecayRuleIP.name).toBe(TEST_IP_DECAY_RULE.name);
  });

  it('should DecayRule be field patch', async () => {
    const PATCH_QUERY = gql`
      mutation decayRuleFieldPatch($id: ID!, $input: [EditInput!]!) {
        decayRuleFieldPatch(id: $id, input: $input) {
            id
        }
      }
    `;

    const FIELD_PATCH_DECAY_RULE = {
      id: customDecayRuleId,
      input: { key: 'decay_points', value: [80, 20, 60, -5] }
    };

    await queryAsAdminWithSuccess({
      query: PATCH_QUERY,
      variables: FIELD_PATCH_DECAY_RULE,
    });

    const queryResult = await queryAsAdminWithSuccess({
      query: DECAY_RULE_READ_QUERY,
      variables: { id: customDecayRuleId }
    });

    const customDecayRule = queryResult.data?.decayRule;
    if (customDecayRule) {
      expect(customDecayRule.id).toBe(customDecayRuleId);
      expect(customDecayRule.decay_points).toStrictEqual([80, 60, 20]);
    }
  });

  it('should indicator with custom DecayRule created', async () => {
    const INDICATOR_CREATE_QUERY = gql`
      mutation IndicatorAdd($input: IndicatorAddInput!) {
        indicatorAdd(input: $input) {
          id
          name
          description
          observables {
            edges {
              node {
                id
                standard_id
              }
            }
          }
        }
      }
  `;

    const INDICATOR_TO_CREATE = {
      input: {
        name: 'Indicator custom DecayRule on ENTITY_EMAIL_ADDR',
        description: 'Indicator that matches DecayRule named decay rule email',
        pattern: "[email-addr:value = 'test@octi.io']\n",
        pattern_type: 'stix',
        x_opencti_main_observable_type: ENTITY_EMAIL_ADDR,
      },
    };

    const indicatorWithDecay = await queryAsAdminWithSuccess({
      query: INDICATOR_CREATE_QUERY,
      variables: INDICATOR_TO_CREATE,
    });

    const indicatorInternalId = indicatorWithDecay.data?.indicatorAdd.id;
    expect(indicatorInternalId, 'Something is wrong, Indicator has not been created').toBeDefined();
    indicatorsToCleanup.push(indicatorInternalId);

    const getIndicatorResult = await queryAsAdminWithSuccess({ query: INDICATOR_WITH_DECAY_RULE_READ_QUERY, variables: { id: indicatorInternalId } });
    expect(getIndicatorResult.data?.indicator).toBeDefined();
    const decayAppliedRule = getIndicatorResult.data?.indicator.decay_applied_rule;
    expect(decayAppliedRule).toBeDefined();
    expect(decayAppliedRule.decay_rule_id).toBe(customDecayRuleId);
    expect(decayAppliedRule.decay_lifetime).toBe(42);
  });

  it('should indicator with no custom DecayRule created', async () => {
    const INDICATOR_CREATE_QUERY_2 = gql`
      mutation IndicatorAdd($input: IndicatorAddInput!) {
        indicatorAdd(input: $input) {
          id
          name
          description
          observables {
            edges {
              node {
                id
                standard_id
              }
            }
          }
        }
      }
    `;

    const INDICATOR_TO_CREATE_2 = {
      input: {
        name: 'Indicator ENTITY_HASHED_OBSERVABLE_STIX_FILE',
        description: 'Indicator that does not match any decay rule',
        pattern: "[file:hashes.'SHA-256' = 'ea4c2f895f7b1c46aa8de559e7a6d8201b49437332d6d5e859052276db50c6c4']",
        pattern_type: 'stix',
        x_opencti_main_observable_type: ENTITY_FINANCIAL_ACCOUNT,
      },
    };

    const indicatorWithDecay = await queryAsAdminWithSuccess({
      query: INDICATOR_CREATE_QUERY_2,
      variables: INDICATOR_TO_CREATE_2,
    });
    expect(indicatorWithDecay.data?.indicatorAdd.id).toBeDefined();
    const indicatorInternalId = indicatorWithDecay.data?.indicatorAdd.id;
    indicatorsToCleanup.push(indicatorInternalId);

    const getIndicatorResult = await queryAsAdminWithSuccess({ query: INDICATOR_WITH_DECAY_RULE_READ_QUERY, variables: { id: indicatorInternalId } });
    expect(getIndicatorResult.data?.indicator).toBeDefined();

    const decayAppliedRule = getIndicatorResult.data?.indicator.decay_applied_rule;
    expect(decayAppliedRule).toBeDefined();
    expect(decayAppliedRule.decay_rule_id).toBe(defaultDecayRuleId);
    expect(decayAppliedRule.decay_lifetime).toBe(TEST_FALLBACK_DECAY_RULE.decay_lifetime);
  });

  it('should custom DecayRule have one impacted indicator and graph data.', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: DECAY_RULE_READ_QUERY, variables: { id: customDecayRuleId } });
    expect(queryResult.data?.decayRule).toBeDefined();
    expect(queryResult.data?.decayRule.appliedIndicatorsCount).toBe(1);
    expect(queryResult.data?.decayRule.decaySettingsChartData).toBeDefined();
    expect(queryResult.data?.decayRule.decaySettingsChartData.live_score_serie).toBeDefined();
    expect(queryResult.data?.decayRule.decaySettingsChartData.live_score_serie.length).toBe(101);
  });

  it('should custom DecayRule be deleted', async () => {
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: customDecayRuleId },
    });

    const queryResult = await queryAsAdminWithSuccess({ query: DECAY_RULE_READ_QUERY, variables: { id: customDecayRuleId } });
    expect(queryResult.data?.decayRule).toBeNull();
  });

  it('Should built-in default DecayRule NEVER be deleted', async () => {
    const deleteQueryResult = await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: defaultDecayRuleId },
    });
    expect(deleteQueryResult.errors).toBeDefined();
    expect(deleteQueryResult.errors?.length).toBe(1);

    const queryResult = await queryAsAdminWithSuccess({
      query: DECAY_RULE_READ_QUERY,
      variables: { id: defaultDecayRuleId }
    });
    expect(queryResult.data?.decayRule).toBeDefined();
    expect(queryResult.data?.decayRule.decay_lifetime).toBe(TEST_FALLBACK_DECAY_RULE.decay_lifetime);
  });

  it('should all Indicators created in this test file be deleted.', async () => {
    const deleteIndicator = async (indicatorId: string) => {
      const INDICATOR_DELETE_QUERY = gql`
        mutation indicatorDelete($id: ID!) {
          indicatorDelete(id: $id)
        }
      `;
      // Delete the indicator
      await queryAsAdminWithSuccess({
        query: INDICATOR_DELETE_QUERY,
        variables: { id: indicatorId },
      });
      // Verify is no longer found
      const queryResult = await queryAsAdminWithSuccess({
        query: INDICATOR_WITH_DECAY_RULE_READ_QUERY,
        variables: { id: indicatorId }
      });
      expect(queryResult.data?.indicator).toBeNull();
    };
    for (let i = 0; i < indicatorsToCleanup.length; i += 1) {
      await deleteIndicator(indicatorsToCleanup[i]);
    }
  });
});

describe('DecayRule rights management checks', () => {
  it('should Participant/Editor user not be allowed to create a DecayRule.', async () => {
    const DECAY_RULE_TO_CREATE = {
      input: {
        active: true,
        decay_lifetime: 42,
        decay_observable_types: [ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_ADDR],
        decay_points: [90, 15, 45, -1], // disorder and negative number in purpose, to check of ordering is done correctly.
        decay_pound: 0.5,
        decay_revoke_score: 10,
        description: 'Decay rule for email message and email address.',
        name: 'decay rule email',
        order: 12,
      },
    };
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: CREATE_QUERY,
      variables: DECAY_RULE_TO_CREATE,
    });

    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: CREATE_QUERY,
      variables: DECAY_RULE_TO_CREATE,
    });
  });

  it('should Participant/Editor user not be allowed to list DecayRules.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, { query: DECAY_RULE_LIST_QUERY, variables: { first: 10 } });

    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, { query: DECAY_RULE_LIST_QUERY, variables: { first: 10 } });
  });

  it('should Participant/Editor user not be allowed to delete DecayRules.', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: DELETE_QUERY,
      variables: { id: 'dummy-id' },
    });

    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: DELETE_QUERY,
      variables: { id: 'dummy-id' },
    });
  });
});
