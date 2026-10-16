import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { checkDecayExclusionRules, getActiveDecayExclusionRules } from '../../../../src/modules/decayRule/exclusions/decayExclusionRule-domain';

const CUSTOM_FIELD_ADD = gql`
  mutation DecayCustomFieldAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) { id }
  }
`;
const CUSTOM_FIELD_ADD_ENTITY_TYPE = gql`
  mutation DecayCustomFieldAddEntityType($id: ID!, $entityType: String!, $mandatory: Boolean!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType, mandatory: $mandatory) { id }
  }
`;
const CUSTOM_FIELD_DELETE = gql`
  mutation DecayCustomFieldDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;
const DECAY_RULE_ADD = gql`
  mutation DecayCustomFieldRuleAdd($input: DecayRuleAddInput!) {
    decayRuleAdd(input: $input) { id }
  }
`;
const DECAY_RULE_DELETE = gql`
  mutation DecayCustomFieldRuleDelete($id: ID!) {
    decayRuleDelete(id: $id)
  }
`;
const DECAY_EXCLUSION_RULE_ADD = gql`
  mutation DecayCustomFieldExclusionRuleAdd($input: DecayExclusionRuleAddInput!) {
    decayExclusionRuleAdd(input: $input) { id }
  }
`;
const DECAY_EXCLUSION_RULE_DELETE = gql`
  mutation DecayCustomFieldExclusionRuleDelete($id: ID!) {
    decayExclusionRuleDelete(id: $id)
  }
`;
const INDICATOR_ADD = gql`
  mutation DecayCustomFieldIndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id }
  }
`;
const INDICATOR_DELETE = gql`
  mutation DecayCustomFieldIndicatorDelete($id: ID!) {
    indicatorDelete(id: $id)
  }
`;

const INDICATOR_READ = gql`
  query DecayCustomFieldIndicatorRead($id: String!) {
    indicator(id: $id) { id decay_applied_rule { decay_rule_id decay_lifetime } }
  }
`;

const LEVEL = 'x_opencti_cf_decay_level';
const levelFilter = (value: string) => JSON.stringify({
  mode: 'and',
  filters: [{ key: [LEVEL], values: [value], operator: 'eq', mode: 'or' }],
  filterGroups: [],
});

describe('Decay rules on custom fields', () => {
  let definitionId: string;
  let decayRuleId: string;
  let decayExclusionRuleId: string;
  let indicatorId: string;

  beforeAll(async () => {
    const definition = await queryAsAdmin({
      query: CUSTOM_FIELD_ADD,
      variables: { input: { name: LEVEL, label: 'Decay level', field_type: 'select', select_options: ['critical', 'excluded', 'other'] } },
    });
    expect(definition.errors).toBeUndefined();
    definitionId = definition.data?.customFieldDefinitionAdd.id;
    await queryAsAdmin({ query: CUSTOM_FIELD_ADD_ENTITY_TYPE, variables: { id: definitionId, entityType: 'Indicator', mandatory: false } });
    const decayRule = await queryAsAdmin({
      query: DECAY_RULE_ADD,
      variables: {
        input: {
          name: 'Decay rule on a custom field',
          order: 1000,
          active: true,
          decay_lifetime: 42,
          decay_pound: 1,
          decay_points: [60],
          decay_revoke_score: 20,
          decay_filters: levelFilter('critical'),
        },
      },
    });
    expect(decayRule.errors).toBeUndefined();
    decayRuleId = decayRule.data?.decayRuleAdd.id;
    const decayExclusionRule = await queryAsAdmin({
      query: DECAY_EXCLUSION_RULE_ADD,
      variables: { input: { name: 'Decay exclusion rule on a custom field', active: true, decay_exclusion_filters: levelFilter('excluded') } },
    });
    expect(decayExclusionRule.errors).toBeUndefined();
    decayExclusionRuleId = decayExclusionRule.data?.decayExclusionRuleAdd.id;
  });

  afterAll(async () => {
    if (indicatorId) await queryAsAdmin({ query: INDICATOR_DELETE, variables: { id: indicatorId } });
    await queryAsAdmin({ query: DECAY_RULE_DELETE, variables: { id: decayRuleId } });
    await queryAsAdmin({ query: DECAY_EXCLUSION_RULE_DELETE, variables: { id: decayExclusionRuleId } });
    await queryAsAdmin({ query: CUSTOM_FIELD_DELETE, variables: { id: definitionId } });
  });

  it('should apply the decay rule selecting the indicator on its custom field value', async () => {
    const created = await queryAsAdmin({
      query: INDICATOR_ADD,
      variables: {
        input: {
          name: 'Indicator with a decay level',
          pattern: "[domain-name:value = 'decay-custom-field.test']",
          pattern_type: 'stix',
          x_opencti_main_observable_type: 'Domain-Name',
          customFieldValues: [{ field_name: LEVEL, value: ['critical'] }],
        },
      },
    });
    expect(created.errors).toBeUndefined();
    indicatorId = created.data?.indicatorAdd.id;
    const indicator = await queryAsAdmin({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.decay_applied_rule).toMatchObject({ decay_rule_id: decayRuleId, decay_lifetime: 42 });
  });

  it('should select the decay exclusion rule on a custom field value', async () => {
    const activeExclusionRules = await getActiveDecayExclusionRules(testContext, ADMIN_USER);
    const indicator = (value: string) => ({ entity_type: 'Indicator', custom_field_values: [{ field_id: definitionId, field_name: LEVEL, select_value: value }] });
    const excluded = await checkDecayExclusionRules(testContext, ADMIN_USER, indicator('excluded'), activeExclusionRules);
    expect(excluded?.id).toEqual(decayExclusionRuleId);
    const notExcluded = await checkDecayExclusionRules(testContext, ADMIN_USER, indicator('other'), activeExclusionRules);
    expect(notExcluded?.id).not.toEqual(decayExclusionRuleId);
  });
});
