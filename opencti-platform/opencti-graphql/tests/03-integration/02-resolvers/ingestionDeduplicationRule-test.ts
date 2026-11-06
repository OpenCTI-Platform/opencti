import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { getUserIdByEmail, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../utils/testQuery';
import { ENABLED_FEATURE_FLAGS } from '../../../src/config/conf';

const RULES_QUERY = gql`
  query ingestionDeduplicationRules($userId: ID) {
    ingestionDeduplicationRules(userId: $userId) {
      id
      user_id
      target_type
      excluded_fields
    }
  }
`;

const ALLOWED_TYPES_QUERY = gql`
  query ingestionDeduplicationAllowedTypes {
    ingestionDeduplicationAllowedTypes
  }
`;

const RULE_ADD = gql`
  mutation ingestionDeduplicationRuleAdd($input: IngestionDeduplicationRuleAddInput!) {
    ingestionDeduplicationRuleAdd(input: $input) {
      id
      user_id
      target_type
      excluded_fields
    }
  }
`;

const RULE_PATCH = gql`
  mutation ingestionDeduplicationRuleFieldPatch($id: ID!, $input: [EditInput!]!) {
    ingestionDeduplicationRuleFieldPatch(id: $id, input: $input) {
      id
      target_type
      excluded_fields
    }
  }
`;

const RULE_DELETE = gql`
  mutation ingestionDeduplicationRuleDelete($id: ID!) {
    ingestionDeduplicationRuleDelete(id: $id)
  }
`;

describe('Ingestion deduplication rule', () => {
  let userId: string;
  let ruleId: string;

  beforeAll(async () => {
    userId = await getUserIdByEmail(USER_EDITOR.email);
  });

  afterAll(async () => {
    if (ruleId) {
      await queryAsAdmin({ query: RULE_DELETE, variables: { id: ruleId } });
    }
  });

  it('should list the allowed entity types', async () => {
    const result = await queryAsAdminWithSuccess({ query: ALLOWED_TYPES_QUERY, variables: {} });
    expect(result.data.ingestionDeduplicationAllowedTypes).toContain('Attack-Pattern');
    expect(result.data.ingestionDeduplicationAllowedTypes).not.toContain('Vulnerability');
  });

  it('should create a rule', async () => {
    const result = await queryAsAdminWithSuccess({
      query: RULE_ADD,
      variables: { input: { user_id: userId, target_type: 'Attack-Pattern', excluded_fields: ['modified'] } },
    });
    ruleId = result.data.ingestionDeduplicationRuleAdd.id;
    expect(result.data.ingestionDeduplicationRuleAdd.user_id).toBe(userId);
    expect(result.data.ingestionDeduplicationRuleAdd.excluded_fields).toEqual(['modified']);
  });

  it('should list the rules of a user', async () => {
    const result = await queryAsAdminWithSuccess({ query: RULES_QUERY, variables: { userId } });
    expect(result.data.ingestionDeduplicationRules.map((rule: { id: string }) => rule.id)).toEqual([ruleId]);
  });

  it('should refuse a second rule for the same user and type', async () => {
    const result = await queryAsAdmin({
      query: RULE_ADD,
      variables: { input: { user_id: userId, target_type: 'Attack-Pattern', excluded_fields: [] } },
    });
    expect(result.errors?.[0].message).toBe('A deduplication rule already exists for this user and entity type');
  });

  it('should refuse a type outside the allowlist', async () => {
    const result = await queryAsAdmin({
      query: RULE_ADD,
      variables: { input: { user_id: userId, target_type: 'Vulnerability', excluded_fields: [] } },
    });
    expect(result.errors?.[0].message).toBe('Deduplication is not available for this entity type');
  });

  it('should update the excluded fields', async () => {
    const result = await queryAsAdminWithSuccess({
      query: RULE_PATCH,
      variables: { id: ruleId, input: [{ key: 'excluded_fields', value: ['modified', 'x_opencti_modified_at'] }] },
    });
    expect(result.data.ingestionDeduplicationRuleFieldPatch.excluded_fields).toEqual(['modified', 'x_opencti_modified_at']);
  });

  it('should refuse a change of user', async () => {
    const result = await queryAsAdmin({
      query: RULE_PATCH,
      variables: { id: ruleId, input: [{ key: 'user_id', value: ['another-user'] }] },
    });
    expect(result.errors?.[0].message).toBe('Only the entity type and the excluded fields of a deduplication rule can be changed');
  });

  it('should let a user who can access ingestion read the rules', async () => {
    const result = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, { query: RULES_QUERY, variables: { userId } });
    expect(result.data.ingestionDeduplicationRules).toHaveLength(1);
  });

  it('should forbid a user who cannot manage ingestion to create a rule', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: RULE_ADD,
      variables: { input: { user_id: userId, target_type: 'Malware', excluded_fields: [] } },
    });
  });

  it('should refuse changes when the feature is disabled', async () => {
    const enabledFlags = ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    try {
      const result = await queryAsAdmin({
        query: RULE_ADD,
        variables: { input: { user_id: userId, target_type: 'Malware', excluded_fields: [] } },
      });
      expect(result.errors).toBeDefined();
    } finally {
      ENABLED_FEATURE_FLAGS.push(...enabledFlags);
    }
  });

  it('should delete the rule', async () => {
    const result = await queryAsAdminWithSuccess({ query: RULE_DELETE, variables: { id: ruleId } });
    expect(result.data.ingestionDeduplicationRuleDelete).toBe(ruleId);
    const rules = await queryAsAdminWithSuccess({ query: RULES_QUERY, variables: { userId } });
    expect(rules.data.ingestionDeduplicationRules).toHaveLength(0);
    ruleId = '';
  });
});
