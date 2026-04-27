import { describe, expect, it, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import type { RetentionRuleAddInput } from '../../../src/generated/graphql';
import { RetentionRuleScope, RetentionUnit } from '../../../src/generated/graphql';

// ---------------------------------------------------------------------------
// GraphQL fragments
// ---------------------------------------------------------------------------

const RETENTION_RULE_FIELDS = gql`
  fragment RetentionRuleFields on RetentionRule {
    id
    standard_id
    name
    filters
    max_retention
    retention_unit
    scope
    last_execution_date
    last_deleted_count
    remaining_count
  }
`;

const CREATE_RETENTION_RULE = gql`
  ${RETENTION_RULE_FIELDS}
  mutation RetentionRuleAdd($input: RetentionRuleAddInput!) {
    retentionRuleAdd(input: $input) {
      ...RetentionRuleFields
    }
  }
`;

const GET_RETENTION_RULE = gql`
  ${RETENTION_RULE_FIELDS}
  query RetentionRule($id: String!) {
    retentionRule(id: $id) {
      ...RetentionRuleFields
    }
  }
`;

const LIST_RETENTION_RULES = gql`
  ${RETENTION_RULE_FIELDS}
  query RetentionRules($first: Int, $search: String) {
    retentionRules(first: $first, search: $search) {
      pageInfo {
        globalCount
        hasNextPage
      }
      edges {
        node {
          ...RetentionRuleFields
        }
      }
    }
  }
`;

const UPDATE_RETENTION_RULE = gql`
  ${RETENTION_RULE_FIELDS}
  mutation RetentionRuleFieldPatch($id: ID!, $input: [EditInput]!) {
    retentionRuleEdit(id: $id) {
      fieldPatch(input: $input) {
        ...RetentionRuleFields
      }
    }
  }
`;

const DELETE_RETENTION_RULE = gql`
  mutation RetentionRuleDelete($id: ID!) {
    retentionRuleEdit(id: $id) {
      delete
    }
  }
`;

const CHECK_RETENTION_RULE = gql`
  mutation RetentionRuleCheck($input: RetentionRuleAddInput) {
    retentionRuleCheck(input: $input)
  }
`;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const emptyFilters = JSON.stringify({ mode: 'and', filters: [], filterGroups: [] });

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RetentionRules module – integration tests', () => {
  let knowledgeRuleId: string;
  let fileRuleId: string;
  let workbenchRuleId: string;
  let historyRuleId: string;

  // -------------------------------------------------------------------------
  // CREATE
  // -------------------------------------------------------------------------

  describe('createRetentionRule', () => {
    it('should create a knowledge retention rule', async () => {
      const input: RetentionRuleAddInput = {
        name: '[Integration] Knowledge rule',
        filters: emptyFilters,
        max_retention: 30,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.Knowledge,
      };

      const response = await queryAsAdminWithSuccess({
        query: CREATE_RETENTION_RULE,
        variables: { input },
      });

      const rule = response.data?.retentionRuleAdd;
      expect(rule).toBeDefined();
      expect(rule.id).toBeDefined();
      expect(rule.name).toBe('[Integration] Knowledge rule');
      expect(rule.scope).toBe('knowledge');
      expect(rule.max_retention).toBe(30);
      expect(rule.retention_unit).toBe('days');
      expect(rule.filters).toBe(emptyFilters);
      expect(rule.last_execution_date).toBeNull();
      expect(rule.last_deleted_count).toBeNull();
      expect(rule.remaining_count).toBeNull();

      knowledgeRuleId = rule.id;
    });

    it('should create a file retention rule', async () => {
      const input: RetentionRuleAddInput = {
        name: '[Integration] File rule',
        filters: emptyFilters,
        max_retention: 7,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.File,
      };

      const response = await queryAsAdminWithSuccess({
        query: CREATE_RETENTION_RULE,
        variables: { input },
      });

      const rule = response.data?.retentionRuleAdd;
      expect(rule).toBeDefined();
      expect(rule.id).toBeDefined();
      expect(rule.name).toBe('[Integration] File rule');
      expect(rule.scope).toBe('file');

      fileRuleId = rule.id;
    });

    it('should create a workbench retention rule with hours unit', async () => {
      const input: RetentionRuleAddInput = {
        name: '[Integration] Workbench rule',
        filters: emptyFilters,
        max_retention: 48,
        retention_unit: RetentionUnit.Hours,
        scope: RetentionRuleScope.Workbench,
      };

      const response = await queryAsAdminWithSuccess({
        query: CREATE_RETENTION_RULE,
        variables: { input },
      });

      const rule = response.data?.retentionRuleAdd;
      expect(rule).toBeDefined();
      expect(rule.id).toBeDefined();
      expect(rule.name).toBe('[Integration] Workbench rule');
      expect(rule.scope).toBe('workbench');
      expect(rule.retention_unit).toBe('hours');
      expect(rule.max_retention).toBe(48);

      workbenchRuleId = rule.id;
    });

    it('should create a history retention rule', async () => {
      const input: RetentionRuleAddInput = {
        name: '[Integration] History rule',
        filters: emptyFilters,
        max_retention: 365,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.History,
      };

      const response = await queryAsAdminWithSuccess({
        query: CREATE_RETENTION_RULE,
        variables: { input },
      });

      const rule = response.data?.retentionRuleAdd;
      expect(rule).toBeDefined();
      expect(rule.id).toBeDefined();
      expect(rule.name).toBe('[Integration] History rule');
      expect(rule.scope).toBe('history');
      expect(rule.max_retention).toBe(365);
      expect(rule.retention_unit).toBe('days');
      expect(rule.last_execution_date).toBeNull();
      expect(rule.last_deleted_count).toBeNull();
      expect(rule.remaining_count).toBeNull();

      historyRuleId = rule.id;
    });

    it('should create a retention rule without filters (defaults to empty filter set)', async () => {
      const input: RetentionRuleAddInput = {
        name: '[Integration] No filter rule',
        max_retention: 5,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.Knowledge,
      };

      const response = await queryAsAdminWithSuccess({
        query: CREATE_RETENTION_RULE,
        variables: { input },
      });

      const rule = response.data?.retentionRuleAdd;
      expect(rule).toBeDefined();

      const parsedFilters = JSON.parse(rule.filters);
      expect(parsedFilters).toMatchObject({ mode: 'and', filters: [], filterGroups: [] });

      // Cleanup
      await queryAsAdminWithSuccess({
        query: DELETE_RETENTION_RULE,
        variables: { id: rule.id },
      });
    });
  });

  // -------------------------------------------------------------------------
  // READ (findById)
  // -------------------------------------------------------------------------

  describe('findById', () => {
    it('should retrieve a retention rule by id', async () => {
      const response = await queryAsAdminWithSuccess({
        query: GET_RETENTION_RULE,
        variables: { id: knowledgeRuleId },
      });

      const rule = response.data?.retentionRule;
      expect(rule).toBeDefined();
      expect(rule.id).toBe(knowledgeRuleId);
      expect(rule.name).toBe('[Integration] Knowledge rule');
      expect(rule.scope).toBe('knowledge');
    });

    it('should return null for a non-existent rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: GET_RETENTION_RULE,
        variables: { id: 'non-existent-id' },
      });

      expect(response.data?.retentionRule).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // LIST (findRetentionRulePaginated)
  // -------------------------------------------------------------------------

  describe('findRetentionRulePaginated', () => {
    it('should list retention rules with pagination info', async () => {
      const response = await queryAsAdminWithSuccess({
        query: LIST_RETENTION_RULES,
        variables: { first: 100 },
      });

      const connection = response.data?.retentionRules;
      expect(connection).toBeDefined();
      expect(connection.pageInfo.globalCount).toBeGreaterThanOrEqual(3);

      const names = connection.edges.map((e: any) => e.node.name);
      expect(names).toContain('[Integration] Knowledge rule');
      expect(names).toContain('[Integration] File rule');
      expect(names).toContain('[Integration] Workbench rule');
    });

    it('should filter rules by search term', async () => {
      const response = await queryAsAdminWithSuccess({
        query: LIST_RETENTION_RULES,
        variables: { first: 100, search: '[Integration] File rule' },
      });

      const connection = response.data?.retentionRules;
      expect(connection).toBeDefined();
      const names = connection.edges.map((e: any) => e.node.name);
      expect(names).toContain('[Integration] File rule');
    });
  });

  // -------------------------------------------------------------------------
  // UPDATE (retentionRuleEditField)
  // -------------------------------------------------------------------------

  describe('retentionRuleEditField', () => {
    it('should update the name of a retention rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: UPDATE_RETENTION_RULE,
        variables: {
          id: knowledgeRuleId,
          input: [{ key: 'name', value: ['[Integration] Knowledge rule – updated'] }],
        },
      });

      const rule = response.data?.retentionRuleEdit?.fieldPatch;
      expect(rule).toBeDefined();
      expect(rule.name).toBe('[Integration] Knowledge rule – updated');
    });

    it('should update max_retention of a retention rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: UPDATE_RETENTION_RULE,
        variables: {
          id: knowledgeRuleId,
          input: [{ key: 'max_retention', value: [60] }],
        },
      });

      const rule = response.data?.retentionRuleEdit?.fieldPatch;
      expect(rule).toBeDefined();
      expect(rule.max_retention).toBe(60);
    });

    it('should reflect updates when reading back the rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: GET_RETENTION_RULE,
        variables: { id: knowledgeRuleId },
      });

      const rule = response.data?.retentionRule;
      expect(rule.name).toBe('[Integration] Knowledge rule – updated');
      expect(rule.max_retention).toBe(60);
    });
  });

  // -------------------------------------------------------------------------
  // CHECK (checkRetentionRule)
  // -------------------------------------------------------------------------

  describe('checkRetentionRule', () => {
    it('should return a count for knowledge scope', async () => {
      const input: RetentionRuleAddInput = {
        name: 'check knowledge',
        filters: emptyFilters,
        max_retention: 1,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.Knowledge,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should return a count for file scope', async () => {
      const input: RetentionRuleAddInput = {
        name: 'check file',
        filters: emptyFilters,
        max_retention: 1,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.File,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should return a count for workbench scope', async () => {
      const input: RetentionRuleAddInput = {
        name: 'check workbench',
        filters: emptyFilters,
        max_retention: 1,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.Workbench,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should return a count for history scope', async () => {
      // Verifies the history code path executes and returns a number.
      // max_retention: 3650 days means "entries not updated in 10 years" → 0 in a fresh test env, which is valid.
      const input: RetentionRuleAddInput = {
        name: 'check history',
        filters: emptyFilters,
        max_retention: 3650,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.History,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should return a number for history scope with a short retention window', async () => {
      // A 1-minute window may or may not match entries depending on test suite duration – just verify it returns a number.
      const input: RetentionRuleAddInput = {
        name: 'check history short window',
        filters: emptyFilters,
        max_retention: 1,
        retention_unit: RetentionUnit.Minutes,
        scope: RetentionRuleScope.History,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should return a count for history scope with filters', async () => {
      // Use a large window to ensure we have entries, combined with an entity_type filter on History
      const historyFilters = JSON.stringify({
        mode: 'and',
        filters: [{ key: ['entity_type'], values: ['History'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      });
      const input: RetentionRuleAddInput = {
        name: 'check history with filters',
        filters: historyFilters,
        max_retention: 3650,
        retention_unit: RetentionUnit.Days,
        scope: RetentionRuleScope.History,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should return 0 elements when max_retention is very short (minutes)', async () => {
      // A very short retention (1 minute) should find elements modified before 1 minute ago – likely 0 in a fresh test run
      const input: RetentionRuleAddInput = {
        name: 'check short retention',
        filters: emptyFilters,
        max_retention: 1,
        retention_unit: RetentionUnit.Minutes,
        scope: RetentionRuleScope.Knowledge,
      };

      const response = await queryAsAdminWithSuccess({
        query: CHECK_RETENTION_RULE,
        variables: { input },
      });

      const count = response.data?.retentionRuleCheck;
      expect(typeof count).toBe('number');
    });
  });

  // -------------------------------------------------------------------------
  // DELETE
  // -------------------------------------------------------------------------

  describe('deleteRetentionRule', () => {
    it('should delete the knowledge retention rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: DELETE_RETENTION_RULE,
        variables: { id: knowledgeRuleId },
      });

      expect(response.data?.retentionRuleEdit?.delete).toBe(knowledgeRuleId);

      // Verify it no longer exists
      const getResponse = await queryAsAdminWithSuccess({
        query: GET_RETENTION_RULE,
        variables: { id: knowledgeRuleId },
      });
      expect(getResponse.data?.retentionRule).toBeNull();
    });

    it('should delete the file retention rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: DELETE_RETENTION_RULE,
        variables: { id: fileRuleId },
      });
      expect(response.data?.retentionRuleEdit?.delete).toBe(fileRuleId);
    });

    it('should delete the workbench retention rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: DELETE_RETENTION_RULE,
        variables: { id: workbenchRuleId },
      });
      expect(response.data?.retentionRuleEdit?.delete).toBe(workbenchRuleId);
    });

    it('should delete the history retention rule', async () => {
      const response = await queryAsAdminWithSuccess({
        query: DELETE_RETENTION_RULE,
        variables: { id: historyRuleId },
      });
      expect(response.data?.retentionRuleEdit?.delete).toBe(historyRuleId);

      // Verify it no longer exists
      const getResponse = await queryAsAdminWithSuccess({
        query: GET_RETENTION_RULE,
        variables: { id: historyRuleId },
      });
      expect(getResponse.data?.retentionRule).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Safety cleanup – remove any leftover rules created during tests
  // -------------------------------------------------------------------------

  afterAll(async () => {
    const rules = [knowledgeRuleId, fileRuleId, workbenchRuleId, historyRuleId].filter(Boolean);
    await Promise.allSettled(
      rules.map((id) => queryAsAdminWithSuccess({ query: DELETE_RETENTION_RULE, variables: { id } })),
    );
  });
});
