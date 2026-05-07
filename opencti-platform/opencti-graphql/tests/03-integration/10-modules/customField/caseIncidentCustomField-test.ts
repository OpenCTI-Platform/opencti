/**
 * Integration tests for custom field values on CaseIncident.
 *
 * Tests cover:
 *   1. Setting a custom field value (caseIncidentSetCustomFieldValue)
 *   2. Reading custom field values on CaseIncident (customFieldValues resolver)
 *   3. Removing a custom field value (caseIncidentRemoveCustomFieldValue)
 *   4. Business rule validation (min_value / max_value / wrong entity type)
 *   5. Filtering CaseIncidents by custom field value (customFieldValue filter key)
 *      — operators: eq, gt, gte, lt, lte, nil, not_nil
 *
 * Notes:
 * - Currently only the `integer` field_type is implemented.
 *   Future types (string, boolean…) should be added in new describe blocks.
 * - The `operator` for the custom field filter must be placed at the top-level
 *   Filter.operator, NOT inside the values array (enum inside Any is always null).
 *   Correct syntax:
 *     { key: ["customFieldValue"], operator: gt, values: [
 *         { key: "field_name", values: ["x_opencti_<name>"] },
 *         { key: "int_value",  values: ["3"] }
 *       ]
 *     }
 *
 * Location: tests/03-integration/10-modules/customField/
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../../utils/testQueryHelper';

// ---------------------------------------------------------------------------
// GraphQL documents — CustomFieldDefinition helpers
// ---------------------------------------------------------------------------

const CREATE_DEFINITION = gql`
  mutation TestCFDAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) {
      id
      name
      field_type
      min_value
      max_value
    }
  }
`;
const ADD_ENTITY_TYPE = gql`
  mutation TestCFDAddEntityType($id: ID!, $entityType: String!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType) {
      id
      entity_types
    }
  }
`;
const DELETE_DEFINITION = gql`
  mutation TestCFDDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;

// ---------------------------------------------------------------------------
// GraphQL documents — CaseIncident
// ---------------------------------------------------------------------------

const CREATE_CASE = gql`
  mutation TestCICreate($input: CaseIncidentAddInput!) {
    caseIncidentAdd(input: $input) {
      id
      name
    }
  }
`;

const DELETE_CASE = gql`
  mutation TestCIDelete($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

const READ_CASE_CUSTOM_FIELDS = gql`
  query TestCIGet($id: String!) {
    caseIncident(id: $id) {
      id
      name
      customFieldValues {
        field_id
        field_name
        int_value
      }
    }
  }
`;

const SET_CUSTOM_FIELD = gql`
  mutation TestCISetCustomField($id: ID!, $fieldId: ID!, $value: String!) {
    caseIncidentSetCustomFieldValue(id: $id, fieldId: $fieldId, value: $value) {
      id
      customFieldValues {
        field_id
        field_name
        int_value
      }
    }
  }
`;

const REMOVE_CUSTOM_FIELD = gql`
  mutation TestCIRemoveCustomField($id: ID!, $fieldId: ID!) {
    caseIncidentRemoveCustomFieldValue(id: $id, fieldId: $fieldId) {
      id
      customFieldValues {
        field_id
        field_name
        int_value
      }
    }
  }
`;

const LIST_CASES_WITH_FILTER = gql`
  query TestCIList($filters: FilterGroup) {
    caseIncidents(filters: $filters) {
      edges {
        node {
          id
          name
          customFieldValues {
            field_name
            int_value
          }
        }
      }
    }
  }
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a customFieldValue FilterGroup for a given operator and int value.
 * Operator must be at the Filter level (not inside values) — see file header.
 */
const buildCustomFieldFilter = (fieldName: string, operator: string, intValue?: string) => ({
  mode: 'and',
  filters: [{
    key: ['customFieldValue'],
    operator,
    values: [
      { key: 'field_name', values: [fieldName] },
      { key: 'int_value', values: intValue !== undefined ? [intValue] : [] },
    ],
  }],
  filterGroups: [],
});

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('CaseIncident — custom field values (integer type)', () => {
  // Shared state across tests in this suite
  let definitionId: string;
  let fieldName: string; // "x_opencti_<name>" — the name stored in ES
  let caseAId: string; // int_value = 3
  let caseBId: string; // int_value = 7
  let caseCId: string; // no custom field value set

  // -------------------------------------------------------------------------
  // Setup — create 1 CustomFieldDefinition + 3 CaseIncidents
  // -------------------------------------------------------------------------

  beforeAll(async () => {
    // 1. Create the definition (min=1, max=10, integer)
    const defResult = await queryAsAdmin({
      query: CREATE_DEFINITION,
      variables: {
        input: {
          name: 'test_cf_priority',
          label: 'Test CF Priority',
          field_type: 'integer',
          mandatory: false,
          min_value: 1,
          max_value: 10,
        },
      },
    });
    expect(defResult.errors).toBeUndefined();
    const def = defResult.data?.customFieldDefinitionAdd;
    definitionId = def.id;
    fieldName = `x_opencti_${def.name}`; // → "x_opencti_test_cf_priority"

    // 2. Associate it to Case-Incident
    const assocResult = await queryAsAdmin({
      query: ADD_ENTITY_TYPE,
      variables: { id: definitionId, entityType: 'Case-Incident' },
    });
    expect(assocResult.errors).toBeUndefined();

    // 3. Create CaseIncident A — will receive int_value = 3
    const caseA = await queryAsAdmin({
      query: CREATE_CASE,
      variables: { input: { name: 'Test CI A — custom field POC' } },
    });
    expect(caseA.errors).toBeUndefined();
    caseAId = caseA.data?.caseIncidentAdd.id;

    // 4. Create CaseIncident B — will receive int_value = 7
    const caseB = await queryAsAdmin({
      query: CREATE_CASE,
      variables: { input: { name: 'Test CI B — custom field POC' } },
    });
    expect(caseB.errors).toBeUndefined();
    caseBId = caseB.data?.caseIncidentAdd.id;

    // 5. Create CaseIncident C — no custom field set (used for nil/not_nil tests)
    const caseC = await queryAsAdmin({
      query: CREATE_CASE,
      variables: { input: { name: 'Test CI C — custom field POC' } },
    });
    expect(caseC.errors).toBeUndefined();
    caseCId = caseC.data?.caseIncidentAdd.id;
  });

  afterAll(async () => {
    // Cleanup in reverse order
    if (caseAId) await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseAId } });
    if (caseBId) await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseBId } });
    if (caseCId) await queryAsAdmin({ query: DELETE_CASE, variables: { id: caseCId } });
    if (definitionId) await queryAsAdmin({ query: DELETE_DEFINITION, variables: { id: definitionId } });
  });

  // -------------------------------------------------------------------------
  // SET — happy path
  // -------------------------------------------------------------------------

  it('should set int_value = 3 on CaseIncident A', async () => {
    const result = await queryAsAdmin({
      query: SET_CUSTOM_FIELD,
      variables: { id: caseAId, fieldId: definitionId, value: '3' },
    });
    expect(result.errors).toBeUndefined();
    const values = result.data?.caseIncidentSetCustomFieldValue?.customFieldValues;
    expect(values).toBeDefined();
    const entry = values.find((v: any) => v.field_id === definitionId);
    expect(entry).toBeDefined();
    expect(entry.field_name).toBe(fieldName);
    expect(entry.int_value).toBe(3);
  });

  it('should set int_value = 7 on CaseIncident B', async () => {
    const result = await queryAsAdmin({
      query: SET_CUSTOM_FIELD,
      variables: { id: caseBId, fieldId: definitionId, value: '7' },
    });
    expect(result.errors).toBeUndefined();
    const entry = result.data?.caseIncidentSetCustomFieldValue?.customFieldValues
      .find((v: any) => v.field_id === definitionId);
    expect(entry?.int_value).toBe(7);
  });

  // -------------------------------------------------------------------------
  // READ — customFieldValues resolver
  // -------------------------------------------------------------------------

  it('should read customFieldValues from CaseIncident A via query', async () => {
    const result = await queryAsAdmin({ query: READ_CASE_CUSTOM_FIELDS, variables: { id: caseAId } });
    expect(result.errors).toBeUndefined();
    const ci = result.data?.caseIncident;
    expect(ci).toBeDefined();
    const entry = ci.customFieldValues?.find((v: any) => v.field_id === definitionId);
    expect(entry).toBeDefined();
    expect(entry.field_name).toBe(fieldName);
    expect(entry.int_value).toBe(3);
  });

  it('should return empty customFieldValues for CaseIncident C (no value set)', async () => {
    const result = await queryAsAdmin({ query: READ_CASE_CUSTOM_FIELDS, variables: { id: caseCId } });
    expect(result.errors).toBeUndefined();
    const vals = result.data?.caseIncident?.customFieldValues ?? [];
    expect(vals.find((v: any) => v.field_id === definitionId)).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // SET — overwrite existing value
  // -------------------------------------------------------------------------

  it('should overwrite int_value on CaseIncident A from 3 to 5', async () => {
    const result = await queryAsAdmin({
      query: SET_CUSTOM_FIELD,
      variables: { id: caseAId, fieldId: definitionId, value: '5' },
    });
    expect(result.errors).toBeUndefined();
    const entry = result.data?.caseIncidentSetCustomFieldValue?.customFieldValues
      .find((v: any) => v.field_id === definitionId);
    expect(entry?.int_value).toBe(5);
    // Reset back to 3 for filter tests that follow
    await queryAsAdmin({ query: SET_CUSTOM_FIELD, variables: { id: caseAId, fieldId: definitionId, value: '3' } });
  });

  // -------------------------------------------------------------------------
  // SET — business rule errors (integer type)
  // -------------------------------------------------------------------------

  it('should reject a value below min_value (min=1)', async () => {
    const result = await queryAsAdmin({
      query: SET_CUSTOM_FIELD,
      variables: { id: caseAId, fieldId: definitionId, value: '0' },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors![0].message).toMatch(/below min_value/i);
  });

  it('should reject a value above max_value (max=10)', async () => {
    const result = await queryAsAdmin({
      query: SET_CUSTOM_FIELD,
      variables: { id: caseAId, fieldId: definitionId, value: '99' },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors![0].message).toMatch(/exceeds max_value/i);
  });

  it('should reject a non-integer value', async () => {
    const result = await queryAsAdmin({
      query: SET_CUSTOM_FIELD,
      variables: { id: caseAId, fieldId: definitionId, value: 'abc' },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors![0].message).toMatch(/integer/i);
  });

  it('should reject a definition not associated to Case-Incident', async () => {
    // Create a definition without associating it to Case-Incident
    const unlinkedDef = await queryAsAdmin({
      query: CREATE_DEFINITION,
      variables: {
        input: { name: 'unlinked_field', label: 'Unlinked', field_type: 'integer', mandatory: false },
      },
    });
    const unlinkedId = unlinkedDef.data?.customFieldDefinitionAdd.id;
    try {
      const result = await queryAsAdmin({
        query: SET_CUSTOM_FIELD,
        variables: { id: caseAId, fieldId: unlinkedId, value: '5' },
      });
      expect(result.errors).toBeDefined();
      expect(result.errors![0].message).toMatch(/not applicable to Case-Incident/i);
    } finally {
      await queryAsAdmin({ query: DELETE_DEFINITION, variables: { id: unlinkedId } });
    }
  });

  // -------------------------------------------------------------------------
  // REMOVE
  // -------------------------------------------------------------------------

  it('should remove the custom field value from CaseIncident A then re-set it', async () => {
    // Remove
    const removeResult = await queryAsAdmin({
      query: REMOVE_CUSTOM_FIELD,
      variables: { id: caseAId, fieldId: definitionId },
    });
    expect(removeResult.errors).toBeUndefined();
    const afterRemove = removeResult.data?.caseIncidentRemoveCustomFieldValue?.customFieldValues ?? [];
    expect(afterRemove.find((v: any) => v.field_id === definitionId)).toBeUndefined();

    // Re-set for following filter tests
    await queryAsAdmin({ query: SET_CUSTOM_FIELD, variables: { id: caseAId, fieldId: definitionId, value: '3' } });
  });

  // -------------------------------------------------------------------------
  // FILTER — eq
  // eq is converted internally to gte+lte with the same value
  // -------------------------------------------------------------------------

  it('filter eq: should return only CaseIncident A (int_value = 3)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'eq', '3') },
    });
    expect(result.errors).toBeUndefined();
    const edges = result.data?.caseIncidents.edges ?? [];
    const ids = edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).not.toContain(caseBId);
    expect(ids).not.toContain(caseCId);
  });

  it('filter eq: should return only CaseIncident B (int_value = 7)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'eq', '7') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseBId);
    expect(ids).not.toContain(caseAId);
  });

  // -------------------------------------------------------------------------
  // FILTER — gt
  // -------------------------------------------------------------------------

  it('filter gt 3: should return CaseIncident B (7 > 3) but not A (3 is not > 3)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'gt', '3') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseBId);
    expect(ids).not.toContain(caseAId);
    expect(ids).not.toContain(caseCId);
  });

  it('filter gt 1: should return both A (3) and B (7)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'gt', '1') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).toContain(caseBId);
    expect(ids).not.toContain(caseCId);
  });

  // -------------------------------------------------------------------------
  // FILTER — gte
  // -------------------------------------------------------------------------

  it('filter gte 3: should return both A (3 >= 3) and B (7 >= 3)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'gte', '3') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).toContain(caseBId);
    expect(ids).not.toContain(caseCId);
  });

  it('filter gte 7: should return only CaseIncident B', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'gte', '7') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseBId);
    expect(ids).not.toContain(caseAId);
  });

  // -------------------------------------------------------------------------
  // FILTER — lt / lte
  // -------------------------------------------------------------------------

  it('filter lt 7: should return only CaseIncident A (3 < 7)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'lt', '7') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).not.toContain(caseBId);
  });

  it('filter lte 3: should return only CaseIncident A (3 <= 3)', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'lte', '3') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).not.toContain(caseBId);
  });

  // -------------------------------------------------------------------------
  // FILTER — range combination (gte + lte in same filterGroup)
  // -------------------------------------------------------------------------

  it('filter range gte 3 AND lte 5: should return only CaseIncident A (3 in [3..5])', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: {
        filters: {
          mode: 'and',
          filters: [
            {
              key: ['customFieldValue'],
              operator: 'gte',
              values: [
                { key: 'field_name', values: [fieldName] },
                { key: 'int_value', values: ['3'] },
              ],
            },
            {
              key: ['customFieldValue'],
              operator: 'lte',
              values: [
                { key: 'field_name', values: [fieldName] },
                { key: 'int_value', values: ['5'] },
              ],
            },
          ],
          filterGroups: [],
        },
      },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).not.toContain(caseBId); // 7 is outside [3..5]
    expect(ids).not.toContain(caseCId);
  });

  // -------------------------------------------------------------------------
  // FILTER — nil / not_nil
  // -------------------------------------------------------------------------

  it('filter not_nil: should include A and B (have value) but not C', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'not_nil') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseAId);
    expect(ids).toContain(caseBId);
    expect(ids).not.toContain(caseCId);
  });

  it('filter nil: should include C (no value) but not A or B', async () => {
    const result = await queryAsAdmin({
      query: LIST_CASES_WITH_FILTER,
      variables: { filters: buildCustomFieldFilter(fieldName, 'nil') },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.caseIncidents.edges.map((e: any) => e.node.id);
    expect(ids).toContain(caseCId);
    expect(ids).not.toContain(caseAId);
    expect(ids).not.toContain(caseBId);
  });
});

// ---------------------------------------------------------------------------
// TODO: Additional field types — add describe blocks here when implemented
// ---------------------------------------------------------------------------
// describe('CaseIncident — custom field values (string type)', () => { ... });
// describe('CaseIncident — custom field values (boolean type)', () => { ... });

