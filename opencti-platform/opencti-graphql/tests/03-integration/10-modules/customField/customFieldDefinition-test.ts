/**
 * Integration tests for the CustomFieldDefinition module.
 *
 * Tests cover the full CRUD lifecycle of CustomFieldDefinition:
 *   - create (customFieldDefinitionAdd)
 *   - read by id (customFieldDefinition)
 *   - list/paginate (customFieldDefinitions)
 *   - patch a field (customFieldDefinitionFieldPatch)
 *   - add / remove entity type association
 *   - delete (customFieldDefinitionDelete)
 *
 * Note: currently only the `integer` field_type is implemented.
 * Additional field types (string, boolean, date…) should be added in dedicated
 * describe blocks below without modifying the existing ones.
 *
 * Location: tests/03-integration/10-modules/customField/
 * Run via:  yarn test:ci-integration-sync (or the test suite that includes 10-modules)
 */

import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../../utils/testQueryHelper';

// ---------------------------------------------------------------------------
// GraphQL documents
// ---------------------------------------------------------------------------

const CREATE_DEFINITION = gql`
  mutation CustomFieldDefinitionAdd($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) {
      id
      name
      label
      field_type
      mandatory
      min_value
      max_value
      entity_types
      description
    }
  }
`;

const READ_DEFINITION = gql`
  query CustomFieldDefinition($id: String!) {
    customFieldDefinition(id: $id) {
      id
      name
      label
      field_type
      mandatory
      min_value
      max_value
      entity_types
      description
    }
  }
`;

const LIST_DEFINITIONS = gql`
  query CustomFieldDefinitions($first: Int, $filters: FilterGroup) {
    customFieldDefinitions(first: $first, filters: $filters) {
      edges {
        node {
          id
          name
          label
          field_type
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

const PATCH_DEFINITION = gql`
  mutation CustomFieldDefinitionFieldPatch($id: ID!, $input: [EditInput!]!) {
    customFieldDefinitionFieldPatch(id: $id, input: $input) {
      id
      label
      description
    }
  }
`;

const ADD_ENTITY_TYPE = gql`
  mutation CustomFieldDefinitionAddEntityType($id: ID!, $entityType: String!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType) {
      id
      entity_types
    }
  }
`;

const REMOVE_ENTITY_TYPE = gql`
  mutation CustomFieldDefinitionRemoveEntityType($id: ID!, $entityType: String!) {
    customFieldDefinitionRemoveEntityType(id: $id, entityType: $entityType) {
      id
      entity_types
    }
  }
`;

const DELETE_DEFINITION = gql`
  mutation CustomFieldDefinitionDelete($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const createIntegerDefinition = async (name: string, overrides: Record<string, unknown> = {}) => {
  const result = await queryAsAdmin({
    query: CREATE_DEFINITION,
    variables: {
      input: {
        name,
        label: `Test label for ${name}`,
        field_type: 'integer',
        mandatory: false,
        min_value: 1,
        max_value: 10,
        ...overrides,
      },
    },
  });
  expect(result.errors).toBeUndefined();
  return result.data?.customFieldDefinitionAdd;
};

const deleteDefinition = async (id: string) => {
  await queryAsAdmin({ query: DELETE_DEFINITION, variables: { id } });
};

// ---------------------------------------------------------------------------
// Tests — integer field type (only type currently supported)
// ---------------------------------------------------------------------------

describe('CustomFieldDefinition — integer field_type', () => {
  let definitionId: string;

  afterAll(async () => {
    if (definitionId) await deleteDefinition(definitionId);
  });

  // --- CREATE ---

  it('should create a CustomFieldDefinition with field_type=integer', async () => {
    const def = await createIntegerDefinition('test_priority', { description: 'POC priority field' });
    expect(def).toBeDefined();
    expect(def.id).toBeTruthy();
    expect(def.name).toBe('test_priority');
    expect(def.label).toBe('Test label for test_priority');
    expect(def.field_type).toBe('integer');
    expect(def.mandatory).toBe(false);
    expect(def.min_value).toBe(1);
    expect(def.max_value).toBe(10);
    expect(def.description).toBe('POC priority field');
    definitionId = def.id;
  });

  // --- READ ---

  it('should load a CustomFieldDefinition by internal id', async () => {
    const result = await queryAsAdmin({ query: READ_DEFINITION, variables: { id: definitionId } });
    expect(result.errors).toBeUndefined();
    const def = result.data?.customFieldDefinition;
    expect(def).toBeDefined();
    expect(def.id).toBe(definitionId);
    expect(def.name).toBe('test_priority');
    expect(def.field_type).toBe('integer');
  });

  it('should return null for a non-existent id', async () => {
    const result = await queryAsAdmin({ query: READ_DEFINITION, variables: { id: 'non-existent-id' } });
    expect(result.errors).toBeUndefined();
    expect(result.data?.customFieldDefinition).toBeNull();
  });

  // --- LIST ---

  it('should list CustomFieldDefinitions and include the created one', async () => {
    const result = await queryAsAdmin({ query: LIST_DEFINITIONS, variables: { first: 50 } });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.customFieldDefinitions.edges.map((e: any) => e.node.id);
    expect(ids).toContain(definitionId);
  });

  it('should filter CustomFieldDefinitions by name', async () => {
    const result = await queryAsAdmin({
      query: LIST_DEFINITIONS,
      variables: {
        first: 10,
        filters: {
          mode: 'and',
          filters: [{ key: ['name'], values: ['test_priority'] }],
          filterGroups: [],
        },
      },
    });
    expect(result.errors).toBeUndefined();
    const edges = result.data?.customFieldDefinitions.edges;
    expect(edges.length).toBeGreaterThanOrEqual(1);
    expect(edges.some((e: any) => e.node.id === definitionId)).toBe(true);
  });

  // --- PATCH ---

  it('should patch the label of a CustomFieldDefinition', async () => {
    const result = await queryAsAdmin({
      query: PATCH_DEFINITION,
      variables: {
        id: definitionId,
        input: [{ key: 'label', value: ['Updated label'] }],
      },
    });
    expect(result.errors).toBeUndefined();
    expect(result.data?.customFieldDefinitionFieldPatch.label).toBe('Updated label');
  });

  // --- entity_types association ---

  it('should associate a CustomFieldDefinition to Case-Incident', async () => {
    const result = await queryAsAdmin({
      query: ADD_ENTITY_TYPE,
      variables: { id: definitionId, entityType: 'Case-Incident' },
    });
    expect(result.errors).toBeUndefined();
    expect(result.data?.customFieldDefinitionAddEntityType.entity_types).toContain('Case-Incident');
  });

  it('should list definitions filtered by entity_types = Case-Incident', async () => {
    const result = await queryAsAdmin({
      query: LIST_DEFINITIONS,
      variables: {
        first: 50,
        filters: {
          mode: 'and',
          filters: [{ key: ['entity_types'], values: ['Case-Incident'] }],
          filterGroups: [],
        },
      },
    });
    expect(result.errors).toBeUndefined();
    const ids = result.data?.customFieldDefinitions.edges.map((e: any) => e.node.id);
    expect(ids).toContain(definitionId);
  });

  it('should dissociate a CustomFieldDefinition from Case-Incident', async () => {
    const result = await queryAsAdmin({
      query: REMOVE_ENTITY_TYPE,
      variables: { id: definitionId, entityType: 'Case-Incident' },
    });
    expect(result.errors).toBeUndefined();
    expect(result.data?.customFieldDefinitionRemoveEntityType.entity_types).not.toContain('Case-Incident');
  });

  // --- DELETE ---

  it('should delete a CustomFieldDefinition', async () => {
    const result = await queryAsAdmin({ query: DELETE_DEFINITION, variables: { id: definitionId } });
    expect(result.errors).toBeUndefined();
    expect(result.data?.customFieldDefinitionDelete).toBe(definitionId);
    // Verify it is gone
    const readResult = await queryAsAdmin({ query: READ_DEFINITION, variables: { id: definitionId } });
    expect(readResult.data?.customFieldDefinition).toBeNull();
    definitionId = ''; // already deleted, skip afterAll cleanup
  });
});

// ---------------------------------------------------------------------------
// TODO: Additional field types (add here when implemented)
// ---------------------------------------------------------------------------
// describe('CustomFieldDefinition — string field_type', () => { ... });
// describe('CustomFieldDefinition — boolean field_type', () => { ... });
// describe('CustomFieldDefinition — date field_type', () => { ... });

