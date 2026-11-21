import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const LIST_QUERY = gql`
  query markingDefinitions(
    $first: Int
    $after: ID
    $orderBy: MarkingDefinitionsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    markingDefinitions(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          definition_type
          definition
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query markingDefinition($id: String!) {
    markingDefinition(id: $id) {
      id
      definition_type
      definition
      toStix
    }
  }
`;

describe('MarkingDefinition resolver standard behavior', () => {
  let markingDefinitionInternalId;
  const markingDefinitionStixId = 'marking-definition--35ee3df2-dc60-4bf3-9b57-98222b827a83';
  it('should markingDefinition created', async () => {
    const CREATE_QUERY = gql`
      mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput!) {
        markingDefinitionAdd(input: $input) {
          id
          definition_type
          definition
        }
      }
    `;
    // Create the markingDefinition
    const MARKING_DEFINITION_TO_CREATE = {
      input: {
        stix_id: markingDefinitionStixId,
        definition_type: 'TLP',
        definition: 'TLP:TEST2',
        x_opencti_order: 0,
      },
    };
    const markingDefinition = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: MARKING_DEFINITION_TO_CREATE,
    });
    expect(markingDefinition).not.toBeNull();
    expect(markingDefinition.data.markingDefinitionAdd).not.toBeNull();
    expect(markingDefinition.data.markingDefinitionAdd.definition).toEqual('TLP:TEST2');
    markingDefinitionInternalId = markingDefinition.data.markingDefinitionAdd.id;
  });
  it('should markingDefinition loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: markingDefinitionInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.markingDefinition).not.toBeNull();
    expect(queryResult.data.markingDefinition.id).toEqual(markingDefinitionInternalId);
    expect(queryResult.data.markingDefinition.toStix.length).toBeGreaterThan(5);
  });
  it('should markingDefinition loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: markingDefinitionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.markingDefinition).not.toBeNull();
    expect(queryResult.data.markingDefinition.id).toEqual(markingDefinitionInternalId);
  });
  it('should list markingDefinitions', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 20 } });
    expect(queryResult.data.markingDefinitions.edges.length).toEqual(12);
  });
  it('should list markingDefinitions without option "first"', async () => {
    // https://github.com/OpenCTI-Platform/opencti/issues/7905
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: null } });
    expect(queryResult.data.markingDefinitions.edges.length).toEqual(12);
  });
  it('should update markingDefinition', async () => {
    const UPDATE_QUERY = gql`
      mutation MarkingDefinitionEdit($id: ID!, $input: [EditInput]!) {
        markingDefinitionEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            definition
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: markingDefinitionInternalId, input: { key: 'definition', value: ['TLP:TEST3'] } },
    });
    expect(queryResult.data.markingDefinitionEdit.fieldPatch.definition).toEqual('TLP:TEST3');
  });
  it('should context patch markingDefinition', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation MarkingDefinitionEdit($id: ID!, $input: EditContext) {
        markingDefinitionEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: markingDefinitionInternalId, input: { focusOn: 'definition' } },
    });
    expect(queryResult.data.markingDefinitionEdit.contextPatch.id).toEqual(markingDefinitionInternalId);
  });
  it('should context clean markingDefinition', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation MarkingDefinitionEdit($id: ID!) {
        markingDefinitionEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: markingDefinitionInternalId },
    });
    expect(queryResult.data.markingDefinitionEdit.contextClean.id).toEqual(markingDefinitionInternalId);
  });
  it('should resolve the OASIS TLP 2.0 ids to the static TLP markings', async () => {
    const oasisTlpIds = {
      'TLP:CLEAR': 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487',
      'TLP:GREEN': 'marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb',
      'TLP:AMBER': 'marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421',
      'TLP:AMBER+STRICT': 'marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003',
      'TLP:RED': 'marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1',
    };
    const entries = Object.entries(oasisTlpIds);
    for (let index = 0; index < entries.length; index += 1) {
      const [definition, oasisId] = entries[index];
      const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: oasisId } });
      expect(queryResult.data.markingDefinition).not.toBeNull();
      expect(queryResult.data.markingDefinition.definition_type).toEqual('TLP');
      expect(queryResult.data.markingDefinition.definition).toEqual(definition);
    }
  });
  it('should mark an indicator referencing the OASIS TLP 2.0 RED id as TLP:RED', async () => {
    const INDICATOR_ADD = gql`
      mutation IndicatorAdd($input: IndicatorAddInput!) {
        indicatorAdd(input: $input) {
          id
          objectMarking {
            definition
          }
        }
      }
    `;
    const INDICATOR_DELETE = gql`
      mutation indicatorDelete($id: ID!) {
        indicatorDelete(id: $id)
      }
    `;
    const indicator = await queryAsAdmin({
      query: INDICATOR_ADD,
      variables: {
        input: {
          name: 'Indicator marked with the OASIS TLP 2.0 RED id',
          pattern: "[domain-name:value = 'oasis-tlp-red.example.com']",
          pattern_type: 'stix',
          x_opencti_main_observable_type: 'Domain-Name',
          objectMarking: ['marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1'],
        },
      },
    });
    expect(indicator.errors).toBeUndefined();
    const markings = indicator.data.indicatorAdd.objectMarking.map((m) => m.definition);
    expect(markings).toEqual(['TLP:RED']);
    await queryAsAdmin({ query: INDICATOR_DELETE, variables: { id: indicator.data.indicatorAdd.id } });
  });
  it('should markingDefinition deleted', async () => {
    const DELETE_QUERY = gql`
      mutation markingDefinitionDelete($id: ID!) {
        markingDefinitionEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the markingDefinition
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: markingDefinitionInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: markingDefinitionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.markingDefinition).toBeNull();
  });
});
