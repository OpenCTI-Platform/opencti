import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query markingDefinitions(
    $first: Int
    $after: ID
    $orderBy: MarkingDefinitionsOrdering
    $orderMode: OrderingMode
    $filters: [MarkingDefinitionsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    markingDefinitions(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
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
      mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput) {
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
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.markingDefinitions.edges.length).toEqual(8);
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
