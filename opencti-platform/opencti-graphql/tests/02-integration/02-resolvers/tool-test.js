import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query tools(
    $first: Int
    $after: ID
    $orderBy: ToolsOrdering
    $orderMode: OrderingMode
    $filters: [ToolsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    tools(
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
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query tool($id: String!) {
    tool(id: $id) {
      id
      name
      description
      killChainPhases {
        edges {
          node {
            id
          }
        }
      }
      toStix
    }
  }
`;

describe('Tool resolver standard behavior', () => {
  let toolInternalId;
  let toolMarkingDefinitionRelationId;
  const toolStixId = 'tool--50a74e71-131c-4d98-a4b8-24e0441b2587';
  it('should tool created', async () => {
    const CREATE_QUERY = gql`
      mutation ToolAdd($input: ToolAddInput) {
        toolAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the tool
    const TOOL_TO_CREATE = {
      input: {
        name: 'Tool',
        stix_id_key: toolStixId,
        description: 'Tool description',
        killChainPhases: ['2a2202bd-1da6-4668-9fc5-ad1017e974bc'],
      },
    };
    const tool = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: TOOL_TO_CREATE,
    });
    expect(tool).not.toBeNull();
    expect(tool.data.toolAdd).not.toBeNull();
    expect(tool.data.toolAdd.name).toEqual('Tool');
    toolInternalId = tool.data.toolAdd.id;
  });
  it('should tool loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: toolInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.tool).not.toBeNull();
    expect(queryResult.data.tool.id).toEqual(toolInternalId);
    expect(queryResult.data.tool.toStix.length).toBeGreaterThan(5);
    expect(queryResult.data.tool.killChainPhases.edges.length).toEqual(1);
    expect(queryResult.data.tool.killChainPhases.edges[0].node.id).toEqual('2a2202bd-1da6-4668-9fc5-ad1017e974bc');
  });
  it('should tool loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: toolStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.tool).not.toBeNull();
    expect(queryResult.data.tool.id).toEqual(toolInternalId);
  });
  it('should list tools', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.tools.edges.length).toEqual(1);
  });
  it('should update tool', async () => {
    const UPDATE_QUERY = gql`
      mutation ToolEdit($id: ID!, $input: EditInput!) {
        toolEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: toolInternalId, input: { key: 'name', value: ['Tool - test'] } },
    });
    expect(queryResult.data.toolEdit.fieldPatch.name).toEqual('Tool - test');
  });
  it('should context patch tool', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ToolEdit($id: ID!, $input: EditContext) {
        toolEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: toolInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.toolEdit.contextPatch.id).toEqual(toolInternalId);
  });
  it('should context clean tool', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ToolEdit($id: ID!) {
        toolEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: toolInternalId },
    });
    expect(queryResult.data.toolEdit.contextClean.id).toEqual(toolInternalId);
  });
  it('should add relation in tool', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation ToolEdit($id: ID!, $input: RelationAddInput!) {
        toolEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Tool {
                markingDefinitions {
                  edges {
                    node {
                      id
                    }
                    relation {
                      id
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: toolInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.toolEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    toolMarkingDefinitionRelationId =
      queryResult.data.toolEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in tool', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation ToolEdit($id: ID!, $relationId: ID!) {
        toolEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
            markingDefinitions {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: toolInternalId,
        relationId: toolMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.toolEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should tool deleted', async () => {
    const DELETE_QUERY = gql`
      mutation toolDelete($id: ID!) {
        toolEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the tool
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: toolInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: toolStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.tool).toBeNull();
  });
});
