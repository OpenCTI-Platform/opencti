import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query workspaces($first: Int, $after: ID, $orderBy: WorkspacesOrdering, $orderMode: OrderingMode, $search: String) {
    workspaces(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
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
  query workspace($id: String!) {
    workspace(id: $id) {
      id
      workspace_type
      name
      description
    }
  }
`;

describe('Workspace resolver standard behavior', () => {
  let workspaceInternalId;
  it('should workspace created', async () => {
    const CREATE_QUERY = gql`
      mutation WorkspaceAdd($input: WorkspaceAddInput) {
        workspaceAdd(input: $input) {
          id
          workspace_type
          name
          description
        }
      }
    `;
    // Create the workspace
    const WORKSPACE_TO_CREATE = {
      input: {
        workspace_type: 'explore',
        name: 'Test Workspace',
        description: 'A new workspace',
      },
    };
    const workspace = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE_TO_CREATE,
    });
    expect(workspace).not.toBeNull();
    expect(workspace.data.workspaceAdd).not.toBeNull();
    expect(workspace.data.workspaceAdd.workspace_type).toEqual('explore');
    workspaceInternalId = workspace.data.workspaceAdd.id;
  });
  it('should workspace loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: workspaceInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).not.toBeNull();
    expect(queryResult.data.workspace.id).toEqual(workspaceInternalId);
  });
  it('should list workspaces', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.workspaces.edges.length).toEqual(1);
  });
  it('should update workspace', async () => {
    const UPDATE_QUERY = gql`
      mutation WorkspaceEdit($id: ID!, $input: EditInput!) {
        workspaceEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: workspaceInternalId, input: { key: 'name', value: ['Workspace name 2'] } },
    });
    expect(queryResult.data.workspaceEdit.fieldPatch.name).toEqual('Workspace name 2');
  });
  it('should context patch workspace', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation WorkspaceEdit($id: ID!, $input: EditContext) {
        workspaceEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: workspaceInternalId, input: { focusOn: 'value' } },
    });
    expect(queryResult.data.workspaceEdit.contextPatch.id).toEqual(workspaceInternalId);
  });
  it('should context clean workspace', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation WorkspaceEdit($id: ID!) {
        workspaceEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult.data.workspaceEdit.contextClean.id).toEqual(workspaceInternalId);
  });
  it('should workspace deleted', async () => {
    const DELETE_QUERY = gql`
      mutation workspaceDelete($id: ID!) {
        workspaceEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the workspace
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspaceInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: workspaceInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).toBeNull();
  });
});
