import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, USER_EDITOR, queryAsAdmin, editorQuery, testContext, getUserIdByEmail } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
    query workspaces(
        $first: Int
        $after: ID
        $orderBy: WorkspacesOrdering
        $orderMode: OrderingMode
        $filters: [WorkspacesFiltering!]
        $filterMode: FilterMode
        $includeAuthorities: Boolean
        $search: String
    ) {
        workspaces(
            first: $first
            after: $after
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
            filterMode: $filterMode
            includeAuthorities: $includeAuthorities
            search: $search
        ) {
          edges {
            node {
              id
              name
              authorizedMembers {
                  id
                  name
                  entity_type
                  access_right
              }
            }
          }
        }
    }
`;

const READ_QUERY = gql`
    query workspace($id: String!) {
        workspace(id: $id) {
            id
            type
            name
        }
    }
`;

const CREATE_QUERY = gql`
    mutation WorkspaceAdd($input: WorkspaceAddInput!) {
        workspaceAdd(input: $input) {
            id
            name
        }
    }
`;

const UPDATE_QUERY = gql`
    mutation WorkspaceEdit($id: ID!, $input: [EditInput!]!) {
        workspaceFieldPatch(id: $id, input: $input) {
            id
            name
        }
    }
`;

const DELETE_QUERY = gql`
    mutation workspaceDelete($id: ID!) {
        workspaceDelete(id: $id)
    }
`;

const UPDATE_MEMBERS_QUERY = gql`
  mutation workspaceEditAuthorizedMembers($id: ID!, $input: [MemberAccessInput!]!) {
    workspaceEditAuthorizedMembers(id: $id, input: $input) {
      id
      name
      authorizedMembers {
        id
        name
        entity_type
        access_right
      }
    }
  }
`;

describe('Workspace resolver standard behavior', () => {
  let workspaceInternalId;
  let stixObjectInternalId;
  it('should workspace created', async () => {
    // Create the workspace
    const WORKSPACE_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'custom dashboard',
      },
    };
    const workspace = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE_TO_CREATE,
    });
    expect(workspace).not.toBeNull();
    expect(workspace.data.workspaceAdd).not.toBeNull();
    expect(workspace.data.workspaceAdd.name).toEqual('custom dashboard');
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
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: workspaceInternalId, input: { key: 'name', value: ['custom dashboard - updated'] } },
    });
    expect(queryResult.data.workspaceFieldPatch.name).toEqual('custom dashboard - updated');
  });
  it('should context patch workspace', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation WorkspaceEdit($id: ID!, $input: EditContext!) {
            workspaceContextPatch(id: $id,  input: $input) {
                id
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: workspaceInternalId, input: { focusOn: 'name' } },
    });
    expect(queryResult.data.workspaceContextPatch.id).toEqual(workspaceInternalId);
  });
  it('should context clean workspace', async () => {
    const CONTEXT_CLEAN_QUERY = gql`
        mutation WorkspaceEdit($id: ID!) {
            workspaceContextClean(id: $id) {
                id
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_CLEAN_QUERY,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult.data.workspaceContextClean.id).toEqual(workspaceInternalId);
  });
  it('should add relation in workspace', async () => {
    const city = await elLoadById(testContext, ADMIN_USER, 'location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c');
    stixObjectInternalId = city.internal_id;

    const RELATION_ADD_QUERY = gql`
        mutation WorkspaceEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
            workspaceRelationAdd(id: $id, input: $input) {
                id
                to {
                    ... on BasicObject {
                        id
                        entity_type
                        parent_types
                    }
                    ... on BasicRelationship {
                        id
                        entity_type
                        parent_types
                    }
                }
            }
        }
    `;

    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: workspaceInternalId,
        input: {
          toId: stixObjectInternalId,
          relationship_type: 'has-reference',
        },
      },
    });
    expect(queryResult.data.workspaceRelationAdd.to.id).toEqual(stixObjectInternalId);
  });
  it('should workspace stix objects or stix relationships accurate', async () => {
    const WORKSPACE_STIX_DOMAIN_ENTITIES = gql`
            query workspace($id: String!) {
                workspace(id: $id) {
                    id
                    objects {
                        edges {
                            node {
                                ... on BasicObject {
                                    id
                                    standard_id
                                }
                                ... on BasicRelationship {
                                    id
                                    standard_id
                                }
                            }
                        }
                    }
                }
            }
        `;
    const queryResult = await queryAsAdmin({
      query: WORKSPACE_STIX_DOMAIN_ENTITIES,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).not.toBeNull();
    expect(queryResult.data.workspace.objects.edges.length).toEqual(1);
  });
  it('should delete relation in workspace', async () => {
    const RELATION_DELETE_QUERY = gql`
        mutation WorkspaceEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
            workspaceRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
                id
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: workspaceInternalId,
        toId: stixObjectInternalId,
        relationship_type: 'has-reference',
      },
    });
    expect(queryResult.data.workspaceRelationDelete.id).toEqual(workspaceInternalId);
  });
  it('should workspace deleted', async () => {
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

describe('Workspace member access behavior', () => {
  let workspace1InternalId;
  let workspace2InternalId;
  let workspace3InternalId;
  let workspace4InternalId;
  let userEditorId;
  it('should 4 workspaces created', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    // Create the workspace
    const WORKSPACE1_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace1',
        authorized_members: [{
          id: userEditorId,
          access_right: 'admin'
        }]
      },
    };
    const WORKSPACE2_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace2',
        authorized_members: [{
          id: userEditorId,
          access_right: 'edit'
        }]
      },
    };
    const WORKSPACE3_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace3',
        authorized_members: [{
          id: userEditorId,
          access_right: 'view'
        }]
      },
    };
    const WORKSPACE4_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace4',
        authorized_members: [{
          id: ADMIN_USER.id, // or any other user_id
          access_right: 'admin'
        }]
      }
    };
    const workspace1 = await editorQuery({
      query: CREATE_QUERY,
      variables: WORKSPACE1_TO_CREATE,
    });
    expect(workspace1.data.workspaceAdd).not.toBeNull();
    expect(workspace1.data.workspaceAdd.name).toEqual('workspace1');
    workspace1InternalId = workspace1.data.workspaceAdd.id;

    const workspace2 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE2_TO_CREATE,
    });
    expect(workspace2.data.workspaceAdd).not.toBeNull();
    expect(workspace2.data.workspaceAdd.name).toEqual('workspace2');
    workspace2InternalId = workspace2.data.workspaceAdd.id;

    const workspace3 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE3_TO_CREATE,
    });
    expect(workspace3.data.workspaceAdd).not.toBeNull();
    expect(workspace3.data.workspaceAdd.name).toEqual('workspace3');
    workspace3InternalId = workspace3.data.workspaceAdd.id;

    const workspace4 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE4_TO_CREATE,
    });
    expect(workspace4.data.workspaceAdd).not.toBeNull();
    expect(workspace4.data.workspaceAdd.name).toEqual('workspace4');
    workspace4InternalId = workspace4.data.workspaceAdd.id;
  });

  it('Admin gets only his 3 created workspaces', async () => {
    const queryResultDefault = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResultDefault.data.workspaces.edges.length).toEqual(3);
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.workspaces.edges.length).toEqual(3);
  });

  it('Admin gets all 4 workspaces when bypass', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10, includeAuthorities: true } });
    expect(queryResult.data.workspaces.edges.length).toEqual(4);
  });

  it('User gets only the 3 shared workspaces', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.workspaces.edges.length).toEqual(3);
  });

  it('User with view access right cannot update workspace3', async () => {
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: workspace3InternalId, input: { key: 'name', value: ['custom dashboard3'] } },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('ForbiddenAccess');
  });

  it('User with edit access right updates workspace2', async () => {
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: workspace2InternalId, input: { key: 'name', value: ['custom dashboard2'] } },
    });
    expect(queryResult.data.workspaceFieldPatch.name).toEqual('custom dashboard2');
  });

  it('User with admin access right should update workspace members', async () => {
    const authorizedMembersUpdate = [{
      id: userEditorId,
      access_right: 'admin'
    }, {
      id: ADMIN_USER.id,
      access_right: 'edit'
    }];
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace1InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult.data.workspaceEditAuthorizedMembers.authorizedMembers.length).toEqual(2);
  });

  it('User with edit access right should not update workspace members', async () => {
    const authorizedMembersUpdate = [{
      id: userEditorId,
      access_right: 'admin'
    }, {
      id: ADMIN_USER.id,
      access_right: 'edit'
    }];
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace2InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('ForbiddenAccess');
  });

  it('User with admin access right deletes workspace1', async () => {
    // Delete the workspace
    const editorDeleteResult = await editorQuery({
      query: DELETE_QUERY,
      variables: { id: workspace1InternalId },
    });
    expect(editorDeleteResult).not.toBeNull();
    expect(editorDeleteResult.data.workspaceDelete).toEqual(workspace1InternalId);
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: workspace1InternalId } }); // ce1bd336-6353-4ee8-96c9-4e723196dbf0
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).toBeNull();
  });

  it('Admin delete workspaces', async () => {
    // Delete the workspace
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspace2InternalId },
    });
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspace3InternalId },
    });
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspace4InternalId },
    });

    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspaces.edges.length).toEqual(0);
  });
});
