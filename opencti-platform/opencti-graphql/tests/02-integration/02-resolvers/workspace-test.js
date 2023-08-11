import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import {
  ADMIN_USER,
  editorQuery,
  getUserIdByEmail,
  queryAsAdmin,
  testContext,
  USER_EDITOR
} from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { MEMBER_ACCESS_ALL } from '../../../src/utils/access';

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
  const workspaceName = 'an investigation';
  it('should workspace created', async () => {
    // Create the workspace
    const WORKSPACE_TO_CREATE = {
      input: {
        type: 'investigation',
        name: workspaceName,
      },
    };
    const workspace = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE_TO_CREATE,
    });
    expect(workspace).not.toBeNull();
    expect(workspace.data.workspaceAdd).not.toBeNull();
    expect(workspace.data.workspaceAdd.name).toEqual(workspaceName);
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
    const updatedName = `${workspaceName} - updated`;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: workspaceInternalId,
        input: { key: 'name', value: updatedName }
      },
    });
    expect(queryResult.data.workspaceFieldPatch.name).toEqual(updatedName);
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

  it('can not investigate on an entity that does not exists', async () => {
    const nonExistingEntityId = 'non-existing-entity-id';

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation addEntityToInvestigation($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: nonExistingEntityId
        },
      },
    });

    expect(queryResult.errors[0].message).toEqual('Business validation');
  });

  it('can not investigate on an internal object', async () => {
    const queryResult = await queryAsAdmin({
      query: gql`
        mutation investigateOnCity($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: workspaceInternalId
        },
      },
    });

    expect(queryResult.errors[0].message).toEqual('Business validation');
  });

  it('can investigate on an entity', async () => {
    const anEntity = await elLoadById(testContext, ADMIN_USER, 'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85');
    const anEntityId = anEntity.internal_id;

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation investigateOnALocation($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            id
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: anEntityId
        },
      },
    });

    expect(queryResult.data.workspaceFieldPatch.investigated_entities_ids[0]).toEqual(anEntityId);
  });

  it('can not investigate twice on the same entity', async () => {
    const anEntity = await elLoadById(testContext, ADMIN_USER, 'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85');
    const anEntityId = anEntity.internal_id;

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation addEntityToInvestigation($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            id
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: anEntityId
        },
      },
    });

    expect(queryResult.data.workspaceFieldPatch.investigated_entities_ids).toHaveLength(1);
  });

  it('can retrieve the investigated entity object', async () => {
    const anEntity = await elLoadById(testContext, ADMIN_USER, 'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85');
    const anEntityId = anEntity.internal_id;

    const WORKSPACE_STIX_DOMAIN_ENTITIES = gql`
      query workspace($id: String!) {
        workspace(id: $id) {
          id
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
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

    expect(queryResult.data.workspace.objects.edges[0].node.id).toEqual(anEntityId);
  });

  it('exports the investigation as a report along with the investigated entity', async () => {
    const queryResult = await queryAsAdmin({
      query: gql`
        query exportInvestigation($id: String!) {
          workspace(id: $id) {
            id
            toStixReportBundle
          }
        }
      `,
      variables: { id: workspaceInternalId }
    });

    const exportedInvestigationObjects = JSON.parse(queryResult.data.workspace.toStixReportBundle).objects;
    const exportedInvestigationObjectsTypes = exportedInvestigationObjects.map((object) => object.type);

    expect(exportedInvestigationObjectsTypes).toHaveLength(2);
    expect(exportedInvestigationObjectsTypes).toContain('report');
    expect(exportedInvestigationObjectsTypes).toContain('malware');
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
    expect(queryResult.errors.at(0).extensions?.code).toEqual('ForbiddenAccess');
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
      access_right: 'admin',
    }, {
      id: ADMIN_USER.id,
      access_right: 'admin'
    }, {
      id: MEMBER_ACCESS_ALL,
      access_right: 'view'
    }];
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace1InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult.data.workspaceEditAuthorizedMembers.authorizedMembers.length).toEqual(3);
  });

  it('A user can\'t modifiy authorized_members if the update leads to a workspace with no valid admin', async () => {
    const authorizedMembersUpdate = [{
      id: 'not_existing_id',
      access_right: 'admin'
    }, {
      id: ADMIN_USER.id,
      access_right: 'edit'
    }];
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace1InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).extensions?.code).toEqual('FunctionalError');
    expect(queryResult.errors.at(0).extensions?.data.reason).toEqual('Workspace should have at least one admin');
  });

  it('User with edit access right should not update workspace members', async () => {
    const authorizedMembersUpdate = [{
      id: userEditorId,
      access_right: 'admin'
    }, {
      id: ADMIN_USER.id,
      access_right: 'admin'
    }];
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace2InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).extensions?.code).toEqual('ForbiddenAccess');
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
