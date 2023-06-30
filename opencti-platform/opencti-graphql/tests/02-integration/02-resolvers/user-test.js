import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { elLoadById } from '../../../src/database/engine';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/schema/stixDomainObject';
import { ADMIN_USER, editorQuery, queryAsAdmin, testContext } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query users(
    $first: Int
    $after: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
    $filters: [UsersFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    users(
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

const LOGIN_QUERY = gql`
  mutation Token($input: UserLoginInput) {
    token(input: $input)
  }
`;

const READ_QUERY = gql`
  query user($id: String!) {
    user(id: $id) {
      id
      standard_id
      name
      description
      groups {
          edges {
              node {
                  id
                  name
              }
          }
      }
      roles {
        id
        standard_id
        name
        description
      }
      capabilities {
        id
        standard_id
        name
        description
      }
      api_token
    }
  }
`;

const LIST_MEMBERS_QUERY = gql`
  query members(
    $first: Int
    $search: String
  ) {
    members(
      first: $first
      search: $search
    ) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

describe('User resolver standard behavior', () => {
  let userInternalId;
  let groupInternalId;
  let userStandardId;
  let roleInternalId;
  let capabilityId;
  it('should user created', async () => {
    const CREATE_QUERY = gql`
      mutation UserAdd($input: UserAddInput!) {
        userAdd(input: $input) {
          id
          standard_id
          name
          user_email
          firstname
          lastname
        }
      }
    `;
    // Create the user
    const USER_TO_CREATE = {
      input: {
        name: 'User',
        description: 'User description',
        password: 'user',
        user_email: 'user@mail.com',
        firstname: 'User',
        lastname: 'OpenCTI',
      },
    };
    const user = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(user).not.toBeNull();
    expect(user.data.userAdd).not.toBeNull();
    expect(user.data.userAdd.name).toEqual('User');
    userInternalId = user.data.userAdd.id;
    userStandardId = user.data.userAdd.standard_id;
  });
  it('should user loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.id).toEqual(userInternalId);
  });
  it('should user loaded by standard id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userStandardId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.id).toEqual(userInternalId);
  });
  it('should user login', async () => {
    const res = await queryAsAdmin({
      query: LOGIN_QUERY,
      variables: {
        input: {
          email: 'user@mail.com',
          password: 'user',
        },
      },
    });
    expect(res).not.toBeNull();
    expect(res.data).not.toBeNull();
    expect(res.data.token).toBeDefined();
  });
  it('should list users', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.users.edges.length).toEqual(5);
  });
  it('should update user', async () => {
    const UPDATE_QUERY = gql`
      mutation UserEdit($id: ID!, $input: [EditInput]!) {
        userEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: userInternalId, input: { key: 'name', value: ['User - test'] } },
    });
    expect(queryResult.data.userEdit.fieldPatch.name).toEqual('User - test');
  });
  it('should context patch user', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation UserEdit($id: ID!, $input: EditContext) {
        userEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: userInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.userEdit.contextPatch.id).toEqual(userInternalId);
  });
  it('should context clean user', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation UserEdit($id: ID!) {
        userEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: userInternalId },
    });
    expect(queryResult.data.userEdit.contextClean.id).toEqual(userInternalId);
  });
  it('should add user in group', async () => {
    const GROUP_ADD_QUERY = gql`
      mutation GroupAdd($input: GroupAddInput!) {
        groupAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the group
    const GROUP_TO_CREATE = {
      input: {
        name: 'Group of user',
        description: 'Group of user description',
      },
    };
    const group = await queryAsAdmin({
      query: GROUP_ADD_QUERY,
      variables: GROUP_TO_CREATE,
    });
    expect(group).not.toBeNull();
    expect(group.data.groupAdd).not.toBeNull();
    expect(group.data.groupAdd.name).toEqual('Group of user');
    groupInternalId = group.data.groupAdd.id;
    const RELATION_ADD_QUERY = gql`
      mutation GroupEdit($id: ID!, $input: InternalRelationshipAddInput!) {
        groupEdit(id: $id) {
          relationAdd(input: $input) {
            id
            to {
              ... on Group {
                members {
                  edges {
                    node {
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
        id: groupInternalId,
        input: {
          fromId: userInternalId,
          relationship_type: 'member-of',
        },
      },
    });
    expect(queryResult.data.groupEdit.relationAdd.to.members.edges.length).toEqual(1);
  });
  it('should user groups to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.groups.edges.length).toEqual(2); // the 2 groups are: 'Group of user' and 'Default'
  });
  it('should add role in group', async () => {
    const ROLE_ADD_QUERY = gql`
        mutation RoleAdd($input: RoleAddInput!) {
            roleAdd(input: $input) {
                id
                name
                description
            }
        }
    `;
    // Create the role
    const ROLE_TO_CREATE = {
      input: {
        name: 'Role in group',
        description: 'Role in group description',
      },
    };
    const role = await queryAsAdmin({
      query: ROLE_ADD_QUERY,
      variables: ROLE_TO_CREATE,
    });
    expect(role).not.toBeNull();
    expect(role.data.roleAdd).not.toBeNull();
    expect(role.data.roleAdd.name).toEqual('Role in group');
    roleInternalId = role.data.roleAdd.id;
    const RELATION_ADD_QUERY = gql`
        mutation GroupEdit($id: ID!, $input: InternalRelationshipAddInput!) {
            groupEdit(id: $id) {
                relationAdd(input: $input) {
                    id
                    from {
                        ... on Group {
                            roles {
                                id
                                name
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
        id: groupInternalId,
        input: {
          toId: roleInternalId,
          relationship_type: 'has-role',
        },
      },
    });
    expect(queryResult.data.groupEdit.relationAdd.from.roles.length).toEqual(1);
  });
  it('should user roles to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.roles.length).toEqual(2); // the 2 roles are: 'Role in group' and 'Default'
  });
  it('should add capability in role', async () => {
    const capabilityStandardId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'KNOWLEDGE' });
    const capability = await elLoadById(testContext, ADMIN_USER, capabilityStandardId);
    capabilityId = capability.id;
    const RELATION_ADD_QUERY = gql`
        mutation RoleEdit($id: ID!, $input: InternalRelationshipAddInput!) {
            roleEdit(id: $id) {
                relationAdd(input: $input) {
                    id
                    from {
                        ... on Role {
                            capabilities {
                                id
                                standard_id
                                name
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
        id: roleInternalId,
        input: {
          toId: capabilityId,
          relationship_type: 'has-capability',
        },
      },
    });
    expect(queryResult.data.roleEdit.relationAdd.from.capabilities.length).toEqual(1);
    expect(queryResult.data.roleEdit.relationAdd.from.capabilities[0].name).toEqual('KNOWLEDGE');
  });
  it('should user capabilities to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.capabilities.length).toEqual(1);
    expect(queryResult.data.user.capabilities[0].name).toEqual('KNOWLEDGE');
  });
  it('should delete relation in user', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation UserEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        userEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            groups {
              edges {
                node {
                  id
                  name
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
        id: userInternalId,
        toId: groupInternalId,
        relationship_type: 'member-of',
      },
    });
    expect(queryResult.data.userEdit.relationDelete.groups.edges.length).toEqual(1);
    expect(queryResult.data.userEdit.relationDelete.groups.edges[0].node.name).toEqual('Default');
    const DELETE_GROUP_QUERY = gql`
      mutation groupDelete($id: ID!) {
        groupEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the group
    await queryAsAdmin({
      query: DELETE_GROUP_QUERY,
      variables: { id: groupInternalId },
    });
  });
  it('should user deleted', async () => {
    const DELETE_QUERY = gql`
      mutation userDelete($id: ID!) {
        userEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the user
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: userInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userStandardId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });
});

describe('User list members query behavior', () => {
  it('Should user lists all members', async () => {
    const queryResult = await editorQuery({ query: LIST_MEMBERS_QUERY, variables: { first: 20 } });
    expect(queryResult.data.members.edges.length).toEqual(16);
    expect(queryResult.data.members.edges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_USER).length).toEqual(4);
    expect(queryResult.data.members.edges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_GROUP).length).toEqual(5);
    expect(queryResult.data.members.edges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION).length).toEqual(7);
  });
});
