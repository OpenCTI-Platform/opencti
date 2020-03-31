import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { authentication } from '../../../src/domain/user';

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
      name
      description
      roles {
        name
        description
        default_assignation
      }
      capabilities {
        name
        description
      }
      token
    }
  }
`;

describe('User resolver standard behavior', () => {
  let userInternalId;
  let groupInternalId;
  let userGroupRelationId;
  let userToken;
  const userStixId = 'identity--a186efb8-5e41-4082-817e-993e378d32f0';
  it('should user created', async () => {
    const CREATE_QUERY = gql`
      mutation UserAdd($input: UserAddInput) {
        userAdd(input: $input) {
          id
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
        stix_id_key: userStixId,
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
  });
  it('should user loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.id).toEqual(userInternalId);
  });
  it('should user loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.id).toEqual(userInternalId);
  });
  it('should me loaded', async () => {
    // TODO: Ask to Julien
    /*
    const userResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    const ME_QUERY = gql`
      query me {
        me {
          id
        }
      }
    `;
    const queryResult = await queryAsUser(userResult.data.user, { query: ME_QUERY });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.me).not.toBeNull();
    expect(queryResult.data.me.id).toEqual(userInternalId); */
  });
  it('should user roles to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.roles.length).toEqual(1);
    expect(queryResult.data.user.roles[0].name).toEqual('Default');
  });
  it('should user capabilities to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.capabilities.length).toEqual(1);
    expect(queryResult.data.user.capabilities[0].name).toEqual('KNOWLEDGE');
  });
  it('should user remove role', async () => {
    const REMOTE_ROLE_QUERY = gql`
      mutation UserEditRemoveRole($id: ID!, $name: String!) {
        userEdit(id: $id) {
          removeRole(name: $name) {
            id
            roles {
              name
              description
              default_assignation
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REMOTE_ROLE_QUERY,
      variables: { id: userInternalId, name: 'Default' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.userEdit).not.toBeNull();
    expect(queryResult.data.userEdit.removeRole.roles.length).toEqual(0);
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
    const user = await authentication(res.data.token);
    expect(user.user_email).toBe('user@mail.com');
    userToken = res.data.token;
  });
  // TODO: Ask to Julien
  /* it('should user login failed', async () => {
    const loginPromise = queryAsAdmin({
      query: LOGIN_QUERY,
      variables: {
        input: {
          email: 'user@mail.com',
          password: 'user-test',
        },
      },
    });
    expect(loginPromise).rejects.toThrow();
  }); */
  it('should user token to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.token).toEqual(userToken);
  });
  it('should list users', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.users.edges.length).toEqual(2);
  });
  it('should update user', async () => {
    const UPDATE_QUERY = gql`
      mutation UserEdit($id: ID!, $input: EditInput!) {
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
  it('should add relation in user', async () => {
    const GROUP_ADD_QUERY = gql`
      mutation GroupAdd($input: GroupAddInput) {
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
        name: 'Group in user',
        description: 'Group in user description',
      },
    };
    const group = await queryAsAdmin({
      query: GROUP_ADD_QUERY,
      variables: GROUP_TO_CREATE,
    });
    expect(group).not.toBeNull();
    expect(group.data.groupAdd).not.toBeNull();
    expect(group.data.groupAdd.name).toEqual('Group in user');
    groupInternalId = group.data.groupAdd.id;
    const RELATION_ADD_QUERY = gql`
      mutation UserEdit($id: ID!, $input: RelationAddInput!) {
        userEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on User {
                groups {
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
        id: userInternalId,
        input: {
          fromRole: 'member',
          toId: group.data.groupAdd.id,
          toRole: 'grouping',
          through: 'membership',
        },
      },
    });
    expect(queryResult.data.userEdit.relationAdd.from.groups.edges.length).toEqual(1);
    userGroupRelationId = queryResult.data.userEdit.relationAdd.from.groups.edges[0].relation.id;
  });
  it('should delete relation in user', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation UserEdit($id: ID!, $relationId: ID!) {
        userEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
            groups {
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
        id: userInternalId,
        relationId: userGroupRelationId,
      },
    });
    expect(queryResult.data.userEdit.relationDelete.groups.edges.length).toEqual(0);
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
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });
});
