import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ROLE } from '../../../src/schema/internalObject';

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
      roles {
        id
        standard_id
        name
        description
        default_assignation
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

describe('User resolver standard behavior', () => {
  let userInternalId;
  let groupInternalId;
  let userStandardId;
  it('should user created', async () => {
    const CREATE_QUERY = gql`
      mutation UserAdd($input: UserAddInput) {
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
    const roleStandardId = generateStandardId(ENTITY_TYPE_ROLE, { name: 'Default' });
    const role = await elLoadById(ADMIN_USER, roleStandardId);
    const REMOTE_ROLE_QUERY = gql`
      mutation UserEditRemoveRole($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        userEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
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
      variables: { id: userInternalId, toId: role.id, relationship_type: 'has-role' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.userEdit).not.toBeNull();
    expect(queryResult.data.userEdit.relationDelete.roles.length).toEqual(0);
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
    expect(queryResult.data.users.edges.length).toEqual(2);
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
      mutation UserEdit($id: ID!, $input: InternalRelationshipAddInput!) {
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
          toId: groupInternalId,
          relationship_type: 'member-of',
        },
      },
    });
    expect(queryResult.data.userEdit.relationAdd.from.groups.edges.length).toEqual(1);
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
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userStandardId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });
});
