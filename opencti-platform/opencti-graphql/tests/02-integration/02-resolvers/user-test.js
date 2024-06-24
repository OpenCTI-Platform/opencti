import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { elLoadById } from '../../../src/database/engine';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ADMIN_USER, adminQuery, editorQuery, queryAsAdmin, testContext, TESTING_GROUPS, TESTING_USERS } from '../../utils/testQuery';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';

const LIST_QUERY = gql`
  query users(
    $first: Int
    $after: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    users(
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
      user_confidence_level {
        max_confidence
      }
      effective_confidence_level {
        max_confidence
        source {
          type
          object {
            ... on User { entity_type id name }
            ... on Group { entity_type id name }
          }
        }
      }
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

const CREATE_QUERY = gql`
  mutation UserAdd($input: UserAddInput!) {
    userAdd(input: $input) {
      id
      standard_id
      name
      user_email
      firstname
      lastname
      user_confidence_level {
        max_confidence
        overrides {
          entity_type
          max_confidence
        }
      }
      effective_confidence_level {
        max_confidence
        source {
          type
          object {
            ... on User { entity_type id name }
            ... on Group { entity_type id name }
          }
        }
      }
    }
  }
`;

const GROUP_ADD_QUERY = gql`
  mutation GroupAdd($input: GroupAddInput!) {
    groupAdd(input: $input) {
      id
      name
      description
      group_confidence_level {
        max_confidence
      }
    }
  }
`;

const DELETE_QUERY = gql`
  mutation userDelete($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

const DELETE_GROUP_QUERY = gql`
  mutation groupDelete($id: ID!) {
    groupEdit(id: $id) {
      delete
    }
  }
`;

describe('User resolver standard behavior', () => {
  let userInternalId;
  let groupInternalId;
  let userStandardId;
  let roleInternalId;
  let capabilityId;
  const userToDeleteIds = [];
  it('should user created', async () => {
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
    const user = await adminQuery({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(user).not.toBeNull();
    expect(user.data.userAdd).not.toBeNull();
    userInternalId = user.data.userAdd.id;
    userStandardId = user.data.userAdd.standard_id;
    userToDeleteIds.push(userInternalId);

    expect(user.data.userAdd.name).toEqual('User');
    expect(user.data.userAdd.user_confidence_level).toBeNull();
    // user created with default group, so effective confidence level shall be set
    expect(user.data.userAdd.effective_confidence_level.max_confidence).toEqual(100);
    expect(user.data.userAdd.effective_confidence_level.source.type).toEqual('Group');
    expect(user.data.userAdd.effective_confidence_level.source.object).toBeDefined();

    const USER_TO_CREATE_WITH_CONFIDENCE = {
      input: {
        name: 'User Confidence',
        password: 'user',
        user_email: 'user_confidence@mail.com',
        user_confidence_level: {
          max_confidence: 50,
          overrides: [{ entity_type: 'Report', max_confidence: 80 }],
        }
      },
    };
    const user2 = await adminQuery({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE_WITH_CONFIDENCE,
    });
    expect(user2.data.userAdd.user_confidence_level).toEqual({
      max_confidence: 50,
      overrides: [{ entity_type: 'Report', max_confidence: 80 }],
    });
    expect(user2.data.userAdd.effective_confidence_level.max_confidence).toEqual(50);
    expect(user2.data.userAdd.effective_confidence_level.source.type).toEqual('User');
    expect(user2.data.userAdd.effective_confidence_level.source.object.id).toEqual(user2.data.userAdd.id);
    userToDeleteIds.push(user2.data.userAdd.id);
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
    expect(queryResult.data.users.edges.length).toEqual(TESTING_USERS.length + 3);
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
  it('should update user confidence level', async () => {
    const UPDATE_QUERY = gql`
      mutation UserEdit($id: ID!, $input: [EditInput]!) {
        userEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            user_confidence_level {
              max_confidence
            }
            effective_confidence_level {
              max_confidence
              source {
                type
                object {
                  ... on User { entity_type id name }
                  ... on Group { entity_type id name }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await adminQuery({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_confidence_level', value: { max_confidence: 33, overrides: [] } }
      },
    });
    expect(queryResult.data.userEdit.fieldPatch.user_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data.userEdit.fieldPatch.effective_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data.userEdit.fieldPatch.effective_confidence_level.source.object.id).toEqual(userInternalId);
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
    // Create the group
    const GROUP_TO_CREATE = {
      input: {
        name: 'Group of user',
        description: 'Group of user description',
        group_confidence_level: {
          max_confidence: 60,
          overrides: [],
        }
      },
    };
    const group = await adminQuery({
      query: GROUP_ADD_QUERY,
      variables: GROUP_TO_CREATE,
    });
    expect(group).not.toBeNull();
    expect(group.data.groupAdd).not.toBeNull();
    expect(group.data.groupAdd.name).toEqual('Group of user');
    expect(group.data.groupAdd.group_confidence_level.max_confidence).toEqual(60);
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
    const queryResult = await adminQuery({
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
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.groups.edges.length).toEqual(2); // the 2 groups are: 'Group of user' and 'Default'
  });
  it('should user confidence level be unchanged', async () => {
    const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).not.toBeNull();
    expect(queryResult.data.user.user_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data.user.effective_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data.user.effective_confidence_level.source.object.id).toEqual(userInternalId);
  });
  it('should remove user confidence level, effective level should be accurate', async () => {
    const UPDATE_QUERY = gql`
      mutation UserEdit($id: ID!, $input: [EditInput]!) {
        userEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            user_confidence_level {
              max_confidence
            }
            effective_confidence_level {
              max_confidence
              source {
                type
                object {
                  ... on User { entity_type id name }
                  ... on Group { entity_type id name }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await adminQuery({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_confidence_level', value: [null] }
      },
    });
    const { userEdit } = queryResult.data;
    expect(userEdit.fieldPatch.user_confidence_level).toBeNull();
    // now effective level is the highest values among the 2 groups (default: 100)
    expect(userEdit.fieldPatch.effective_confidence_level.max_confidence).toEqual(100);
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
    expect(queryResult.data.groupEdit.relationAdd.from.roles.edges.length).toEqual(1);
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
    // Delete the group
    await adminQuery({
      query: DELETE_GROUP_QUERY,
      variables: { id: groupInternalId },
    });
  });
  it('should user deleted', async () => {
    // Delete the users
    for (let i = 0; i < userToDeleteIds.length; i += 1) {
      const userId = userToDeleteIds[i];
      await adminQuery({
        query: DELETE_QUERY,
        variables: { id: userId },
      });
      // Verify is no longer found
      const queryResult = await adminQuery({ query: READ_QUERY, variables: { id: userId } });
      expect(queryResult).not.toBeNull();
      expect(queryResult.data.user).toBeNull();
    }
  });
});

describe('User list members query behavior', () => {
  it('Should user lists all members', async () => {
    const queryResult = await editorQuery({ query: LIST_MEMBERS_QUERY });
    expect(queryResult.data.members.edges.length).toEqual(22);
    expect(queryResult.data.members.edges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_USER).length).toEqual(TESTING_USERS.length + 1); // +1 = Plus admin user
    expect(queryResult.data.members.edges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_GROUP).length).toEqual(TESTING_GROUPS.length + 2); // 2 built-in groups
    expect(queryResult.data.members.edges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION).length).toEqual(7);
  });
});

describe('User creator completion', () => {
  it('Should sector upsert accumulate creator_id', async () => {
    const SECTOR_CREATE_QUERY = gql`
      mutation SectorAdd($input: SectorAddInput!) {
        sectorAdd(input: $input) {
          id
          name
          description
          creators {
            id
          }
        }
      }
    `;
    const SECTOR_TO_CREATE = {
      input: {
        name: 'Consulting',
      },
    };
    const queryResult = await editorQuery({ query: SECTOR_CREATE_QUERY, variables: SECTOR_TO_CREATE });
    expect(queryResult.data.sectorAdd.creators.length).toEqual(2);
  });
});

describe('User has no capability query behavior', () => {
  const GROUP_UPDATE_QUERY = gql`
    mutation GroupEdit($id: ID!, $input: [EditInput]!) {
      groupEdit(id: $id) {
        fieldPatch(input: $input) {
          id
        }
      }
    }
  `;
  let userWithoutRoleInternalId;
  beforeAll(async () => {
    // Modify the default group to prevent default_assignation
    await queryAsAdmin({
      query: GROUP_UPDATE_QUERY,
      variables: {
        id: 'group--a7991a4f-6192-59a4-87d3-d006d2c41cc8',
        input: { key: 'default_assignation', value: [false] }
      },
    });
    // Create the user
    const USER_TO_CREATE = {
      input: {
        name: 'UserWithoutRole',
        password: 'UserWithoutRole',
        user_email: 'UserWithoutRole@mail.com',
        groups: [],
      },
    };
    const userAddResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    userWithoutRoleInternalId = userAddResult.data.userAdd.id;
  });

  it('should has no capability if no role', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userWithoutRoleInternalId } });
    expect(queryResult.data.user.capabilities.length).toEqual(0);
  });

  afterAll(async () => {
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: userWithoutRoleInternalId },
    });
    await queryAsAdmin({
      query: GROUP_UPDATE_QUERY,
      variables: {
        id: 'group--a7991a4f-6192-59a4-87d3-d006d2c41cc8',
        input: { key: 'default_assignation', value: [true] }
      },
    });
  });
});
