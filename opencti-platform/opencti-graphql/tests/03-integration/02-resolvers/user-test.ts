import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { elLoadById } from '../../../src/database/engine';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import {
  ADMIN_USER,
  adminQuery,
  AMBER_GROUP,
  editorQuery,
  getGroupIdByName,
  getOrganizationIdByName,
  getUserIdByEmail,
  GREEN_GROUP,
  PLATFORM_ORGANIZATION,
  queryAsAdmin,
  TEST_ORGANIZATION,
  testContext,
  TESTING_USERS,
  USER_CONNECTOR,
  USER_DISINFORMATION_ANALYST,
  USER_EDITOR,
} from '../../utils/testQuery';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { VIRTUAL_ORGANIZATION_ADMIN } from '../../../src/utils/access';
import {
  adminQueryWithError,
  adminQueryWithSuccess,
  unSetOrganization,
  setOrganization,
  queryAsAdminWithSuccess,
  queryAsUserIsExpectedError,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
} from '../../utils/testQueryHelper';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import type { Capability, Member, UserAddInput } from '../../../src/generated/graphql';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { entitiesCounter } from '../../02-dataInjection/01-dataCount/entityCountHelper';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

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
          user_email
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
      created_at
      creator {
        name
      }
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
      user_service_account
      user_confidence_level {
        max_confidence
        overrides {
          entity_type
          max_confidence
        }
      }
      objectOrganization {
        edges {
          node {
            id
            name
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

const UPDATE_QUERY = gql`
  mutation UserEdit(
    $id: ID!
    $input: [EditInput]!
  ) {
    userEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        name
        description
        language
        user_email
        api_token
        user_service_account
        account_status
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

const TOKEN_RENEW_QUERY = gql`
    mutation UserEdit($id: ID!) {
        userEdit(id: $id) {
            tokenRenew {
                id
                api_token
            }
        }
    }
`;

describe('User resolver standard behavior', () => {
  let userInternalId: string;
  let groupInternalId: string;
  let userStandardId: string;
  let roleInternalId: string;
  let capabilityId;
  const userToDeleteIds: string[] = [];
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
        },
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
  it('should user loaded by standard id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userStandardId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.id).toEqual(userInternalId);
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
    expect(res.data?.token).toBeDefined();
  });
  it('should list users', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 100 } });
    const userList = queryResult.data?.users.edges;

    // Verify that some users are in the list
    // Users in testQuery
    expect(userList.filter((userNode: any) => userNode.node.user_email === 'participate@opencti.io').length).toBe(1);
    expect(userList.filter((userNode: any) => userNode.node.user_email === 'editor@opencti.io').length).toBe(1);
    expect(userList.filter((userNode: any) => userNode.node.user_email === 'security@opencti.io').length).toBe(1);

    // Users from this describe block
    expect(userList.filter((userNode: any) => userNode.node.user_email === 'user_confidence@mail.com').length).toBe(1);
    expect(userList.filter((userNode: any) => userNode.node.user_email === 'user@mail.com').length).toBe(1);
  });
  it('should update user', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: userInternalId, input: { key: 'name', value: ['User - test'] } },
    });
    expect(queryResult.data?.userEdit.fieldPatch.name).toEqual('User - test');
  });
  it('should update language only if the value is valid', async () => {
    const validQueryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: userInternalId, input: { key: 'language', value: ['en-us'] } },
    });
    expect(validQueryResult.data?.userEdit.fieldPatch.language).toEqual('en-us');
    const invalidQueryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: userInternalId, input: { key: 'language', value: ['invalid-value'] } },
    });
    expect(invalidQueryResult.errors?.[0].message).toEqual('The language you have provided is not valid');
  });
  it('should not update Name field for internal user', async () => {
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: ADMIN_USER.id, input: { key: 'name', value: ['new name'] } },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors?.length).toBe(1);
    if (result.errors) {
      expect(result.errors[0].message).toBe('Name cannot be updated for external user');
    }
  });
  it('should not update Email field for internal user', async () => {
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: ADMIN_USER.id, input: { key: 'user_email', value: ['mail@mail.com'] } },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors?.length).toBe(1);
    if (result.errors) {
      expect(result.errors[0].message).toBe('Email cannot be updated for external user');
    }
  });
  it('should Admin be able renew a user token', async () => {
    const queryUserBeforeRenew = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: userInternalId } });
    const tokenBeforeRenew = queryUserBeforeRenew.data?.user.api_token;
    expect(tokenBeforeRenew).toBeDefined();

    const renewResult = await queryAsAdminWithSuccess({
      query: TOKEN_RENEW_QUERY,
      variables: { id: userInternalId },
    });
    expect(renewResult.data?.userEdit.tokenRenew.api_token).toBeDefined();
    expect(renewResult.data?.userEdit.tokenRenew.api_token).not.toBe(tokenBeforeRenew);
  });
  it('should Analyst NOT ne able to renew user token', async () => {
    await queryAsUserIsExpectedForbidden(USER_DISINFORMATION_ANALYST.client, {
      query: TOKEN_RENEW_QUERY,
      variables: { id: userInternalId },
    });
  });
  it('should be forbidden to renew yaml/env configured token (admin)', async () => {
    const result = await queryAsAdmin({
      query: TOKEN_RENEW_QUERY,
      variables: { id: OPENCTI_ADMIN_UUID },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors?.length).toBe(1);
    if (result.errors) {
      expect(result.errors[0].message).toBe('Cannot renew token of admin user defined in configuration, please change configuration instead.');
    }
  });
  it('should update user confidence level', async () => {
    const queryResult = await adminQuery({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_confidence_level', value: { max_confidence: 33, overrides: [] } },
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
    expect(queryResult.data?.userEdit.contextPatch.id).toEqual(userInternalId);
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
    expect(queryResult.data?.userEdit.contextClean.id).toEqual(userInternalId);
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
        },
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
    const queryResult = await adminQuery({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_confidence_level', value: [null] },
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
    expect(role.data?.roleAdd).not.toBeNull();
    expect(role.data?.roleAdd.name).toEqual('Role in group');
    roleInternalId = role.data?.roleAdd.id;
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
    expect(queryResult.data?.groupEdit.relationAdd.from.roles.edges.length).toEqual(1);
  });
  it('should user roles to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.roles.filter((role: any) => role.name === 'Role in group').length).toBe(1);
    expect(queryResult.data?.user.roles.filter((role: any) => role.name === 'Default').length).toBe(1);
    expect(queryResult.data?.user.roles.length).toEqual(2); // the 2 roles are: 'Role in group' and 'Default'
  });
  it('should add capability in role', async () => {
    const capabilityStandardId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'KNOWLEDGE' });
    const capability = await elLoadById(testContext, ADMIN_USER, capabilityStandardId) as unknown as Capability;
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
    expect(queryResult.data?.roleEdit.relationAdd.from.capabilities.length).toEqual(1);
    expect(queryResult.data?.roleEdit.relationAdd.from.capabilities[0].name).toEqual('KNOWLEDGE');
  });
  it('should user capabilities to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.capabilities.length).toEqual(1);
    expect(queryResult.data?.user.capabilities[0].name).toEqual('KNOWLEDGE');
  });
  it('Created user should not be assigned to default groups if prevent_default_groups = true', async () => {
    const USER_TO_CREATE = {
      input: {
        name: 'UserWithGroupsSpecified',
        password: 'UserWithGroupsSpecified',
        user_email: 'UserWithGroupsSpecified@mail.com',
        groups: [GREEN_GROUP.id],
        prevent_default_groups: true,
      },
    };
    const userAddResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(userAddResult.data?.userAdd.groups.edges.length).toEqual(1);
    expect(userAddResult.data?.userAdd.groups.edges[0].node.name).toEqual(GREEN_GROUP.name);
    userToDeleteIds.push(userAddResult.data?.userAdd.id);
  });
  it('Created user should be assigned to default group by default', async () => {
    const USER_TO_CREATE = {
      input: {
        name: 'UserWithNoGroupsSpecified',
        password: 'UserWithNoGroupsSpecified',
        user_email: 'UserWithNoGroupsSpecified@mail.com',
        groups: [],
      },
    };
    const userAddResult = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(userAddResult.data?.userAdd.groups.edges.length).toEqual(1);
    expect(userAddResult.data?.userAdd.groups.edges[0].node.name).toEqual('Default');
    userToDeleteIds.push(userAddResult.data?.userAdd.id);
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
    expect(queryResult.data?.userEdit.relationDelete.groups.edges.length).toEqual(1);
    expect(queryResult.data?.userEdit.relationDelete.groups.edges[0].node.name).toEqual('Default');
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
    const usersEdges = queryResult.data.members.edges as { node: Member }[];
    expect(usersEdges.length).toEqual(25);
    expect(usersEdges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_USER).length).toEqual(TESTING_USERS.length + 1); // +1 = Plus admin user
    expect(usersEdges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_GROUP).length).toEqual(entitiesCounter.Group);
    expect(usersEdges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION).length).toEqual(entitiesCounter.Organization + 1);
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
  let userWithoutRoleInternalId: string;
  beforeAll(async () => {
    // Modify the default group to prevent default_assignation
    await queryAsAdmin({
      query: GROUP_UPDATE_QUERY,
      variables: {
        id: 'group--a7991a4f-6192-59a4-87d3-d006d2c41cc8',
        input: { key: 'default_assignation', value: [false] },
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
    userWithoutRoleInternalId = userAddResult.data?.userAdd.id;
  });

  it('should has no capability if no role', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userWithoutRoleInternalId } });
    expect(queryResult.data?.user.capabilities.length).toEqual(0);
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
        input: { key: 'default_assignation', value: [true] },
      },
    });
  });
});

describe('User has no settings capability and is organization admin query behavior', () => {
  let userInternalId: string;
  let userEditorId: string;
  let testOrganizationId: string;
  let amberGroupId: string;
  let platformOrganizationId: string;
  const organizationsIds: string[] = [];

  const ORGA_ADMIN_ADD_QUERY = gql`
      mutation OrganizationAdminAdd($id: ID!, $memberId: String!) {
          organizationAdminAdd(id: $id, memberId: $memberId) {
              id
              standard_id
          }
      }
    `;

  const ORGANIZATION_ADD_QUERY = gql`
        mutation UserOrganizationAddMutation(
            $id: ID!
            $organizationId: ID!
        ) {
            userEdit(id: $id) {
                organizationAdd(organizationId: $organizationId) {
                    id
                }
            }
        }
    `;

  const UPDATE_ORGANIZATION_QUERY = gql`
    mutation OrganizationEdit($id: ID!, $input: [EditInput]!) {
      organizationFieldPatch(id: $id, input: $input) {
        id
        name
        grantable_groups {
          id
        }
      }
    }
  `;

  const ORGANIZATION_DELETE_QUERY = gql`
        mutation UserOrganizationDeleteMutation(
            $id: ID!
            $organizationId: ID!
        ) {
            userEdit(id: $id) {
                organizationDelete(organizationId: $organizationId) {
                    id
                }
            }
        }
    `;

  afterAll(async () => {
    // remove the capability to administrate the Organization
    const ORGA_ADMIN_DELETE_QUERY = gql`
            mutation OrganizationAdminRemove($id: ID!, $memberId: String!) {
                organizationAdminRemove(id: $id, memberId: $memberId) {
                    id
                }
            }
        `;

    // Delete admin to ORGANIZATION
    await adminQuery({
      query: ORGA_ADMIN_DELETE_QUERY, // +1 update organization
      variables: {
        id: testOrganizationId,
        memberId: userEditorId,
      },
    });
    for (let i = 0; i < organizationsIds.length; i += 1) {
      // remove granted_groups to ORGANIZATION
      await adminQuery({
        query: UPDATE_ORGANIZATION_QUERY, // +1 update organization for each (+2 total)
        variables: { id: organizationsIds[i], input: { key: 'grantable_groups', value: [] } },
      });
    }
  });
  it('should has the capability to administrate the Organization', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email); // USER_EDITOR is perfect because she has no settings capabilities and is part of TEST_ORGANIZATION
    const organizationAdminAddQueryResult = await adminQueryWithSuccess({
      query: ORGA_ADMIN_ADD_QUERY, // +1 update event of organization
      variables: {
        id: TEST_ORGANIZATION.id,
        memberId: userEditorId,
      },
    });
    expect(organizationAdminAddQueryResult.data.organizationAdminAdd).not.toBeNull();
    expect(organizationAdminAddQueryResult.data.organizationAdminAdd.standard_id).toEqual(TEST_ORGANIZATION.id);

    // Check that USER_EDITOR is Organization administrator
    const editorUserQueryResult = await adminQuery({ query: READ_QUERY, variables: { id: userEditorId } });
    expect(editorUserQueryResult).not.toBeNull();
    expect(editorUserQueryResult.data.user).not.toBeNull();
    expect(editorUserQueryResult.data.user.capabilities.length).toEqual(8);
    const { capabilities } = editorUserQueryResult.data.user;
    expect(capabilities.some((capa: Capability) => capa.name === VIRTUAL_ORGANIZATION_ADMIN)).toEqual(true);
  });
  it('should user created', async () => {
    testOrganizationId = await getOrganizationIdByName(TEST_ORGANIZATION.name);
    organizationsIds.push(testOrganizationId);
    amberGroupId = await getGroupIdByName(AMBER_GROUP.name);

    const USER_TO_CREATE = {
      input: {
        name: 'User',
        description: 'User description',
        password: 'user',
        user_email: 'user@mail.com',
        firstname: 'User',
        lastname: 'OpenCTI',
        objectOrganization: [testOrganizationId],
        groups: [amberGroupId],
      },
    };

    // Need to add granted_groups to TEST_ORGANIZATION because of line 533 in domain/user.js
    const queryResult = await adminQuery({
      query: UPDATE_ORGANIZATION_QUERY,
      variables: { id: testOrganizationId, input: { key: 'grantable_groups', value: [amberGroupId] } },
    });
    expect(queryResult.data.organizationFieldPatch.grantable_groups.length).toEqual(1);
    expect(queryResult.data.organizationFieldPatch.grantable_groups[0]).toEqual({ id: amberGroupId });

    // Create User
    const user = await editorQuery({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(user).not.toBeNull();
    expect(user.data.userAdd).not.toBeNull();
    expect(user.data.userAdd.name).toEqual('User');
    userInternalId = user.data.userAdd.id;
  });
  it('should update user from its own organization', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: UPDATE_QUERY,
      variables: { id: userInternalId, input: { key: 'account_status', value: ['Inactive'] } },
    });
    expect(queryResult.data.userEdit.fieldPatch.account_status).toEqual('Inactive');
  });
  it('should not add organization to user if not admin', async () => {
    platformOrganizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: ORGANIZATION_ADD_QUERY,
      variables: {
        id: userInternalId,
        organizationId: platformOrganizationId,
      },
    });
  });
  it('should administrate more than 1 organization', async () => {
    // Need to add granted_groups to PLATFORM_ORGANIZATION because of line 533 in domain/user.js
    const grantableGroupQueryResult = await adminQuery({
      query: UPDATE_ORGANIZATION_QUERY,
      variables: { id: platformOrganizationId, input: { key: 'grantable_groups', value: [amberGroupId] } },
    });
    expect(grantableGroupQueryResult.data.organizationFieldPatch.grantable_groups.length).toEqual(1);
    expect(grantableGroupQueryResult.data.organizationFieldPatch.grantable_groups[0]).toEqual({ id: amberGroupId });
    organizationsIds.push(platformOrganizationId);

    // Add Editor to PLATFORM_ORGANIZATION
    const addEditorToOrgaQuery = await adminQueryWithSuccess({
      query: ORGANIZATION_ADD_QUERY, // +1 create of relation between orga & user
      variables: {
        id: userEditorId,
        organizationId: platformOrganizationId,
      },
    });
    expect(addEditorToOrgaQuery.data.userEdit.organizationAdd.id).toEqual(userEditorId);

    // Editor administrate PLATFORM_ORGANIZATION
    const queryResult = await adminQueryWithSuccess({
      query: ORGA_ADMIN_ADD_QUERY, // +1 update event of organization
      variables: {
        id: PLATFORM_ORGANIZATION.id,
        memberId: userEditorId,
      },
    });
    expect(queryResult.data.organizationAdminAdd).not.toBeNull();
    expect(queryResult.data.organizationAdminAdd.standard_id).toEqual(PLATFORM_ORGANIZATION.id);
  });
  it('should add 2nd organization to user if admin', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: ORGANIZATION_ADD_QUERY, // +1 create of relation between orga & user
      variables: {
        id: userInternalId,
        organizationId: platformOrganizationId,
      },
    });
    expect(queryResult.data.userEdit.organizationAdd.id).toEqual(userInternalId);
  });
  it('should delete 2nd organization to user if admin', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: ORGANIZATION_DELETE_QUERY, // +1 delete of relation between orga & user
      variables: {
        id: userInternalId,
        organizationId: platformOrganizationId,
      },
    });
    expect(queryResult.data.userEdit.organizationDelete.id).toEqual(userInternalId);
  });
  it('should remove Editor from PLATFORM_ORGANIZATION', async () => {
    const queryResult = await adminQueryWithSuccess({
      query: ORGANIZATION_DELETE_QUERY, // +1 delete event (delete relation) +1 update event
      variables: {
        id: userEditorId,
        organizationId: platformOrganizationId,
      },
    });
    expect(queryResult.data.userEdit.organizationDelete.id).toEqual(userEditorId);
  });
  it('should user deleted', async () => {
    // Delete user
    await editorQuery({
      query: DELETE_QUERY,
      variables: { id: userInternalId },
    });
    // Verify is no longer found
    const queryResult = await adminQueryWithSuccess({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult.data.user).toBeNull();
  });
});

describe('meUser specific resolvers', async () => {
  const ME_EDIT = gql`
    mutation meEdit($input: [EditInput]!, $password: String) {
      meEdit(input: $input, password: $password) {
        id
        name
        user_email
        external
        firstname
        lastname
        language
        theme
        api_token
        otp_activated
        otp_qr
        description
      }
    }
  `;

  it('User should update authorized attribute', async () => {
    const variables = {
      password: USER_EDITOR.password,
      input: [
        { key: 'language', value: 'fr-fr' },
      ],
    };
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: ME_EDIT,
      variables,
    });
    expect(queryResult.data.meEdit.language).toEqual('fr-fr');
  });
  it('User should NOT update unauthorized attribute', async () => {
    const variables = {
      password: USER_EDITOR.password,
      input: [
        { key: 'api_token', value: 'd434ce02-e58e-4cac-8b4c-42bf16748e84' },
      ],
    };
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: ME_EDIT,
      variables,
    });
  });
  it('User should update multiple authorized attributes', async () => {
    const variables = {
      password: USER_EDITOR.password,
      input: [
        { key: 'language', value: 'en-us' },
        { key: 'theme', value: 'dark' },
      ],
    };
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR.client, {
      query: ME_EDIT,
      variables,
    });
    expect(queryResult.data.meEdit.language).toEqual('en-us');
  });
  it('User should NOT update multiple attribute when unauthorized keys in input', async () => {
    const variables = {
      password: USER_EDITOR.password,
      input: [
        { key: 'language', value: 'fr-fr' },
        { key: 'api_token', value: 'd434ce02-e58e-4cac-8b4c-42bf16748e84' },
      ],
    };
    await queryAsUserIsExpectedForbidden(USER_EDITOR.client, {
      query: ME_EDIT,
      variables,
    });
  });
  it('User should NOT update password without providing proper current password', async () => {
    const variables = {
      password: 'incorrect_current_password',
      input: [
        { key: 'password', value: 'new_password' },
      ],
    };
    await queryAsUserIsExpectedError(USER_EDITOR.client, {
      query: ME_EDIT,
      variables,
    });
  });
});

describe('User is impersonated', async () => {
  it('Applicant user without any organization is rejected when a platform organization is set', async () => {
    await setOrganization(TEST_ORGANIZATION);

    const CREATE_REPORT_QUERY = gql`
      mutation ReportAdd($input: ReportAddInput!) {
        reportAdd(input: $input) {
          id
          standard_id
          name
          description
          published
        }
      }
    `;
    // Report to create: creation should fail
    const REPORT_TO_CREATE = {
      input: {
        name: 'ReportCreationFail',
      },
    };
    const reportQuery = await adminQuery({
      query: CREATE_REPORT_QUERY,
      variables: REPORT_TO_CREATE,
    }, { applicantId: USER_CONNECTOR.id });
    expect(reportQuery.errors).toBeDefined();

    // revert platform orga
    await unSetOrganization();
  });
});

describe('Service account User coverage', async () => {
  let userInternalId: string;
  const userToDeleteIds: string[] = [];
  it('should service account user created', async () => {
    // Create the user
    const USER_TO_CREATE: UserAddInput = {
      name: 'Service account',
      user_service_account: true,
      groups: [],
      objectOrganization: [],
    };
    const user = await adminQueryWithSuccess({
      query: CREATE_QUERY,
      variables: { input: USER_TO_CREATE },
    });
    expect(user.data.userAdd).not.toBeNull();
    userInternalId = user.data.userAdd.id;
    userToDeleteIds.push(userInternalId);

    expect(user.data.userAdd.name).toEqual('Service account');
    expect(user.data.userAdd.user_email).toBeDefined();
    expect(user.data.userAdd.user_email.startsWith('automatic+')).toBeTruthy();
    expect(user.data.userAdd.user_service_account).toEqual(true);
  });
  it('should service account user read', async () => {
    const QUERY_SERVICE_ACCOUNT_USER = gql`
      query user($id: String!) {
        user(id: $id) {
          id
          standard_id
          name
          user_email
          description
          groups {
            edges {
              node {
                id
                name
              }
            }
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

    const queryResult = await queryAsAdminWithSuccess({ query: QUERY_SERVICE_ACCOUNT_USER, variables: { id: userInternalId } });
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.id).toEqual(userInternalId);
  });
  it('should turn service account into user', async () => {
    const queryResult = await adminQueryWithSuccess({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_service_account', value: [false] },
      },
    });
    const { userEdit } = queryResult.data;
    expect(userEdit.fieldPatch.user_service_account).toEqual(false);
    // check password has been created
    const userCreated: any = await storeLoadById(testContext, ADMIN_USER, userInternalId, ENTITY_TYPE_USER);
    expect(userCreated.password).toBeDefined();
  });
  it('should turn user into service account', async () => {
    const queryResult = await adminQueryWithSuccess({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: [{ key: 'user_service_account', value: [true] }, { key: 'password', value: ['toto'] }],
      },
    });
    const { userEdit } = queryResult.data;
    expect(userEdit.fieldPatch.user_service_account).toEqual(true);
    // check password has been removed
    const userCreated: any = await storeLoadById(testContext, ADMIN_USER, userInternalId, ENTITY_TYPE_USER);
    expect(userCreated.password).toBeUndefined();
  });
  it('should not update password for service account', async () => {
    await adminQueryWithError({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: [{ key: 'password', value: ['toto'] }],
      },
    }, 'Cannot update password for Service account');
  });
  it('should service account user deleted', async () => {
    // Delete the users
    for (let i = 0; i < userToDeleteIds.length; i += 1) {
      const userId = userToDeleteIds[i];
      await adminQueryWithSuccess({
        query: DELETE_QUERY,
        variables: { id: userId },
      });
      // Verify is no longer found
      const queryResult = await adminQueryWithSuccess({ query: READ_QUERY, variables: { id: userId } });
      expect(queryResult.data.user).toBeNull();
    }
  });
});
