import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { elLoadById } from '../../../src/database/engine';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import {
  ADMIN_USER,
  AMBER_GROUP,
  getGroupIdByName,
  getOrganizationIdByName,
  getUserIdByEmail,
  GREEN_GROUP,
  queryInitPlatformAsAdmin,
  PLATFORM_ORGANIZATION,
  TEST_ORGANIZATION,
  testContext,
  TESTING_USERS,
  USER_CONNECTOR,
  USER_EDITOR,
  USER_PARTICIPATE,
  USER_SECURITY,
} from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { VIRTUAL_ORGANIZATION_ADMIN } from '../../../src/utils/access';
import {
  queryAsAdminWithError,
  queryAsAdminWithSuccess,
  queryAsUser,
  queryAsUserIsExpectedError,
  queryAsUserIsExpectedForbidden,
  queryAsUserWithSuccess,
  setOrganization,
  unSetOrganization,
} from '../../utils/testQueryHelper';

import type { Capability, Member, UserAddInput } from '../../../src/generated/graphql';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { entitiesCounter } from '../../02-dataInjection/01-dataCount/entityCountHelper';
import { clearAllUsersPasswordValidUntil, adjustAllUsersPasswordValidUntil, isPasswordExpired, computePasswordValidUntilFromPolicy } from '../../../src/domain/user';
import { getSettingsFromDatabase } from '../../../src/domain/settings';
import { updateLocalAuth } from '../../../src/domain/setting-auth';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { DateTime } from 'luxon';

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
      user_email
      firstname
      lastname
      language
      theme
      user_service_account
      external
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
      groups {
        edges {
          node {
            id
            standard_id
            name
            description
            group_confidence_level {
              max_confidence
              overrides {
                entity_type
                max_confidence
              }
            }
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
    const user = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(user).not.toBeNull();
    expect(user.data?.userAdd).not.toBeNull();
    userInternalId = user.data?.userAdd.id;
    userStandardId = user.data?.userAdd.standard_id;
    userToDeleteIds.push(userInternalId);

    expect(user.data?.userAdd.name).toEqual('User');
    expect(user.data?.userAdd.user_confidence_level).toBeNull();
    // user created with default group, so effective confidence level shall be set
    expect(user.data?.userAdd.effective_confidence_level.max_confidence).toEqual(100);
    expect(user.data?.userAdd.effective_confidence_level.source.type).toEqual('Group');
    expect(user.data?.userAdd.effective_confidence_level.source.object).toBeDefined();

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
    const user2 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: USER_TO_CREATE_WITH_CONFIDENCE,
    });
    expect(user2.data?.userAdd.user_confidence_level).toEqual({
      max_confidence: 50,
      overrides: [{ entity_type: 'Report', max_confidence: 80 }],
    });
    expect(user2.data?.userAdd.effective_confidence_level.max_confidence).toEqual(50);
    expect(user2.data?.userAdd.effective_confidence_level.source.type).toEqual('User');
    expect(user2.data?.userAdd.effective_confidence_level.source.object.id).toEqual(user2.data?.userAdd.id);
    userToDeleteIds.push(user2.data?.userAdd.id);
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

  it('should update user confidence level', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_confidence_level', value: { max_confidence: 33, overrides: [] } },
      },
    });
    expect(queryResult.data?.userEdit.fieldPatch.user_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data?.userEdit.fieldPatch.effective_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data?.userEdit.fieldPatch.effective_confidence_level.source.object.id).toEqual(userInternalId);
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
    const group = await queryAsAdmin({
      query: GROUP_ADD_QUERY,
      variables: GROUP_TO_CREATE,
    });
    expect(group).not.toBeNull();
    expect(group.data?.groupAdd).not.toBeNull();
    expect(group.data?.groupAdd.name).toEqual('Group of user');
    expect(group.data?.groupAdd.group_confidence_level.max_confidence).toEqual(60);
    groupInternalId = group.data?.groupAdd.id;
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
    expect(queryResult.data?.groupEdit.relationAdd.to.members.edges.length).toEqual(1);
  });
  it('should user groups to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.groups.edges.length).toEqual(2); // the 2 groups are: 'Group of user' and 'Default'
  });
  it('should user confidence level be unchanged', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.user_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data?.user.effective_confidence_level.max_confidence).toEqual(33);
    expect(queryResult.data?.user.effective_confidence_level.source.object.id).toEqual(userInternalId);
  });
  it('should remove user confidence level, effective level should be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: userInternalId,
        input: { key: 'user_confidence_level', value: [null] },
      },
    });
    expect(queryResult.data?.userEdit.fieldPatch.user_confidence_level).toBeNull();
    // now effective level is the highest values among the 2 groups (default: 100)
    expect(queryResult.data?.userEdit.fieldPatch.effective_confidence_level.max_confidence).toEqual(100);
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
    await queryAsAdmin({
      query: DELETE_GROUP_QUERY,
      variables: { id: groupInternalId },
    });
  });
  it('should user deleted', async () => {
    // Delete the users
    for (let i = 0; i < userToDeleteIds.length; i += 1) {
      const userId = userToDeleteIds[i];
      await queryAsAdmin({
        query: DELETE_QUERY,
        variables: { id: userId },
      });
      // Verify is no longer found
      const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userId } });
      expect(queryResult).not.toBeNull();
      expect(queryResult.data?.user).toBeNull();
    }
  });
});

describe('User list members query behavior', () => {
  it('Should user lists all members', async () => {
    const queryResult = await queryAsUser(USER_EDITOR, { query: LIST_MEMBERS_QUERY, variables: {} });
    const usersEdges = queryResult.data?.members.edges as { node: Member }[];
    expect(usersEdges.length).toEqual(23);
    // +1 = Plus admin user minus 2 users in PLATFORM_ORGANIZATION
    expect(usersEdges.filter(({ node: { entity_type } }) => entity_type === ENTITY_TYPE_USER).length).toEqual(TESTING_USERS.length + 1 - 2);
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
    const queryResult = await queryAsUser(USER_EDITOR, { query: SECTOR_CREATE_QUERY, variables: SECTOR_TO_CREATE });
    expect(queryResult.data?.sectorAdd.creators.length).toEqual(2);
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

describe('User has no settings capability and is organization admin query behavior', async () => {
  let userInternalId: string;
  let testOrganizationId: string;
  let amberGroupId: string;
  let platformOrganizationId: string;
  const organizationsIds: string[] = [];

  const userEditorId = await getUserIdByEmail(USER_EDITOR.email);
  const userParticipateId = await getUserIdByEmail(USER_PARTICIPATE.email);

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
    mutation OrganizationEdit($id: ID!, $input: [EditInput!]!) {
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
    await queryAsAdmin({
      query: ORGA_ADMIN_DELETE_QUERY, // +1 update organization
      variables: {
        id: testOrganizationId,
        memberId: userEditorId,
      },
    });
    for (let i = 0; i < organizationsIds.length; i += 1) {
      // remove granted_groups to ORGANIZATION
      await queryAsAdmin({
        query: UPDATE_ORGANIZATION_QUERY, // +1 update organization for each (+2 total)
        variables: { id: organizationsIds[i], input: { key: 'grantable_groups', value: [] } },
      });
    }
  });
  it('should has the capability to administrate the Organization', async () => {
    // set USER_EDITOR has organization administrator of TEST_ORGANIZATION
    // USER_EDITOR is perfect because he has no settings capabilities and is part of TEST_ORGANIZATION
    const organizationAdminAddQueryResult = await queryAsAdminWithSuccess({
      query: ORGA_ADMIN_ADD_QUERY, // +1 update event of organization
      variables: {
        id: TEST_ORGANIZATION.id,
        memberId: userEditorId,
      },
    });
    expect(organizationAdminAddQueryResult.data?.organizationAdminAdd).not.toBeNull();
    expect(organizationAdminAddQueryResult.data?.organizationAdminAdd.standard_id).toEqual(TEST_ORGANIZATION.id);

    // Check that USER_EDITOR is Organization administrator
    const editorUserQueryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: userEditorId } });
    expect(editorUserQueryResult).not.toBeNull();
    expect(editorUserQueryResult.data?.user).not.toBeNull();
    expect(editorUserQueryResult.data?.user.capabilities.length).toEqual(11);
    const capabilities = editorUserQueryResult.data?.user.capabilities ?? [];
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
    const queryResult = await queryAsAdmin({
      query: UPDATE_ORGANIZATION_QUERY,
      variables: { id: testOrganizationId, input: { key: 'grantable_groups', value: [amberGroupId] } },
    });
    expect(queryResult.data?.organizationFieldPatch.grantable_groups.length).toEqual(1);
    expect(queryResult.data?.organizationFieldPatch.grantable_groups[0]).toEqual({ id: amberGroupId });

    // Create User
    const user = await queryAsUser(USER_EDITOR, {
      query: CREATE_QUERY,
      variables: USER_TO_CREATE,
    });
    expect(user).not.toBeNull();
    expect(user.data?.userAdd).not.toBeNull();
    expect(user.data?.userAdd.name).toEqual('User');
    userInternalId = user.data?.userAdd.id;
  });
  it('should list users from its own organization', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: LIST_QUERY,
      variables: {},
    });
    expect(queryResult.data?.users.edges.length).toEqual(3);
    expect([userInternalId, userEditorId, userParticipateId].every((userId) => queryResult.data?.users.edges.map((n: any) => n.node.id).includes(userId)))
      .toBeTruthy();
  });
  it('should update user from its own organization', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: UPDATE_QUERY,
      variables: { id: userInternalId, input: { key: 'account_status', value: ['Inactive'] } },
    });
    expect(queryResult.data?.userEdit.fieldPatch.account_status).toEqual('Inactive');
  });
  it('should not update user with no organization', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: UPDATE_QUERY,
      variables: { id: ADMIN_USER.id, input: { key: 'account_status', value: ['Inactive'] } },
    });
  });
  it('should not update user from an other organization', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: UPDATE_QUERY,
      variables: { id: USER_SECURITY.id, input: { key: 'account_status', value: ['Inactive'] } },
    });
  });
  it('should not add organization to user if not admin', async () => {
    platformOrganizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: ORGANIZATION_ADD_QUERY,
      variables: {
        id: userInternalId,
        organizationId: platformOrganizationId,
      },
    });
  });
  it('should not add organization to user if user is not in its own organization', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: ORGANIZATION_ADD_QUERY,
      variables: {
        id: ADMIN_USER.id,
        organizationId: testOrganizationId,
      },
    });
  });
  it('should administrate more than 1 organization', async () => {
    // Need to add granted_groups to PLATFORM_ORGANIZATION because of line 533 in domain/user.js
    const grantableGroupQueryResult = await queryAsAdmin({
      query: UPDATE_ORGANIZATION_QUERY,
      variables: { id: platformOrganizationId, input: { key: 'grantable_groups', value: [amberGroupId] } },
    });
    expect(grantableGroupQueryResult.data?.organizationFieldPatch.grantable_groups.length).toEqual(1);
    expect(grantableGroupQueryResult.data?.organizationFieldPatch.grantable_groups[0]).toEqual({ id: amberGroupId });
    organizationsIds.push(platformOrganizationId);

    // Add Editor to PLATFORM_ORGANIZATION
    const addEditorToOrgaQuery = await queryAsAdminWithSuccess({
      query: ORGANIZATION_ADD_QUERY, // +1 create of relation between orga & user
      variables: {
        id: userEditorId,
        organizationId: platformOrganizationId,
      },
    });
    expect(addEditorToOrgaQuery.data.userEdit.organizationAdd.id).toEqual(userEditorId);

    // Editor administrate PLATFORM_ORGANIZATION
    const queryResult = await queryAsAdminWithSuccess({
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
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ORGANIZATION_ADD_QUERY, // +1 create of relation between orga & user
      variables: {
        id: userInternalId,
        organizationId: platformOrganizationId,
      },
    });
    expect(queryResult.data.userEdit.organizationAdd.id).toEqual(userInternalId);
  });
  it('should delete 2nd organization to user if admin', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ORGANIZATION_DELETE_QUERY, // +1 delete of relation between orga & user
      variables: {
        id: userInternalId,
        organizationId: platformOrganizationId,
      },
    });
    expect(queryResult.data.userEdit.organizationDelete.id).toEqual(userInternalId);
  });
  it('should remove Editor from PLATFORM_ORGANIZATION', async () => {
    const queryResult = await queryAsAdminWithSuccess({
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
    await queryAsUser(USER_EDITOR, {
      query: DELETE_QUERY,
      variables: { id: userInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: userInternalId } });
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
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_EDIT,
      variables,
    });
    expect(queryResult.data?.meEdit.language).toEqual('fr-fr');
  });

  it('User should update multiple authorized attributes', async () => {
    const variables = {
      password: USER_EDITOR.password,
      input: [
        { key: 'language', value: 'en-us' },
        { key: 'theme', value: 'dark' },
      ],
    };
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_EDIT,
      variables,
    });
    expect(queryResult.data?.meEdit.language).toEqual('en-us');
  });

  it('User should NOT update password without providing proper current password', async () => {
    const variables = {
      password: 'incorrect_current_password',
      input: [
        { key: 'password', value: 'new_password' },
      ],
    };
    await queryAsUserIsExpectedError(USER_EDITOR, {
      query: ME_EDIT,
      variables,
    });
  });

  it('User should change password WITHOUT current password when password is expired', async () => {
    // Set password_valid_until to a past date (expire the password)
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    const pastDate = new Date(Date.now() - 86400000).toISOString();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [pastDate] } },
    });

    // Change password without providing current password (force-change scenario)
    const ME_EDIT_WITH_VALIDITY = gql`
      mutation meEdit($input: [EditInput]!, $password: String) {
        meEdit(input: $input, password: $password) {
          id
          password_valid_until
        }
      }
    `;
    const queryResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_EDIT_WITH_VALIDITY,
      variables: {
        input: [{ key: 'password', value: [USER_EDITOR.password] }],
      },
    });
    // password_valid_until should be reset (null if no policy, or future date if policy set)
    const newValidity = queryResult.data?.meEdit.password_valid_until;
    if (newValidity !== null) {
      expect(new Date(newValidity).getTime()).toBeGreaterThan(Date.now());
    }
  });

  it('User should NOT change password without current password when password is NOT expired', async () => {
    // Ensure password_valid_until is null (not expired)
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [null] } },
    });

    // Try to change password without providing current password
    const variables = {
      input: [{ key: 'password', value: ['new_password_attempt'] }],
    };
    await queryAsUserIsExpectedError(USER_EDITOR, {
      query: ME_EDIT,
      variables,
    }, 'The current password you have provided is not valid');
  });
});

describe('Password expiration - userEdit', async () => {
  it('Admin should NOT set password_valid_until on external user', async () => {
    // Create an external user
    const CREATE_EXTERNAL_USER = gql`
      mutation UserAdd($input: UserAddInput!) {
        userAdd(input: $input) { id }
      }
    `;
    const createResult = await queryAsAdminWithSuccess({
      query: CREATE_EXTERNAL_USER,
      variables: {
        input: {
          name: 'External Test User',
          user_email: 'external-test-pwd@opencti.io',
          password: 'external123',
        },
      },
    });
    const externalUserId = createResult.data?.userAdd.id;

    // Mark the user as external
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: externalUserId, input: { key: 'external', value: [true] } },
    });

    // Try to set password_valid_until
    const result = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: externalUserId, input: { key: 'password_valid_until', value: [new Date().toISOString()] } },
    });
    expect(result.errors).toBeDefined();
    expect(result.errors?.[0].message).toContain('Cannot force password change for external user');

    // Cleanup
    const DELETE_USER = gql`mutation { userEdit(id: "${externalUserId}") { delete } }`;
    await queryAsAdmin({ query: DELETE_USER, variables: {} });
  });

  it('Admin should set password_valid_until on internal user', async () => {
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    const futureDate = new Date(Date.now() + 30 * 86400000).toISOString();
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [futureDate] } },
    });
    expect(queryResult.errors).toBeUndefined();

    // Cleanup
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [null] } },
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
    // Calls main execution context server
    // as requires passing the extra header
    // to check logic happening in middleware.
    // Won't participate in test coverage.
    const reportQuery = await queryInitPlatformAsAdmin(
      CREATE_REPORT_QUERY,
      REPORT_TO_CREATE,
      { applicantId: USER_CONNECTOR.id },
    );
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
    const user = await queryAsAdminWithSuccess({
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

        }
      }
    `;

    const queryResult = await queryAsAdminWithSuccess({ query: QUERY_SERVICE_ACCOUNT_USER, variables: { id: userInternalId } });
    expect(queryResult.data?.user).not.toBeNull();
    expect(queryResult.data?.user.id).toEqual(userInternalId);
  });
  it('should turn service account into user', async () => {
    const queryResult = await queryAsAdminWithSuccess({
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
    const queryResult = await queryAsAdminWithSuccess({
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
    await queryAsAdminWithError({
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
      await queryAsAdminWithSuccess({
        query: DELETE_QUERY,
        variables: { id: userId },
      });
      // Verify is no longer found
      const queryResult = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: { id: userId } });
      expect(queryResult.data.user).toBeNull();
    }
  });
});

describe('User API Token Mutation', () => {
  const USER_TOKEN_ADD_MUTATION = gql`
    mutation UserTokenAdd($input: UserTokenAddInput!) {
      userTokenAdd(input: $input) {
        token_id
        plaintext_token
        expires_at
      }
    }
  `;

  // Use the admin user ID for testing

  it('should admin generate a token for themselves', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: USER_TOKEN_ADD_MUTATION,
      variables: {
        input: {
          name: 'Integration Test Token',
          duration: 'UNLIMITED',
        },
      },
    });

    const tokenData = queryResult.data?.userTokenAdd;
    expect(tokenData).toBeDefined();
    expect(tokenData.token_id).toBeDefined();
    expect(tokenData.plaintext_token).toBeDefined();
    expect(tokenData.plaintext_token.startsWith('flgrn_octi_tkn_')).toBe(true);
    expect(tokenData.expires_at).toBeNull();
  });

  it('should admin generate a token for another user (via context)', async () => {
    // Note: Implicitly testing context handling if we were to switch users,
    // but userTokenAdd currently uses the logged-in user (context.user).
    // The current mutation definition doesn't accept a userId to generate FOR someone else directly unless impersonating.
    // For this test, we verify basic functionality first.

    const queryResult = await queryAsAdminWithSuccess({
      query: USER_TOKEN_ADD_MUTATION,
      variables: {
        input: {
          name: 'Short Lived Token',
          duration: 'DAYS_30',
        },
      },
    });

    expect(queryResult.data?.userTokenAdd.expires_at).toBeDefined();
  });
});

describe('Password expiration - isPasswordExpired', () => {
  it('returns false when password_valid_until is null', () => {
    expect(isPasswordExpired({ password_valid_until: null } as any)).toBe(false);
  });

  it('returns false when password_valid_until is undefined', () => {
    expect(isPasswordExpired({} as any)).toBe(false);
  });

  it('returns false when password_valid_until is in the future', () => {
    const future = DateTime.now().plus({ days: 6 }).toUTC().toString();
    expect(isPasswordExpired({ password_valid_until: future } as any)).toBe(false);
  });

  it('returns true when password_valid_until is in the past', () => {
    const past = DateTime.now().minus({ days: 1 }).toUTC().toString();
    expect(isPasswordExpired({ password_valid_until: past } as any)).toBe(true);
  });

  it('returns true when password_valid_until is exactly now (inclusive boundary)', () => {
    const now = DateTime.now().minus({ milliseconds: 1 }).toUTC().toString();
    expect(isPasswordExpired({ password_valid_until: now } as any)).toBe(true);
  });
});

describe('Password expiration - computePasswordValidUntilFromPolicy', () => {
  let settings: BasicStoreSettings;
  let originalValidityDays: number;

  beforeAll(async () => {
    settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    originalValidityDays = (settings as any).password_policy_validity_days ?? 0;
  });

  afterAll(async () => {
    // Restore original policy
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: originalValidityDays,
    });
  });

  it('returns null when policy validity days is 0', async () => {
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 0,
    });
    const result = await computePasswordValidUntilFromPolicy(testContext);
    expect(result).toBeNull();
  });

  it('returns a date approximately now + N days when policy is set', async () => {
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 20,
    });
    const before = DateTime.now().plus({ days: 20 }).toUTC();
    const result = await computePasswordValidUntilFromPolicy(testContext);
    const after = DateTime.now().plus({ days: 20 }).toUTC();

    expect(result).not.toBeNull();
    const resultDate = DateTime.fromISO(result!);
    expect(resultDate >= before.minus({ seconds: 1 })).toBe(true);
    expect(resultDate <= after.plus({ seconds: 1 })).toBe(true);
  });
});

describe('Password expiration - force change flow', () => {
  let editorId: string;
  let settings: BasicStoreSettings;

  beforeAll(async () => {
    editorId = await getUserIdByEmail(USER_EDITOR.email);
    settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    // Set policy to 0 (no expiry)
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 0,
    });
  });

  afterAll(async () => {
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [null] } },
    });
  });

  it('user is not expired when password_valid_until is null (no policy)', async () => {
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [null] } },
    });
    const user: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    expect(isPasswordExpired(user)).toBe(false);
  });

  it('user becomes expired when admin forces password_valid_until to a past date', async () => {
    const pastDate = DateTime.now().minus({ hours: 1 }).toISO();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [pastDate] } },
    });
    const user: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    expect(isPasswordExpired(user)).toBe(true);
  });

  it('user can change password without current password when expired, and validity resets to null (policy=0)', async () => {
    // Expire the user
    const pastDate = DateTime.now().minus({ hours: 1 }).toISO();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [pastDate] } },
    });

    // Change password without current password
    const ME_EDIT_VALIDITY = gql`
      mutation meEdit($input: [EditInput]!, $password: String) {
        meEdit(input: $input, password: $password) { id, password_valid_until }
      }
    `;
    const result = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_EDIT_VALIDITY,
      variables: { input: [{ key: 'password', value: [USER_EDITOR.password] }] },
    });

    // With policy = 0, password_valid_until should be null
    expect(result.data?.meEdit.password_valid_until).toBeNull();
  });
});

describe('Password policy propagation to all users', () => {
  let editorId: string;
  let participateId: string;

  beforeAll(async () => {
    editorId = await getUserIdByEmail(USER_EDITOR.email);
    participateId = await getUserIdByEmail(USER_PARTICIPATE.email);
    // Ensure users start with no password_valid_until
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [null] } },
    });
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: participateId, input: { key: 'password_valid_until', value: [null] } },
    });
  });

  afterAll(async () => {
    // Cleanup: clear password_valid_until and reset policy to 0
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [null] } },
    });
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: participateId, input: { key: 'password_valid_until', value: [null] } },
    });
    const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 0,
    });
  });

  it('adjustAllUsersPasswordValidUntil should shift existing dates and set dates for users without one', async () => {
    // Setup: Set a date on editor, leave participate without one
    const existingDate = new Date(Date.now() + 6 * 86400000).toISOString(); // +6 days
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [existingDate] } },
    });

    // Act: simulate policy change from 10 to 600 (diff = +590 days)
    await adjustAllUsersPasswordValidUntil(testContext, 10, 600);

    // Assert: editor date should be shifted by +590 days
    const editorAfter: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    const editorNewDate = new Date(editorAfter.password_valid_until).getTime();
    const expectedEditorDate = new Date(existingDate).getTime() + 590 * 86400000;
    expect(Math.abs(editorNewDate - expectedEditorDate)).toBeLessThan(60000); // within 1 minute

    // Assert: participate (had no date) should now have now + 600 days
    const participateAfter: any = await storeLoadById(testContext, ADMIN_USER, participateId, ENTITY_TYPE_USER);
    expect(participateAfter.password_valid_until).not.toBeNull();
    const participateNewDate = new Date(participateAfter.password_valid_until).getTime();
    const expectedParticipateDate = Date.now() + 600 * 86400000;
    expect(Math.abs(participateNewDate - expectedParticipateDate)).toBeLessThan(60000);
  });

  it('clearAllUsersPasswordValidUntil should clear dates on all internal users', async () => {
    // Setup: ensure both users have a date
    const futureDate = new Date(Date.now() + 100 * 86400000).toISOString();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [futureDate] } },
    });
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: participateId, input: { key: 'password_valid_until', value: [futureDate] } },
    });

    // Act
    await clearAllUsersPasswordValidUntil(testContext);

    // Assert: both should now have no expiry (undefined after ES clear)
    const editorAfter: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    const participateAfter: any = await storeLoadById(testContext, ADMIN_USER, participateId, ENTITY_TYPE_USER);
    expect(editorAfter.password_valid_until == null).toBe(true);
    expect(participateAfter.password_valid_until == null).toBe(true);
  });

  it('updateLocalAuth with validity 0 should clear all users dates (600 → 0)', async () => {
    // Setup: set dates on users
    const futureDate = new Date(Date.now() + 200 * 86400000).toISOString();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [futureDate] } },
    });
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: participateId, input: { key: 'password_valid_until', value: [futureDate] } },
    });

    // Set current policy to 600 days first
    const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 600,
    });

    // Act: set policy to 0 (disable)
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 0,
    });

    // Assert: all users should have password_valid_until cleared (undefined after ES clear)
    const editorAfter: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    const participateAfter: any = await storeLoadById(testContext, ADMIN_USER, participateId, ENTITY_TYPE_USER);
    expect(editorAfter.password_valid_until == null).toBe(true);
    expect(participateAfter.password_valid_until == null).toBe(true);
  });

  it('updateLocalAuth with changed validity should shift dates (10 → 600)', async () => {
    // Setup: set policy to 10, then set a date on editor (simulating password changed 4 days ago)
    const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 10,
    });
    // Editor: password changed 4 days ago → expiry in 6 days
    const editorExpiry = new Date(Date.now() + 6 * 86400000).toISOString();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [editorExpiry] } },
    });
    // Participate: no date set (clear it)
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: participateId, input: { key: 'password_valid_until', value: [null] } },
    });

    // Act: change policy from 10 to 600
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 600,
    });

    // Assert: editor expiry shifted by +590 days
    const editorAfter: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    const editorNewDate = new Date(editorAfter.password_valid_until).getTime();
    const expectedEditorDate = new Date(editorExpiry).getTime() + 590 * 86400000;
    expect(Math.abs(editorNewDate - expectedEditorDate)).toBeLessThan(60000);

    // Assert: participate (no date) should now have now + 600 days
    const participateAfter: any = await storeLoadById(testContext, ADMIN_USER, participateId, ENTITY_TYPE_USER);
    expect(participateAfter.password_valid_until).not.toBeNull();
    const participateNewDate = new Date(participateAfter.password_valid_until).getTime();
    const expectedParticipateDate = Date.now() + 600 * 86400000;
    expect(Math.abs(participateNewDate - expectedParticipateDate)).toBeLessThan(60000);
  });

  it('updateLocalAuth 500→0→1 should give now+1', async () => {
    // Setup: set policy to 500, set dates on users
    const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 500,
    });
    // Set a date in the future (simulating password changed recently with 500 day policy)
    const oldDate = new Date(Date.now() + 490 * 86400000).toISOString();
    await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: editorId, input: { key: 'password_valid_until', value: [oldDate] } },
    });

    // Step 1: set policy to 0 (should clear dates)
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 0,
    });

    // Verify dates are cleared
    const editorMid: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    expect(editorMid.password_valid_until == null).toBe(true);

    // Step 2: set policy to 1 (should give now+1 day)
    await updateLocalAuth(testContext, ADMIN_USER, settings.id, {
      enabled: true,
      password_policy_max_length: 0,
      password_policy_min_length: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_numbers: 0,
      password_policy_min_symbols: 0,
      password_policy_min_uppercase: 0,
      password_policy_min_words: 0,
      password_policy_validity_days: 1,
    });

    // Assert: editor should have now+1 day
    const editorAfter: any = await storeLoadById(testContext, ADMIN_USER, editorId, ENTITY_TYPE_USER);
    expect(editorAfter.password_valid_until).not.toBeNull();
    const editorNewDate = new Date(editorAfter.password_valid_until).getTime();
    const expectedDate = Date.now() + 1 * 86400000; // now + 1 day
    // Should be within 1 minute of now+1day
    expect(Math.abs(editorNewDate - expectedDate)).toBeLessThan(60000);
    // Should NOT be close to old_date+1
    const oldDatePlus1 = new Date(oldDate).getTime() + 1 * 86400000;
    expect(Math.abs(editorNewDate - oldDatePlus1)).toBeGreaterThan(86400000); // at least 1 day away from old_date+1
  });
});

describe('Bookmarks API', () => {
  const BOOKMARKS_QUERY = gql`
    query Bookmarks($first: Int, $after: ID, $types: [String], $orderBy: StixDomainObjectsOrdering, $orderMode: OrderingMode, $filters: FilterGroup) {
      bookmarks(first: $first, after: $after, types: $types, orderBy: $orderBy, orderMode: $orderMode, filters: $filters) {
        edges {
          node {
            id
            entity_type
            ... on Malware {
              name
              created
            }
            ... on Report {
              name
              published
            }
          }
        }
        pageInfo {
          startCursor
          endCursor
          hasNextPage
          hasPreviousPage
          globalCount
        }
      }
    }
  `;

  const BOOKMARK_ADD_MUTATION = gql`
    mutation BookmarkAdd($id: ID!, $type: String!) {
      bookmarkAdd(id: $id, type: $type) {
        id
        entity_type
      }
    }
  `;

  const BOOKMARK_DELETE_MUTATION = gql`
    mutation BookmarkDelete($id: ID!) {
      bookmarkDelete(id: $id)
    }
  `;

  const MALWARE_ADD_MUTATION = gql`
    mutation MalwareAdd($input: MalwareAddInput!) {
      malwareAdd(input: $input) {
        id
        name
        entity_type
      }
    }
  `;

  const MALWARE_DELETE_MUTATION = gql`
    mutation MalwareDelete($id: ID!) {
      malwareEdit(id: $id) {
        delete
      }
    }
  `;

  const REPORT_ADD_MUTATION = gql`
    mutation ReportAdd($input: ReportAddInput!) {
      reportAdd(input: $input) {
        id
        name
        entity_type
      }
    }
  `;

  const REPORT_DELETE_MUTATION = gql`
    mutation ReportDelete($id: ID!) {
      reportEdit(id: $id) {
        delete
      }
    }
  `;

  let malware1Id: string;
  let malware2Id: string;
  let reportId: string;

  beforeAll(async () => {
    // Create test malware entities
    const malware1 = await queryAsAdminWithSuccess({
      query: MALWARE_ADD_MUTATION,
      variables: { input: { name: 'Bookmark Malware 1', malware_types: ['ransomware'] } },
    });
    malware1Id = malware1.data?.malwareAdd.id;

    const malware2 = await queryAsAdminWithSuccess({
      query: MALWARE_ADD_MUTATION,
      variables: { input: { name: 'Bookmark Malware 2', malware_types: ['trojan'] } },
    });
    malware2Id = malware2.data?.malwareAdd.id;

    // Create a test report
    const report = await queryAsAdminWithSuccess({
      query: REPORT_ADD_MUTATION,
      variables: { input: { name: 'Bookmark Report', published: '2024-01-01T00:00:00.000Z' } },
    });
    reportId = report.data?.reportAdd.id;

    // Add all three as bookmarks
    await queryAsAdminWithSuccess({
      query: BOOKMARK_ADD_MUTATION,
      variables: { id: malware1Id, type: 'Malware' },
    });
    await queryAsAdminWithSuccess({
      query: BOOKMARK_ADD_MUTATION,
      variables: { id: malware2Id, type: 'Malware' },
    });
    await queryAsAdminWithSuccess({
      query: BOOKMARK_ADD_MUTATION,
      variables: { id: reportId, type: 'Report' },
    });
  });

  afterAll(async () => {
    // Clean up bookmarks
    await queryAsAdmin({ query: BOOKMARK_DELETE_MUTATION, variables: { id: malware1Id } });
    await queryAsAdmin({ query: BOOKMARK_DELETE_MUTATION, variables: { id: malware2Id } });
    await queryAsAdmin({ query: BOOKMARK_DELETE_MUTATION, variables: { id: reportId } });
    // Delete test entities
    await queryAsAdmin({ query: MALWARE_DELETE_MUTATION, variables: { id: malware1Id } });
    await queryAsAdmin({ query: MALWARE_DELETE_MUTATION, variables: { id: malware2Id } });
    await queryAsAdmin({ query: REPORT_DELETE_MUTATION, variables: { id: reportId } });
  });

  it('should list all bookmarks regardless of type', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: {},
    });
    const edges = queryResult.data?.bookmarks.edges;
    expect(edges.length).toEqual(3);
    const ids = edges.map((e: any) => e.node.id);
    expect(ids).toContain(malware1Id);
    expect(ids).toContain(malware2Id);
    expect(ids).toContain(reportId);
  });

  it('should list only Malware bookmarks when filtered by type', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: { types: ['Malware'] },
    });
    const edges = queryResult.data?.bookmarks.edges;
    expect(edges.length).toEqual(2);
    const ids = edges.map((e: any) => e.node.id);
    expect(ids).toContain(malware1Id);
    expect(ids).toContain(malware2Id);
    expect(ids).not.toContain(reportId);
    edges.forEach((e: any) => {
      expect(e.node.entity_type).toBe('Malware');
    });
  });

  it('should list only Report bookmarks when filtered by type', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: { types: ['Report'] },
    });
    const edges = queryResult.data?.bookmarks.edges;
    expect(edges.length).toEqual(1);
    expect(edges[0].node.id).toEqual(reportId);
    expect(edges[0].node.entity_type).toBe('Report');
  });

  it('should filter bookmarks by entity type using filters parameter', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq' }],
          filterGroups: [],
        },
      },
    });
    const edges = queryResult.data?.bookmarks.edges;
    expect(edges.length).toEqual(2);
    edges.forEach((e: any) => {
      expect(e.node.entity_type).toBe('Malware');
    });
  });

  it('should order bookmarks by name ascending', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: { types: ['Malware'], orderBy: 'name', orderMode: 'asc' },
    });
    const edges = queryResult.data?.bookmarks.edges;
    const names = edges.map((e: any) => e.node.name);
    expect(names[0]).toBe('Bookmark Malware 1');
    expect(names[1]).toBe('Bookmark Malware 2');
  });

  it('should order bookmarks by name descending', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: { types: ['Malware'], orderBy: 'name', orderMode: 'desc' },
    });
    const edges = queryResult.data?.bookmarks.edges;
    const names = edges.map((e: any) => e.node.name);
    expect(names[0]).toBe('Bookmark Malware 2');
    expect(names[1]).toBe('Bookmark Malware 1');
  });

  it('should paginate bookmarks with first parameter', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: { first: 2, orderBy: 'name', orderMode: 'asc' },
    });
    const edges = queryResult.data?.bookmarks.edges;
    expect(edges.length).toEqual(2);
    const pageInfo = queryResult.data?.bookmarks.pageInfo;
    expect(pageInfo.hasNextPage).toBe(true);
  });

  it('should reject filters with unsupported keys', async () => {
    await queryAsAdminWithError({
      query: BOOKMARKS_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filters: [{ key: ['objectLabel'], values: ['some-label-id'], operator: 'eq' }],
          filterGroups: [],
        },
      },
    }, 'Bookmarks widgets only support filter with key=entity_type');
  });

  it('should return empty connection when no bookmarks match type', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: BOOKMARKS_QUERY,
      variables: { types: ['Campaign'] },
    });
    const edges = queryResult.data?.bookmarks.edges;
    expect(edges.length).toBe(0);
  });
});
