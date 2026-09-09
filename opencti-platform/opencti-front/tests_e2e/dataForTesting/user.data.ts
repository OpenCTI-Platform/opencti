import { APIRequestContext } from '@playwright/test';
import { getGroups } from './group.data';
import { getOrganizations } from './organization.data';

export const getUsers = () => `
  query {
    users {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface AddUserInput {
  name: string;
  user_email: string;
  password: string;
  groups: string[];
  organizations?: string[];
}

interface NamedEntity {
  id: string;
  name: string;
}

const addUser = (input: AddUserInput, organizationIds: string[]) => `
  mutation {
    userAdd(input: {
      name: "${input.name}",
      user_email: "${input.user_email}",
      password: "${input.password}",
      objectOrganization: [${organizationIds.map((id) => `"${id}"`).join(', ')}],
    }) {
      id
      name
    }
  }
`;

const addUserGroup = (userId: string, groupId: string) => `
  mutation {
    userEdit(id: "${userId}") {
      relationAdd(input: {
        toId: "${groupId}",
        relationship_type: "member-of",
      }) {
        id
      }
    }
  }
`;

const resetUserDraftContext = async (request: APIRequestContext, userId: string) => {
  const response = await request.post('/graphql', {
    data: {
      query: `
        mutation ResetTestUserDraftContext($id: ID!) {
          userEdit(id: $id) {
            fieldPatch(input: [{ key: "draft_context", value: [""] }]) {
              id
            }
          }
        }
      `,
      variables: { id: userId },
    },
  });
  const data = await response.json();
  if (data.errors) {
    throw new Error(`ResetTestUserDraftContext failed: ${JSON.stringify(data.errors)}`);
  }
};

export const addUsers = async (request: APIRequestContext, users: AddUserInput[]) => {
  const groupsResponse = await request.post('/graphql', { data: { query: getGroups() } });
  const groupsResponseData = JSON.parse((await groupsResponse.body()).toString());
  const groups: NamedEntity[] = groupsResponseData.data.groups.edges.map((e: { node: NamedEntity }) => e.node);

  const organizationsResponse = await request.post('/graphql', { data: { query: getOrganizations() } });
  const organizationsResponseData = JSON.parse((await organizationsResponse.body()).toString());
  const organizations: NamedEntity[] = organizationsResponseData.data.organizations.edges.map((e: { node: NamedEntity }) => e.node);

  const existingUsersResponse = await request.post('/graphql', { data: { query: getUsers() } });
  const existingUsersResponseData = JSON.parse((await existingUsersResponse.body()).toString());
  const existingUsers: NamedEntity[] = existingUsersResponseData.data.users.edges.map((e: { node: NamedEntity }) => e.node);

  await Promise.all(users.map(async (user) => {
    const existingUser = existingUsers.find((u) => u.name === user.name);
    if (existingUser && user.organizations) {
      // Old workflow runs can leave a persona in a draft they can no longer access.
      await resetUserDraftContext(request, existingUser.id);
    }
    if (!existingUser) {
      const userOrganizations = organizations.filter((organization) => user.organizations?.includes(organization.name));
      const organizationIds = userOrganizations.map((organization) => organization.id);
      const addUserResponse = await request.post('/graphql', { data: { query: addUser(user, organizationIds) } });

      if (user.groups && user.groups.length > 0) {
        const userGroups = groups.filter((group) => user.groups?.includes(group.name));
        const addUserResponseData = JSON.parse((await addUserResponse.body()).toString());
        const userId = addUserResponseData.data.userAdd.id;

        await Promise.all(userGroups.map(async (group) => {
          await request.post('/graphql', { data: { query: addUserGroup(userId, group.id) } });
        }));
      }
    }
  }));
};
