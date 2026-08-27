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

export const addUsers = async (request: APIRequestContext, users: AddUserInput[]) => {
  const groupsResponse = await request.post('/graphql', { data: { query: getGroups() } });
  const groupsResponseData = JSON.parse((await groupsResponse.body()).toString());
  const groups = groupsResponseData.data.groups.edges.map((e: any) => e.node);

  const organizationsResponse = await request.post('/graphql', { data: { query: getOrganizations() } });
  const organizationsResponseData = JSON.parse((await organizationsResponse.body()).toString());
  const organizations = organizationsResponseData.data.organizations.edges.map((e: any) => e.node);

  const existingUsersResponse = await request.post('/graphql', { data: { query: getUsers() } });
  const existingUsersResponseData = JSON.parse((await existingUsersResponse.body()).toString());
  const existingUsers = existingUsersResponseData.data.users.edges.map((e: any) => e.node.name);

  await Promise.all(users.map(async (user) => {
    if (!existingUsers.includes(user.name)) {
      const userOrganizations = organizations.filter((organization: any) => user.organizations?.includes(organization.name));
      const organizationIds = userOrganizations.map((organization: any) => organization.id);
      const addUserResponse = await request.post('/graphql', { data: { query: addUser(user, organizationIds) } });

      if (user.groups && user.groups.length > 0) {
        const userGroups = groups.filter((group: any) => user.groups?.includes(group.name));
        const addUserResponseData = JSON.parse((await addUserResponse.body()).toString());
        const userId = addUserResponseData.data.userAdd.id;

        await Promise.all(userGroups.map(async (group: any) => {
          await request.post('/graphql', { data: { query: addUserGroup(userId, group.id) } });
        }));
      }
    }
  }));
};
