import { APIRequestContext } from '@playwright/test';
import { getGroups } from './group.data';
import { graphqlRequest } from './graphql.data';

interface NamedNode {
  id: string;
  name: string;
}

interface EdgesOf<T> {
  edges: Array<{ node: T }>;
}

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
}

const addUser = (input: AddUserInput) => `
  mutation {
    userAdd(input: {
      name: "${input.name}",
      user_email: "${input.user_email}",
      password: "${input.password}",
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

const getUserGroups = (userId: string) => `
  query {
    user(id: "${userId}") {
      groups {
        edges {
          node {
            name
          }
        }
      }
    }
  }
`;

export const addUsers = async (request: APIRequestContext, users: AddUserInput[]) => {
  const { groups } = await graphqlRequest<{ groups: EdgesOf<NamedNode> }>(request, getGroups(), 'list groups');
  const allGroups = groups.edges.map((e) => e.node);

  const { users: existing } = await graphqlRequest<{ users: EdgesOf<NamedNode> }>(request, getUsers(), 'list users');
  const existingUsers = new Map(existing.edges.map((e) => [e.node.name, e.node.id]));

  for (const user of users) {
    let userId = existingUsers.get(user.name);
    if (!userId) {
      const { userAdd } = await graphqlRequest<{ userAdd: NamedNode }>(request, addUser(user), `create user ${user.name}`);
      userId = userAdd.id;
      for (const groupName of user.groups) {
        const group = allGroups.find((g) => g.name === groupName);
        if (!group) throw new Error(`create user ${user.name}: unknown group ${groupName}`);
        await graphqlRequest(request, addUserGroup(userId, group.id), `add user ${user.name} to group ${groupName}`);
      }
    }
    const { user: resolved } = await graphqlRequest<{ user: { groups: EdgesOf<{ name: string }> } }>(request, getUserGroups(userId), `read groups of user ${user.name}`);
    const resolvedGroups = resolved.groups.edges.map((e) => e.node.name);
    const missing = user.groups.filter((g) => !resolvedGroups.includes(g));
    if (missing.length > 0) {
      throw new Error(`user ${user.name} is stored without the group(s) ${missing.join(', ')}: the platform resolves [${resolvedGroups.join(', ')}]`);
    }
  }
};
