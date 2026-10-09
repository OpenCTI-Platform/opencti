import { APIRequestContext } from '@playwright/test';
import { getRoles } from './role.data';
import { graphqlRequest } from './graphql.data';

interface NamedNode {
  id: string;
  name: string;
}

interface EdgesOf<T> {
  edges: Array<{ node: T }>;
}

export const getGroups = () => `
  query {
    groups {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface AddGroupInput {
  name: string;
  roles: string[];
}

const addGroup = (input: AddGroupInput) => `
  mutation {
    groupAdd(input: {
      name: "${input.name}",
      group_confidence_level: {
        max_confidence: 100,
        overrides: []
      },
    }) {
      id
      name
    }
  }
`;

const addGroupRole = (groupId: string, roleId: string) => `
  mutation {
    groupEdit(id: "${groupId}") {
      relationAdd(input: {
        toId: "${roleId}",
        relationship_type: "has-role",
      }) {
        id
      }
    }
  }
`;

export const addGroups = async (request: APIRequestContext, groups: AddGroupInput[]) => {
  const { roles } = await graphqlRequest<{ roles: EdgesOf<NamedNode> }>(request, getRoles(), 'list roles');
  const allRoles = roles.edges.map((e) => e.node);

  const { groups: existing } = await graphqlRequest<{ groups: EdgesOf<NamedNode> }>(request, getGroups(), 'list groups');
  const existingGroups = existing.edges.map((e) => e.node.name);

  for (const group of groups) {
    if (existingGroups.includes(group.name)) continue;
    const { groupAdd } = await graphqlRequest<{ groupAdd: NamedNode }>(request, addGroup(group), `create group ${group.name}`);
    for (const roleName of group.roles) {
      const role = allRoles.find((r) => r.name === roleName);
      if (!role) throw new Error(`create group ${group.name}: unknown role ${roleName}`);
      await graphqlRequest(request, addGroupRole(groupAdd.id, role.id), `add role ${roleName} to group ${group.name}`);
    }
  }
};
