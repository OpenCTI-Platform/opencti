import { APIRequestContext } from '@playwright/test';
import { graphqlRequest } from './graphql.data';

interface NamedNode {
  id: string;
  name: string;
}

interface EdgesOf<T> {
  edges: Array<{ node: T }>;
}

const getCapabilities = () => `
  query {
    capabilities {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

export const getRoles = () => `
  query {
    roles {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface AddRoleInput {
  name: string;
  capabilities?: string[];
}

const addRole = (input: AddRoleInput) => `
  mutation {
    roleAdd(input: { name: "${input.name}" }) {
      id
      name
    }
  }
`;

const addRoleCapability = (roleId: string, capabilityId: string) => `
  mutation {
    roleEdit(id: "${roleId}") {
      relationAdd(input: {
        toId: "${capabilityId}",
        relationship_type: "has-capability",
      }) {
        id
      }
    }
  }
`;

// Seeded one at a time on purpose: concurrent edits of the same entity family have been seen
// leaving the platform with a stale view of one of them (see #18326), and the seeding is
// small enough that the parallelism bought nothing.
export const addRoles = async (request: APIRequestContext, roles: AddRoleInput[]) => {
  const { capabilities } = await graphqlRequest<{ capabilities: EdgesOf<NamedNode> }>(request, getCapabilities(), 'list capabilities');
  const allCapabilities = capabilities.edges.map((e) => e.node);

  const { roles: existing } = await graphqlRequest<{ roles: EdgesOf<NamedNode> }>(request, getRoles(), 'list roles');
  const existingRoles = existing.edges.map((e) => e.node.name);

  for (const role of roles) {
    if (existingRoles.includes(role.name)) continue;
    const { roleAdd } = await graphqlRequest<{ roleAdd: NamedNode }>(request, addRole(role), `create role ${role.name}`);
    for (const capabilityName of role.capabilities ?? []) {
      const capability = allCapabilities.find((c) => c.name === capabilityName);
      if (!capability) throw new Error(`create role ${role.name}: unknown capability ${capabilityName}`);
      await graphqlRequest(request, addRoleCapability(roleAdd.id, capability.id), `add capability ${capabilityName} to role ${role.name}`);
    }
  }
};
