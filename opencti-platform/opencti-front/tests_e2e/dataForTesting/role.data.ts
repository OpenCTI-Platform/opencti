import { APIRequestContext } from '@playwright/test';

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

export const addRoles = async (request: APIRequestContext, roles: AddRoleInput[]) => {
  const capabilitiesResponse = await request.post('/graphql', { data: { query: getCapabilities() } });
  const capabilitiesResponseData = JSON.parse((await capabilitiesResponse.body()).toString());
  const capabilities = capabilitiesResponseData.data.capabilities.edges.map((e: any) => e.node);

  const existingRolesResponse = await request.post('/graphql', { data: { query: getRoles() } });
  const existingRolesResponseData = JSON.parse((await existingRolesResponse.body()).toString());
  const existingRoles = existingRolesResponseData.data.roles.edges.map((e: any) => e.node.name);

  await Promise.all(roles.map(async (role) => {
    if (!existingRoles.includes(role.name)) {
      const addRoleResponse = await request.post('/graphql', { data: { query: addRole(role) } });

      if (role.capabilities && role.capabilities.length > 0) {
        const roleCapabilities = capabilities.filter((capa: any) => role.capabilities?.includes(capa.name));
        const addRoleResponseData = JSON.parse((await addRoleResponse.body()).toString());
        const roleId = addRoleResponseData.data.roleAdd.id;

        await Promise.all(roleCapabilities.map(async (capa: any) => {
          await request.post('/graphql', { data: { query: addRoleCapability(roleId, capa.id) } });
        }));
      }
    }
  }));
};
