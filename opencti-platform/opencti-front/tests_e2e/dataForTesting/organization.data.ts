import { APIRequestContext } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';

export const getOrganizations = () => `
  query {
    organizations {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

interface AddOrganizationInput {
  name: string;
}

interface OrganizationNode {
  id: string;
  name: string;
}

const getOrganizationNodes = async (request: APIRequestContext): Promise<OrganizationNode[]> => {
  const response = await request.post('/graphql', { data: { query: getOrganizations() } });
  const responseData = JSON.parse((await response.body()).toString());
  return responseData.data.organizations.edges.map((e: { node: OrganizationNode }) => e.node);
};

const addOrganization = (input: AddOrganizationInput) => `
  mutation {
    organizationAdd(input: {
      name: "${input.name}",
    }) {
      id
      name
    }
  }
`;

export const addOrganizations = async (request: APIRequestContext, organizations: AddOrganizationInput[]) => {
  const existingOrganizations = (await getOrganizationNodes(request)).map((node) => node.name);

  await Promise.all(organizations.map(async (organization) => {
    if (!existingOrganizations.includes(organization.name)) {
      await request.post('/graphql', { data: { query: addOrganization(organization) } });
    }
  }));
};

const getMe = () => 'query { me { id name } }';

// "use" (not "view") is required so members can still select this org as a Report's Author (`CreatedByField.jsx`'s `canUse()` filters out plain "view" access).
const editAuthorizedMembers = (id: string, adminId: string, viewerIds: string[]) => `
  mutation {
    stixDomainObjectEdit(id: "${id}") {
      editAuthorizedMembers(input: [
        { id: "${adminId}", access_right: "admin" },
        ${viewerIds.map((memberId) => `{ id: "${memberId}", access_right: "use" }`).join(',\n        ')}
      ]) {
        id
        ... on Organization {
          authorized_members {
            member_id
            access_right
          }
        }
      }
    }
  }
`;

/** Restricts an organization's own visibility to only the given viewer organizations (plus the current API user, required by the backend's admin-presence validation). */
export const restrictOrganizationVisibility = async (request: APIRequestContext, organizationName: string, viewerOrganizationNames: string[]) => {
  const nodes = await getOrganizationNodes(request);
  const targetId = nodes.find((n) => n.name === organizationName)!.id;
  const viewerIds = viewerOrganizationNames.map((name) => nodes.find((n) => n.name === name)!.id);
  const meResponse = await request.post('/graphql', { data: { query: getMe() } });
  const meResponseData = JSON.parse((await meResponse.body()).toString());
  const adminId = meResponseData.data.me.id;
  const response = await request.post('/graphql', { data: { query: editAuthorizedMembers(targetId, adminId, viewerIds) } });
  const responseData = JSON.parse((await response.body()).toString());
  if (responseData.errors) {
    throw new Error(`restrictOrganizationVisibility failed: ${JSON.stringify(responseData.errors)}`);
  }
  const authorizedMembers = responseData.data.stixDomainObjectEdit.editAuthorizedMembers.authorized_members;
  const expectedMembers = [
    { member_id: adminId, access_right: 'admin' },
    ...viewerIds.map((memberId) => ({ member_id: memberId, access_right: 'use' })),
  ];
  expect(
    authorizedMembers,
    `Expected ${organizationName}'s organization access grants to be saved; ACCESS_RESTRICTION_CAN_USE must be enabled`,
  ).toEqual(expect.arrayContaining(expectedMembers));
  expect(authorizedMembers).toHaveLength(expectedMembers.length);
};
