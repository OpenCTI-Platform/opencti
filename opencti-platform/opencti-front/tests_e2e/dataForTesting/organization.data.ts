import { APIRequestContext } from '@playwright/test';

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

// "use" (not "view") is required so members can still SELECT this org as a Report's Author in
// the Created By picker (`CreatedByField.jsx`'s `canUse()` filters out plain "view" access -
// see `opencti-graphql/src/utils/authorizedMembers.ts`); "view" alone would silently hide it
// from the autocomplete for everyone, including its own org's members.
const editAuthorizedMembers = (id: string, adminId: string, viewerIds: string[]) => `
  mutation {
    stixDomainObjectEdit(id: "${id}") {
      editAuthorizedMembers(input: [
        { id: "${adminId}", access_right: "admin" },
        ${viewerIds.map((memberId) => `{ id: "${memberId}", access_right: "use" }`).join(',\n        ')}
      ]) {
        id
      }
    }
  }
`;

/**
 * Restricts an organization's own visibility to only the given member (org/group/org) internal
 * ids (plus the current API user, required by the backend's admin-presence validation) - e.g. so
 * an Identity used as a Report's `createdBy` is only visible to specific orgs, exercising the
 * "restricted author" display for everyone else (`ItemAuthor.tsx`'s EMPTY_VALUE).
 */
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
};
