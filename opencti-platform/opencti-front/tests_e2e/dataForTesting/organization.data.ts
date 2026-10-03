import { APIRequestContext } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import { executeGraphql } from './query-utils';

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
  const { organizations } = await executeGraphql<{
    organizations: { edges: { node: OrganizationNode }[] } | null;
  }>(request, 'Get fixture organizations', getOrganizations());
  if (!organizations) {
    throw new Error('Get fixture organizations failed: organizations is null');
  }
  return organizations.edges.map(({ node }) => node);
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
      await executeGraphql(request, `Create organization ${organization.name}`, addOrganization(organization));
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
  const organizationId = (name: string) => {
    const node = nodes.find((n) => n.name === name);
    if (!node) {
      throw new Error(`Cannot restrict organization visibility: organization "${name}" was not found`);
    }
    return node.id;
  };
  const targetId = organizationId(organizationName);
  const viewerIds = viewerOrganizationNames.map(organizationId);
  const { me } = await executeGraphql<{ me: { id: string } }>(request, 'Read fixture admin', getMe());
  const adminId = me.id;
  const responseData = await executeGraphql<{
    stixDomainObjectEdit: {
      editAuthorizedMembers: { authorized_members: { member_id: string; access_right: string }[] };
    };
  }>(request, 'restrictOrganizationVisibility', editAuthorizedMembers(targetId, adminId, viewerIds));
  const authorizedMembers = responseData.stixDomainObjectEdit.editAuthorizedMembers.authorized_members;
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
