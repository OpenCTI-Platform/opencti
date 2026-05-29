import { afterAll, beforeAll, expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR, TEST_ORGANIZATION, USER_SECURITY } from '../../utils/testQuery';
import { queryAsAdmin, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { queryAsUserIsExpectedError } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query organizations(
    $first: Int
    $after: ID
    $orderBy: OrganizationsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    organizations(
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
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query organization($id: String!) {
    organization(id: $id) {
      id
      standard_id
      name
      description
      x_opencti_score
      sectors {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      subOrganizations {
        edges {
          node {
            id
            standard_id
            name
          }
        }
      }
      toStix
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation OrganizationEdit($id: ID!, $input: [EditInput]!) {
    organizationFieldPatch(id: $id, input: $input) {
      id
      name
      x_opencti_score
    }
  }
`;

const DELETE_QUERY = gql`
  mutation organizationDelete($id: ID!) {
    organizationDelete(id: $id)
  }
`;

describe('Organization resolver standard behavior', () => {
  let organizationInternalId;
  const organizationStixId = 'identity--43008345-56bd-4175-adad-312bef2ff6a1';
  it('should organization created', async () => {
    const CREATE_QUERY = gql`
      mutation OrganizationAdd($input: OrganizationAddInput!) {
        organizationAdd(input: $input) {
          id
          name
          description
          x_opencti_score
        }
      }
    `;
    // Create the organization
    const ORGANIZATION_TO_CREATE = {
      input: {
        name: 'Organization',
        stix_id: organizationStixId,
        description: 'Organization description',
        x_opencti_score: 50,
      },
    };
    const organization = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: ORGANIZATION_TO_CREATE,
    });
    expect(organization).not.toBeNull();
    expect(organization.data.organizationAdd).not.toBeNull();
    expect(organization.data.organizationAdd.name).toEqual('Organization');
    expect(organization.data.organizationAdd.x_opencti_score).toEqual(50);
    organizationInternalId = organization.data.organizationAdd.id;
  });
  it('should organization loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: organizationInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.id).toEqual(organizationInternalId);
    expect(queryResult.data.organization.toStix.length).toBeGreaterThan(5);
  });
  it('should organization loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: organizationStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.id).toEqual(organizationInternalId);
  });
  it('should organization sectors be accurate', async () => {
    const organization = await elLoadById(testContext, ADMIN_USER, 'identity--c017f212-546b-4f21-999d-97d3dc558f7b');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: organization.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.standard_id).toEqual('identity--732421a0-8471-52de-8d9f-18c8b260813c');
    expect(queryResult.data.organization.sectors.edges.length).toEqual(1);
    expect(queryResult.data.organization.sectors.edges[0].node.standard_id).toEqual(
      'identity--6e24d2a6-6ce1-5fbb-b3c6-e37f1dc381ff',
    );
  });
  it('should organization sub-organizations be accurate', async () => {
    const organization = await elLoadById(testContext, ADMIN_USER, 'identity--7b82b010-b1c0-4dae-981f-7756374a17df');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: organization.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).not.toBeNull();
    expect(queryResult.data.organization.subOrganizations.edges.length).toEqual(1);
    expect(queryResult.data.organization.subOrganizations.edges[0].node.standard_id).toEqual(
      'identity--8c641a55-16b5-503d-9cc3-bf68ef0c40cc',
    );
  });
  it('should list organizations', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.organizations.edges.length).toEqual(10);
  });
  it('should update organization', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: organizationInternalId, input: { key: 'name', value: ['Organization - test'] } },
    });
    expect(queryResult.data.organizationFieldPatch.name).toEqual('Organization - test');
  });
  it('should update score', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: organizationInternalId, input: { key: 'x_opencti_score', value: 10 } },
    });
    expect(queryResult.data.organizationFieldPatch.x_opencti_score).toEqual(10);
  });
  it('should context patch organization', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: EditContext!) {
        organizationContextPatch(id: $id, input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: organizationInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.organizationContextPatch.id).toEqual(organizationInternalId);
  });
  it('should context clean organization', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OrganizationEdit($id: ID!) {
        organizationContextClean(id: $id) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: organizationInternalId },
    });
    expect(queryResult.data.organizationContextClean.id).toEqual(organizationInternalId);
  });
  it('should add relation in organization', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        organizationRelationAdd(id: $id, input: $input) {
          id
          from {
            ... on Organization {
              objectMarking {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: organizationInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.organizationRelationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in organization', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation OrganizationEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        organizationRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
          id
          objectMarking {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: organizationInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.organizationRelationDelete.objectMarking.length).toEqual(0);
  });
  it('should organization deleted', async () => {
    // Delete the organization
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: organizationInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: organizationStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.organization).toBeNull();
  });
  it('should not delete organization if it has members', async () => {
    await queryAsUserIsExpectedError(USER_EDITOR, {
      query: DELETE_QUERY,
      variables: { id: TEST_ORGANIZATION.id },
    }, 'Cannot delete the organization.', 'FUNCTIONAL_ERROR');

    await queryAsUserIsExpectedError(USER_SECURITY, {
      query: DELETE_QUERY,
      variables: { id: TEST_ORGANIZATION.id },
    }, 'Cannot delete an organization that has members.', 'FUNCTIONAL_ERROR');
  });
});

describe('Organization default_dashboard user cache refresh', () => {
  let testOrganizationId;
  let dashboardId;
  let dashboardUpdatedId;
  const dashboardToDeleteIds = [];

  const CREATE_DASHBOARD_QUERY = gql`
    mutation CreateDashboard($input: WorkspaceAddInput!) {
      workspaceAdd(input: $input) {
        id
        name
      }
    }
  `;

  const ORGANIZATION_FIELD_PATCH_QUERY = gql`
    mutation OrganizationEdit($id: ID!, $input: [EditInput]!) {
      organizationFieldPatch(id: $id, input: $input) {
        id
        default_dashboard {
          id
          name
        }
      }
    }
  `;

  const ME_DEFAULT_DASHBOARDS_QUERY = gql`
    query MeDefaultDashboards {
      me {
        id
        default_dashboards {
          id
          name
        }
      }
    }
  `;

  beforeAll(async () => {
    // Resolve the TEST_ORGANIZATION internal id
    const orgResult = await elLoadById(testContext, ADMIN_USER, TEST_ORGANIZATION.id);
    testOrganizationId = orgResult.internal_id;

    // Create a first dashboard
    const dashboardCreation = await queryAsAdmin({
      query: CREATE_DASHBOARD_QUERY,
      variables: { input: { type: 'dashboard', name: 'orga-dashboard-test' } },
    });
    dashboardId = dashboardCreation.data.workspaceAdd.id;
    dashboardToDeleteIds.push(dashboardId);
  });

  afterAll(async () => {
    // Remove default_dashboard from the organization
    await queryAsAdmin({
      query: ORGANIZATION_FIELD_PATCH_QUERY,
      variables: {
        id: testOrganizationId,
        input: [{ key: 'default_dashboard', value: [null] }],
      },
    });
    // Delete created dashboards
    for (const id of dashboardToDeleteIds) {
      await queryAsAdmin({
        query: gql`
          mutation workspaceDelete($id: ID!) {
            workspaceDelete(id: $id)
          }
        `,
        variables: { id },
      });
    }
  });

  it('should set default_dashboard on organization and refresh user cache', async () => {
    // Set default_dashboard on the organization
    const patchResult = await queryAsAdmin({
      query: ORGANIZATION_FIELD_PATCH_QUERY,
      variables: {
        id: testOrganizationId,
        input: [{ key: 'default_dashboard', value: dashboardId }],
      },
    });
    expect(patchResult.data.organizationFieldPatch.default_dashboard).not.toBeNull();
    expect(patchResult.data.organizationFieldPatch.default_dashboard.id).toEqual(dashboardId);
    expect(patchResult.data.organizationFieldPatch.default_dashboard.name).toEqual('orga-dashboard-test');

    // Verify that USER_EDITOR (member of TEST_ORGANIZATION) sees the dashboard in default_dashboards
    const userResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_DEFAULT_DASHBOARDS_QUERY,
    });
    expect(userResult.data.me).not.toBeNull();
    const dashboardIds = userResult.data.me.default_dashboards.map((d) => d.id);
    expect(dashboardIds).toContain(dashboardId);
  });

  it('should update default_dashboard on organization and refresh user cache', async () => {
    // Create a new dashboard
    const newDashboardCreation = await queryAsAdmin({
      query: CREATE_DASHBOARD_QUERY,
      variables: { input: { type: 'dashboard', name: 'orga-dashboard-updated' } },
    });
    dashboardUpdatedId = newDashboardCreation.data.workspaceAdd.id;
    dashboardToDeleteIds.push(dashboardUpdatedId);

    // Update default_dashboard to the new dashboard
    const patchResult = await queryAsAdmin({
      query: ORGANIZATION_FIELD_PATCH_QUERY,
      variables: {
        id: testOrganizationId,
        input: [{ key: 'default_dashboard', value: [dashboardUpdatedId] }],
      },
    });
    expect(patchResult.data.organizationFieldPatch.default_dashboard).not.toBeNull();
    expect(patchResult.data.organizationFieldPatch.default_dashboard.id).toEqual(dashboardUpdatedId);
    expect(patchResult.data.organizationFieldPatch.default_dashboard.name).toEqual('orga-dashboard-updated');

    // Verify user cache was refreshed: USER_EDITOR should now see the updated dashboard
    const userResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_DEFAULT_DASHBOARDS_QUERY,
    });
    expect(userResult.data.me).not.toBeNull();
    const dashboardIds = userResult.data.me.default_dashboards.map((d) => d.id);
    expect(dashboardIds).toContain(dashboardUpdatedId);
    expect(dashboardIds).not.toContain(dashboardId);
  });

  it('should remove default_dashboard from organization and refresh user cache', async () => {
    // Remove default_dashboard
    const patchResult = await queryAsAdmin({
      query: ORGANIZATION_FIELD_PATCH_QUERY,
      variables: {
        id: testOrganizationId,
        input: [{ key: 'default_dashboard', value: [null] }],
      },
    });
    expect(patchResult.data.organizationFieldPatch.default_dashboard).toBeNull();

    // Verify user cache was refreshed: USER_EDITOR should no longer have the dashboard
    const userResult = await queryAsUserWithSuccess(USER_EDITOR, {
      query: ME_DEFAULT_DASHBOARDS_QUERY,
    });
    expect(userResult.data.me).not.toBeNull();
    const dashboardIds = userResult.data.me.default_dashboards.map((d) => d.id);
    expect(dashboardIds).not.toContain(dashboardUpdatedId);
  });
});
