import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { editorQuery, queryAsAdmin } from '../../utils/testQuery';
import { toBase64 } from '../../../src/database/utils';

const LIST_QUERY = gql`
  query publicDashboards(
    $first: Int
    $after: ID
    $orderBy: PublicDashboardsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
      publicDashboards(
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
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query PublicDashboard($id: String!) {
    publicDashboard(id: $id) {
      id
      name
    }
  }
`;

const CREATE_PRIVATE_DASHBOARD_QUERY = gql`
    mutation WorkspaceAdd($input: WorkspaceAddInput!) {
        workspaceAdd(input: $input) {
            id
            name
        }
    }
`;

const CREATE_QUERY = gql`
  mutation PublicDashboardAdd($input: PublicDashboardAddInput!) {
    publicDashboardAdd(input: $input) {
      id
      name
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation PublicDashboardEdit($id: ID!, $input: [EditInput!]!) {
    publicDashboardFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

const UPDATE_PRIVATE_DASHBOARD_QUERY = gql`
  mutation WorkspaceEdit($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

const DELETE_QUERY = gql`
  mutation PublicDashboardDelete($id: ID!) {
    publicDashboardDelete(id: $id)
  }
`;

const DELETE_PRIVATE_DASHBOARD_QUERY = gql`
    mutation workspaceDelete($id: ID!) {
        workspaceDelete(id: $id)
    }
`;

describe('PublicDashboard resolver standard behavior', () => {
  let privateDashboardInternalId;
  let publicDashboardInternalId;
  const publicDashboardName = 'publicDashboard';
  it('should publicDashboard created', async () => {
    // Create Private dashboard
    const privateDashboard = await queryAsAdmin({
      query: CREATE_PRIVATE_DASHBOARD_QUERY,
      variables: {
        input: {
          type: 'dashboard',
          name: 'private dashboard',
        },
      },
    });
    privateDashboardInternalId = privateDashboard.data.workspaceAdd.id;

    // Add a widget to Private dashboard as empty dashboard should not be pubslished
    const emptyDashboardManifest = toBase64(JSON.stringify({ widgets: {}, config: {} }));
    await queryAsAdmin({
      query: UPDATE_PRIVATE_DASHBOARD_QUERY,
      variables: {
        id: privateDashboardInternalId,
        input: { key: 'manifest', value: emptyDashboardManifest },
      },
    });
    // Create the publicDashboard
    const PUBLICDASHBOARD_TO_CREATE = {
      input: {
        name: publicDashboardName,
        dashboard_id: privateDashboardInternalId,
      },
    };
    const publicDashboard = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PUBLICDASHBOARD_TO_CREATE,
    });

    expect(publicDashboard.data.publicDashboardAdd).not.toBeNull();
    expect(publicDashboard.data.publicDashboardAdd.name).toEqual(publicDashboardName);
    publicDashboardInternalId = publicDashboard.data.publicDashboardAdd.id;
  });
  it('should publicDashboard loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: publicDashboardInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.publicDashboard).not.toBeNull();
    expect(queryResult.data.publicDashboard.id).toEqual(publicDashboardInternalId);
  });
  it('should list publicDashboards', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult.data.publicDashboards.edges.length).toEqual(1);
  });
  it('should update publicDashboard', async () => {
    const updatedName = `${publicDashboardName} - updated`;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: publicDashboardInternalId,
        input: { key: 'name', value: updatedName },
      },
    });
    expect(queryResult.data.publicDashboardFieldPatch.name).toEqual(updatedName);
  });
  it('should delete publicDashboard', async () => {
    // Delete the publicDashboard
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: publicDashboardInternalId },
    });

    // Verify is no longer found
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.publicDashboards.edges.length).toEqual(0);

    // Delete private dashboard
    await queryAsAdmin({
      query: DELETE_PRIVATE_DASHBOARD_QUERY,
      variables: { id: privateDashboardInternalId },
    });
  });
});

describe('PublicDashboard features list', () => {
  let privateDashboard2InternalId;
  const publicDashboardName = 'publicDashboard2';
  it('User without capability should not create private dashboards', async () => {
    // Create Private dashboard
    const privateDashboard2 = await queryAsAdmin({
      query: CREATE_PRIVATE_DASHBOARD_QUERY,
      variables: {
        input: {
          type: 'dashboard',
          name: 'private dashboard 2',
        },
      },
    });
    privateDashboard2InternalId = privateDashboard2.data.workspaceAdd.id;

    // Add a widget to Private dashboard as empty dashboard should not be pubslished
    const emptyDashboardManifest = toBase64(JSON.stringify({ widgets: {}, config: {} }));
    await editorQuery({
      query: UPDATE_PRIVATE_DASHBOARD_QUERY,
      variables: {
        id: privateDashboard2InternalId,
        input: { key: 'manifest', value: emptyDashboardManifest },
      },
    });
    // Create the publicDashboard
    const PUBLICDASHBOARD2_TO_CREATE = {
      input: {
        name: publicDashboardName,
        dashboard_id: privateDashboard2InternalId,
      },
    };
    const publicDashboard = await editorQuery({
      query: CREATE_QUERY,
      variables: PUBLICDASHBOARD2_TO_CREATE,
    });

    expect(publicDashboard).not.toBeNull();
    expect(publicDashboard.errors.length).toEqual(1);
    expect(publicDashboard.errors.at(0).name).toEqual('FORBIDDEN_ACCESS');

    // Delete private dashboard
    await queryAsAdmin({
      query: DELETE_PRIVATE_DASHBOARD_QUERY,
      variables: { id: privateDashboard2InternalId },
    });
  });
  it('Admin should list private dashboards', async () => {});
  it('Admin should list all public dashboards URI keys', async () => {});
  it('Admin should delete a link for a public dashboard', async () => {});
  it('Admin should update a link for a public dashboard', async () => {});
  it('Marking definition update by an admin should impact public dashboard', async () => {});
});
