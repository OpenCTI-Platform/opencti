import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { editorQuery, participantQuery, queryAsAdmin } from '../../utils/testQuery';
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

describe('PublicDashboard resolver', () => {
  let privateDashboardInternalId;
  const publicDashboardName = 'publicDashboard';

  beforeAll(async () => {
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
  });

  afterAll(async () => {
    // Delete private dashboard
    await queryAsAdmin({
      query: DELETE_PRIVATE_DASHBOARD_QUERY,
      variables: { id: privateDashboardInternalId },
    });
  });

  it('Empty dashboard should not be published', async () => {
    // Create the publicDashboard
    const PUBLICDASHBOARD_TO_CREATE = {
      input: {
        name: 'private dashboard',
        dashboard_id: privateDashboardInternalId,
      },
    };
    const emptyPublicDashboard = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PUBLICDASHBOARD_TO_CREATE,
    });

    expect(emptyPublicDashboard).not.toBeNull();
    expect(emptyPublicDashboard.errors.length).toEqual(1);
    expect(emptyPublicDashboard.errors.at(0).message).toEqual('Cannot published empty dashboard');
  });

  describe('Tests with manifest', () => {
    beforeAll(async () => {
      // Add manifest to Private dashboard as empty dashboard should not be published
      const parsedManifest = {
        widgets: {
          'ebb25410-7048-4de7-9288-704e962215f6': {
            id: 'ebb25410-7048-4de7-9288-704e962215f6',
            type: 'number',
            perspective: 'entities',
            dataSelection: [
              {
                label: 'area',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [

                  ],
                  filterGroups: [

                  ]
                },
                dynamicFrom: {
                  mode: 'and',
                  filters: [

                  ],
                  filterGroups: [

                  ]
                },
                dynamicTo: {
                  mode: 'and',
                  filters: [

                  ],
                  filterGroups: [

                  ]
                }
              }
            ],
            parameters: {
              title: 'area number'
            },
            layout: {
              w: 4,
              h: 2,
              x: 4,
              y: 0,
              i: 'ebb25410-7048-4de7-9288-704e962215f6',
              moved: false,
              static: false
            }
          }
        },
        config: {

        }
      };
      const manifest = toBase64(JSON.stringify(parsedManifest));
      await queryAsAdmin({
        query: UPDATE_PRIVATE_DASHBOARD_QUERY,
        variables: {
          id: privateDashboardInternalId,
          input: { key: 'manifest', value: manifest },
        },
      });
    });

    describe('PublicDashboard resolver standard behavior', () => {
      let publicDashboardInternalId;

      it('should publicDashboard created', async () => {
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

      it('should not update publicDashboard if invalidInput key', async () => {
        const updatedDescription = 'updated Description';
        const queryResult = await queryAsAdmin({
          query: UPDATE_QUERY,
          variables: {
            id: publicDashboardInternalId,
            input: { key: 'description', value: updatedDescription },
          },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('Only name and uri_key can be updated');
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

      it('User with EXPLORE_EXUPDATE_PUBLISH capability but no admin access right cannot update public dashboard', async () => {
        const queryResult = await editorQuery({
          query: UPDATE_QUERY,
          variables: {
            id: privateDashboardInternalId,
            input: { key: 'name', value: ['updated name'] },
          },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('Cant find element to update');
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
      });
    });

    describe('PublicDashboard specific behaviour', () => {
      it('User without EXPLORE_EXUPDATE_PUBLISH capability should not create private dashboards', async () => {
        // Create the publicDashboard
        const PUBLICDASHBOARD2_TO_CREATE = {
          input: {
            name: publicDashboardName,
            dashboard_id: privateDashboardInternalId,
          },
        };
        const publicDashboard = await participantQuery({
          query: CREATE_QUERY,
          variables: PUBLICDASHBOARD2_TO_CREATE,
        });

        expect(publicDashboard).not.toBeNull();
        expect(publicDashboard.errors.length).toEqual(1);
        expect(publicDashboard.errors.at(0).name).toEqual('FORBIDDEN_ACCESS');
      });
    });
  });
});
