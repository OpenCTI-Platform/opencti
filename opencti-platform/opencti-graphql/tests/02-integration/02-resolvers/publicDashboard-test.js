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
      uri_key
    }
  }
`;

const READ_URI_KEY_QUERY = gql`
  query PublicDashboardByUriKey($uri_key: String!) {
    publicDashboardByUriKey(uri_key: $uri_key) {
      id
      name
      uri_key
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
      uri_key
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
                label: 'malwares',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'entity_type',
                      values: ['Malware'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'description',
                      values: ['widget tests'],
                      operator: 'search',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                }
              }
            ],
            parameters: {
              title: 'malwares number'
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
          },
          'ecb25410-7048-4de7-9288-704e962215f6': {
            id: 'ecb25410-7048-4de7-9288-704e962215f6',
            type: 'number',
            perspective: 'relationships',
            dataSelection: [
              {
                label: 'malwares',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'relationships',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'toTypes',
                      values: ['Administrative-Area'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'relationship_type',
                      values: ['targets'],
                      operator: 'eq',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                }
              }
            ],
            parameters: {
              title: 'malwares attacking areas'
            },
            layout: {
              w: 4,
              h: 2,
              x: 4,
              y: 0,
              i: 'ecb25410-7048-4de7-9288-704e962215f6',
              moved: false,
              static: false
            }
          },
          '0a471055-7426-4840-9501-33770b845f92': {
            id: '0a471055-7426-4840-9501-33770b845f92',
            type: 'line',
            perspective: 'entities',
            dataSelection: [
              {
                label: 'areas',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['entity_type'],
                      values: ['Administrative-Area'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'description',
                      values: ['widget tests'],
                      operator: 'search',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                },
              },
              {
                label: 'malwares',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['entity_type'],
                      values: ['Malware'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'description',
                      values: ['widget tests'],
                      operator: 'search',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                },
              }
            ],
            parameters: {
              title: 'Evolution of malwares and areas'
            },
            layout: {
              w: 2,
              h: 4,
              x: 0,
              y: 0,
              i: '0a471055-7426-4840-9501-33770b845f92',
              moved: false,
              static: false
            }
          },
          '9e6afa7e-0db7-424c-8951-16b867245583': {
            id: '9e6afa7e-0db7-424c-8951-16b867245583',
            type: 'line',
            perspective: 'relationships',
            dataSelection: [
              {
                label: '',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'relationships',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['relationship_type'],
                      values: ['targets'],
                      operator: 'eq',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                }
              }
            ],
            parameters: {
              title: 'Evolution of attacks'
            },
            layout: {
              w: 3,
              h: 4,
              x: 2,
              y: 0,
              i: '9e6afa7e-0db7-424c-8951-16b867245583',
              moved: false,
              static: false
            }
          },
          '9865bec0-d8b1-4592-b14e-0e81e1645f59': {
            id: '9865bec0-d8b1-4592-b14e-0e81e1645f59',
            type: 'donut',
            perspective: 'entities',
            dataSelection: [
              {
                label: 'Area',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['entity_type'],
                      values: ['Administrative-Area'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'description',
                      values: ['widget tests'],
                      operator: 'search',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                }
              }
            ],
            parameters: {
              title: 'Donut entities'
            },
            layout: {
              w: 2,
              h: 4,
              x: 6,
              y: 0,
              i: '9865bec0-d8b1-4592-b14e-0e81e1645f59',
              moved: false,
              static: false
            }
          },
          '1865bec0-d8b1-4592-b14e-0e81e1645f59': {
            id: '1865bec0-d8b1-4592-b14e-0e81e1645f59',
            type: 'donut',
            perspective: 'entities',
            dataSelection: [
              {
                label: '',
                attribute: 'malware_types',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['entity_type'],
                      values: ['Malware'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'description',
                      values: ['widget tests'],
                      operator: 'search',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                },
              }
            ],
            parameters: {
              title: 'Malwares by type'
            },
            layout: {
              w: 2,
              h: 4,
              x: 6,
              y: 0,
              i: '1865bec0-d8b1-4592-b14e-0e81e1645f59',
              moved: false,
              static: false
            }
          },
          '2b3c637b-bf25-46ca-8b28-b891d349cc31': {
            id: '2b3c637b-bf25-46ca-8b28-b891d349cc31',
            type: 'donut',
            perspective: 'relationships',
            dataSelection: [
              {
                label: '',
                attribute: 'internal_id',
                date_attribute: 'created_at',
                perspective: 'relationships',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['relationship_type'],
                      values: ['targets'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: ['toTypes'],
                      values: ['Administrative-Area'],
                      operator: 'eq',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                },
              }
            ],
            parameters: {
              title: 'Donut relationships'
            },
            layout: {
              w: 2,
              h: 4,
              x: 8,
              y: 0,
              i: '2b3c637b-bf25-46ca-8b28-b891d349cc31',
              moved: false,
              static: false
            }
          },
          'bec879df-4da2-46c0-994a-e795c1b3a649': {
            id: 'bec879df-4da2-46c0-994a-e795c1b3a649',
            type: 'list',
            perspective: 'entities',
            dataSelection: [
              {
                label: '',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'entities',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['entity_type'],
                      values: ['Administrative-Area'],
                      operator: 'eq',
                      mode: 'or'
                    },
                    {
                      key: 'description',
                      values: ['widget tests'],
                      operator: 'search',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                },
              }
            ],
            parameters: {
              title: 'List entities'
            },
            layout: {
              w: 4,
              h: 2,
              x: 8,
              y: 4,
              i: 'bec879df-4da2-46c0-994a-e795c1b3a649',
              moved: false,
              static: false
            }
          },
          '6dbb6564-3e4a-4a28-85b1-e2ac479e38e7': {
            id: '6dbb6564-3e4a-4a28-85b1-e2ac479e38e7',
            type: 'list',
            perspective: 'relationships',
            dataSelection: [
              {
                label: '',
                attribute: 'entity_type',
                date_attribute: 'created_at',
                perspective: 'relationships',
                isTo: true,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: ['relationship_type'],
                      values: ['targets'],
                      operator: 'eq',
                      mode: 'or'
                    }
                  ],
                  filterGroups: []
                }
              }
            ],
            parameters: {
              title: 'List relationships'
            },
            layout: {
              w: 4,
              h: 2,
              x: 8,
              y: 6,
              i: '6dbb6564-3e4a-4a28-85b1-e2ac479e38e7',
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
      let publicDashboardUriKey;

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

      it('should publicDashboard created', async () => {
        // Create the publicDashboard
        const PUBLIC_DASHBOARD_TO_CREATE = {
          input: {
            name: publicDashboardName,
            dashboard_id: privateDashboardInternalId,
          },
        };
        const publicDashboard = await queryAsAdmin({
          query: CREATE_QUERY,
          variables: PUBLIC_DASHBOARD_TO_CREATE,
        });
        expect(publicDashboard.data.publicDashboardAdd).not.toBeNull();
        expect(publicDashboard.data.publicDashboardAdd.name).toEqual(publicDashboardName);
        publicDashboardInternalId = publicDashboard.data.publicDashboardAdd.id;
        publicDashboardUriKey = publicDashboard.data.publicDashboardAdd.uri_key;
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

      it('should fetch publicDashboard by uri key', async () => {
        const queryResult = await queryAsAdmin({
          query: READ_URI_KEY_QUERY,
          variables: { uri_key: publicDashboardUriKey },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.data.publicDashboardByUriKey).not.toBeNull();
        expect(queryResult.data.publicDashboardByUriKey.id).toEqual(publicDashboardInternalId);
        expect(queryResult.data.publicDashboardByUriKey.uri_key).toEqual(publicDashboardUriKey);
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

      it('User with EXPLORE_EXUPDATE_PUBLISH capability but view access right cannot update public dashboard', async () => {
        const queryResult = await editorQuery({
          query: UPDATE_QUERY,
          variables: {
            id: publicDashboardInternalId,
            input: { key: 'name', value: ['updated name'] },
          },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('You are not allowed to do this.');
      });

      describe('Tests widgets API', () => {
        let vadorId;
        let magnetoId;
        let octopusId;
        let franceId;
        let belgiqueId;
        let vadorFranceId;
        let magnetoFranceId;
        let magnetoBelgiqueId;
        let octopusBelgiqueId;

        afterAll(async () => {
          // region Delete areas.
          const DELETE_AREA = gql`
            mutation administrativeAreaDelete($id: ID!) {
              administrativeAreaDelete(id: $id)
            }
          `;
          await editorQuery({
            query: DELETE_AREA,
            variables: { id: franceId },
          });
          await editorQuery({
            query: DELETE_AREA,
            variables: { id: belgiqueId },
          });
          // endregion

          // region Delete malwares.
          const DELETE_MALWARE = gql`
            mutation malwareDelete($id: ID!) {
              malwareEdit(id: $id) {
                delete
              }
            }
          `;
          await queryAsAdmin({
            query: DELETE_MALWARE,
            variables: { id: vadorId },
          });
          await queryAsAdmin({
            query: DELETE_MALWARE,
            variables: { id: magnetoId },
          });
          await queryAsAdmin({
            query: DELETE_MALWARE,
            variables: { id: octopusId },
          });
          // endregion

          // region Delete relations between areas and malwares
          const DELETE_TARGETS_REL = gql`
            mutation StixCoreRelationshipDelete($id: ID!) {
              stixCoreRelationshipEdit(id: $id) {
                delete
              }
            }
          `;
          await queryAsAdmin({
            query: DELETE_TARGETS_REL,
            variables: { id: vadorFranceId },
          });
          await queryAsAdmin({
            query: DELETE_TARGETS_REL,
            variables: { id: magnetoFranceId },
          });
          await queryAsAdmin({
            query: DELETE_TARGETS_REL,
            variables: { id: magnetoBelgiqueId },
          });
          await queryAsAdmin({
            query: DELETE_TARGETS_REL,
            variables: { id: octopusBelgiqueId },
          });
          // endregion
        });

        beforeAll(async () => {
          // region Create some areas.
          const CREATE_AREA = gql`
            mutation AdministrativeAreaAdd($input: AdministrativeAreaAddInput!) {
              administrativeAreaAdd(input: $input) { id }
            }
          `;
          const france = await editorQuery({
            query: CREATE_AREA,
            variables: { input: { name: 'france', description: 'widget tests' } },
          });
          franceId = france.data.administrativeAreaAdd.id;
          const belgique = await editorQuery({
            query: CREATE_AREA,
            variables: { input: { name: 'belgique', description: 'widget tests' } },
          });
          belgiqueId = belgique.data.administrativeAreaAdd.id;
          // endregion

          // region Create some malwares.
          const CREATE_MALWARES = gql`
            mutation MalwareAdd($input: MalwareAddInput!) {
              malwareAdd(input: $input) { id }
            }
          `;
          const vador = await editorQuery({
            query: CREATE_MALWARES,
            variables: { input: { name: 'vador', malware_types: ['ddos'], description: 'widget tests' } },
          });
          vadorId = vador.data.malwareAdd.id;
          const magneto = await editorQuery({
            query: CREATE_MALWARES,
            variables: { input: { name: 'magneto', malware_types: ['backdoor'], description: 'widget tests' } },
          });
          magnetoId = magneto.data.malwareAdd.id;
          const octopus = await editorQuery({
            query: CREATE_MALWARES,
            variables: { input: { name: 'octopus', malware_types: ['rootkit'], description: 'widget tests' } },
          });
          octopusId = octopus.data.malwareAdd.id;
          // endregion

          // region Create targets relationships between areas and malwares
          const ADD_TARGETS_REL = gql`
            mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
              stixCoreRelationshipAdd(input: $input) { id }
            }
          `;
          const vadorFrance = await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: vadorId,
                toId: franceId
              }
            },
          });
          vadorFranceId = vadorFrance.data.stixCoreRelationshipAdd.id;
          const magnetoFrance = await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: magnetoId,
                toId: franceId
              }
            },
          });
          magnetoFranceId = magnetoFrance.data.stixCoreRelationshipAdd.id;
          const magnetoBelgique = await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: magnetoId,
                toId: belgiqueId
              }
            },
          });
          magnetoBelgiqueId = magnetoBelgique.data.stixCoreRelationshipAdd.id;
          const octopusBelgique = await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: octopusId,
                toId: belgiqueId
              }
            },
          });
          octopusBelgiqueId = octopusBelgique.data.stixCoreRelationshipAdd.id;
          // endregion
        });

        it('should return the data for API: SCO Number', async () => {
          const API_SCO_NUMBER_QUERY = gql`
            query PublicStixCoreObjectsNumber(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixCoreObjectsNumber(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                total
                count
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCO_NUMBER_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: 'ebb25410-7048-4de7-9288-704e962215f6'
            },
          });
          const { publicStixCoreObjectsNumber } = data;
          expect(publicStixCoreObjectsNumber.total).toEqual(3);
          expect(publicStixCoreObjectsNumber.count).toEqual(0);
        });

        it('should return the data for API: SCR Number', async () => {
          const API_SCR_NUMBER_QUERY = gql`
            query PublicStixRelationshipsNumber(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixRelationshipsNumber(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                total
                count
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCR_NUMBER_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: 'ecb25410-7048-4de7-9288-704e962215f6'
            },
          });
          const { publicStixRelationshipsNumber } = data;
          expect(publicStixRelationshipsNumber.total).toEqual(4);
          expect(publicStixRelationshipsNumber.count).toEqual(0);
        });

        it('should return the data for API: SCO Time series', async () => {
          const API_SCO_LIST_QUERY = gql`
            query PublicStixCoreObjectsMultiTimeSeries(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixCoreObjectsMultiTimeSeries(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                data {
                  date
                  value
                }
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCO_LIST_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: '0a471055-7426-4840-9501-33770b845f92'
            },
          });
          const { publicStixCoreObjectsMultiTimeSeries } = data;
          const areasData = publicStixCoreObjectsMultiTimeSeries[0].data;
          const malwaressData = publicStixCoreObjectsMultiTimeSeries[1].data;
          expect(areasData.length).toEqual(1);
          expect(areasData[0].value).toEqual(2);
          expect(malwaressData.length).toEqual(1);
          expect(malwaressData[0].value).toEqual(3);
        });

        it('should return the data for API: SCR Time series', async () => {
          const API_SCR_LIST_QUERY = gql`
            query PublicStixRelationshipsMultiTimeSeries(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixRelationshipsMultiTimeSeries(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                data {
                  date
                  value
                }
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCR_LIST_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: '9e6afa7e-0db7-424c-8951-16b867245583'
            },
          });
          const { publicStixRelationshipsMultiTimeSeries } = data;
          const attacksData = publicStixRelationshipsMultiTimeSeries[0].data;
          expect(attacksData.length).toEqual(1);
          expect(attacksData[0].value).toEqual(4);
        });

        it('should return the data for API: SCO Distribution', async () => {
          const API_SCO_DONUT_QUERY = gql`
            query PublicStixCoreObjectsDistribution(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixCoreObjectsDistribution(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                label
                entity {
                  __typename
                }
                value
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCO_DONUT_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: '9865bec0-d8b1-4592-b14e-0e81e1645f59'
            },
          });
          const { publicStixCoreObjectsDistribution } = data;
          expect(publicStixCoreObjectsDistribution[0].label).toEqual('Administrative-Area');
          expect(publicStixCoreObjectsDistribution[0].value).toEqual(2);

          const { data: dataMalwares } = await queryAsAdmin({
            query: API_SCO_DONUT_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: '1865bec0-d8b1-4592-b14e-0e81e1645f59'
            },
          });
          const malwaresDistribution = dataMalwares.publicStixCoreObjectsDistribution;
          expect(malwaresDistribution.length).toEqual(3);
          const backdoor = malwaresDistribution.find((m) => m.label === 'Backdoor');
          const ddos = malwaresDistribution.find((m) => m.label === 'Ddos');
          const rootkit = malwaresDistribution.find((m) => m.label === 'Rootkit');
          expect(backdoor).toBeDefined();
          expect(ddos).toBeDefined();
          expect(rootkit).toBeDefined();
          expect(backdoor.value).toEqual(1);
          expect(ddos.value).toEqual(1);
          expect(rootkit.value).toEqual(1);
        });

        it('should return the data for API: SCR Distribution', async () => {
          const API_SCR_DONUT_QUERY = gql`
            query PublicStixRelationshipsDistribution(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixRelationshipsDistribution(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                label
                entity {
                  __typename
                  ... on AdministrativeArea {
                    name
                  }
                }
                value
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCR_DONUT_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: '2b3c637b-bf25-46ca-8b28-b891d349cc31'
            },
          });
          const { publicStixRelationshipsDistribution } = data;
          const france = publicStixRelationshipsDistribution.find((d) => d.entity.name === 'france');
          const belgique = publicStixRelationshipsDistribution.find((d) => d.entity.name === 'belgique');
          expect(france).toBeDefined();
          expect(belgique).toBeDefined();
          expect(france.value).toEqual(2);
          expect(belgique.value).toEqual(2);
        });

        it('should return the data for API: SCO List', async () => {
          const API_SCO_LIST_QUERY = gql`
            query PublicStixCoreObjects(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixCoreObjects(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                edges {
                  node {
                    entity_type
                    ... on AdministrativeArea {
                      name
                    }
                  }
                }
                pageInfo {
                  globalCount
                }
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCO_LIST_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: 'bec879df-4da2-46c0-994a-e795c1b3a649'
            },
          });
          const { publicStixCoreObjects } = data;
          const entityTypes = new Set(publicStixCoreObjects.edges.map((e) => e.node.entity_type));
          expect(entityTypes.size).toEqual(1);
          expect(entityTypes.has('Administrative-Area')).toEqual(true);
          expect(publicStixCoreObjects.pageInfo.globalCount).toEqual(2);
          const france = publicStixCoreObjects.edges.find((e) => e.node.name === 'france');
          const belgique = publicStixCoreObjects.edges.find((e) => e.node.name === 'belgique');
          expect(france).toBeDefined();
          expect(belgique).toBeDefined();
        });

        it('should return the data for API: SCR List', async () => {
          const API_SCR_LIST_QUERY = gql`
            query PublicStixRelationships(
              $startDate: DateTime
              $endDate: DateTime
              $uriKey: String!
              $widgetId : String!
            ) {
              publicStixRelationships(
                startDate: $startDate
                endDate: $endDate
                uriKey: $uriKey
                widgetId : $widgetId
              ) {
                edges {
                  node {
                    relationship_type
                  }
                }
                pageInfo {
                  globalCount
                }
              }
            }
          `;
          const { data } = await queryAsAdmin({
            query: API_SCR_LIST_QUERY,
            variables: {
              uriKey: publicDashboardUriKey,
              widgetId: '6dbb6564-3e4a-4a28-85b1-e2ac479e38e7'
            },
          });
          const { publicStixRelationships } = data;
          expect(publicStixRelationships.edges[0].node.relationship_type).toEqual('targets');
          expect(publicStixRelationships.pageInfo.globalCount).toEqual(4);
        });

        // TODO add tests for other APIS
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
  });
});
