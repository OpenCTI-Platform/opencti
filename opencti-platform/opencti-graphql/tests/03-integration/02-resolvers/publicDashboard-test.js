import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, editorQuery, getUserIdByEmail, participantQuery, queryAsAdmin, USER_EDITOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { PRIVATE_DASHBOARD_MANIFEST } from './publicDashboard-data';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../../../src/modules/publicDashboard/publicDashboard-types';
import { queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { toB64 } from '../../../src/utils/base64';

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
      enabled
      dashboard_id
      dashboard {
        id
      }
    }
  }
`;

const READ_QUERY_PRIVATE_DASHBOARD = gql`
  query workspace($id: String!) {
    workspace(id: $id) {
      id
      type
      name
      isShared
    }
  }
`;

const READ_URI_KEY_QUERY = gql`
  query PublicDashboardByUriKey($uri_key: String!) {
    publicDashboardByUriKey(uri_key: $uri_key) {
      id
      name
      uri_key
      enabled
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
      enabled
    }
  }
`;

const UPDATE_MEMBERS_QUERY = gql`
  mutation workspaceEditAuthorizedMembers(
    $id: ID!
    $input: [MemberAccessInput!]!
  ) {
    workspaceEditAuthorizedMembers(id: $id, input: $input) {
      id
      name
      authorizedMembers {
        id
        name
        entity_type
        access_right
      }
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

const MARKINGS_QUERY = gql`
  query markings {
    markingDefinitions {
      edges {
        node {
          id
          definition
        }
      }
    }
  }
`;

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

describe('PublicDashboard resolver', () => {
  let privateDashboardInternalId;
  const publicDashboardName = 'publicDashboard';

  let tlpClear;
  let tlpGreen;
  let tlpAmber;
  let tlpRed;

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

    // Fetch markings.
    const { data } = await queryAsAdmin({ query: MARKINGS_QUERY, variables: {} });
    const markings = data.markingDefinitions.edges.map((e) => e.node);
    tlpClear = markings.find((m) => m.definition === 'TLP:CLEAR');
    tlpGreen = markings.find((m) => m.definition === 'TLP:GREEN');
    tlpAmber = markings.find((m) => m.definition === 'TLP:AMBER');
    tlpRed = markings.find((m) => m.definition === 'TLP:RED');
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
        name: 'public dashboard',
        uri_key: 'public-dashboard',
        dashboard_id: privateDashboardInternalId,
        enabled: true,
      },
    };
    const emptyPublicDashboard = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PUBLICDASHBOARD_TO_CREATE,
    });

    expect(emptyPublicDashboard).not.toBeNull();
    expect(emptyPublicDashboard.errors.length).toEqual(1);
    expect(emptyPublicDashboard.errors.at(0).message).toEqual('Cannot publish an empty dashboard');
  });

  describe('Tests with manifest', () => {
    beforeAll(async () => {
      // Add manifest to Private dashboard as empty dashboard should not be published
      const manifest = toB64(PRIVATE_DASHBOARD_MANIFEST);
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
      let userEditorId;

      it('User without EXPLORE_EXUPDATE_PUBLISH capability should not create public dashboards', async () => {
        // Create the publicDashboard
        const PUBLICDASHBOARD2_TO_CREATE = {
          input: {
            name: publicDashboardName,
            uri_key: publicDashboardName,
            dashboard_id: privateDashboardInternalId,
            enabled: true,
          },
        };
        await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
          query: CREATE_QUERY,
          variables: PUBLICDASHBOARD2_TO_CREATE,
        });
      });

      it('User with EXPLORE_EXUPDATE_PUBLISH capability but private dashboard view access right cannot create public dashboard', async () => {
        // Add editor user in private dashboard authorizedMembers with view access right
        userEditorId = await getUserIdByEmail(USER_EDITOR.email);
        const authorizedMembersUpdate = [
          {
            id: ADMIN_USER.id,
            access_right: 'admin',
          },
          {
            id: userEditorId,
            access_right: 'view',
          },
        ];
        const authorizedMembersUpdateQuery = await queryAsAdmin({
          query: UPDATE_MEMBERS_QUERY,
          variables: { id: privateDashboardInternalId, input: authorizedMembersUpdate },
        });
        expect(authorizedMembersUpdateQuery.data.workspaceEditAuthorizedMembers.authorizedMembers.length).toEqual(2);

        // Create the publicDashboard
        const PUBLICDASHBOARD3_TO_CREATE = {
          input: {
            name: publicDashboardName,
            uri_key: publicDashboardName,
            dashboard_id: privateDashboardInternalId,
            enabled: true,
          },
        };
        const queryResult = await editorQuery({
          query: CREATE_QUERY,
          variables: PUBLICDASHBOARD3_TO_CREATE,
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('You are not allowed to do this.');
      });

      it('User cannot create public dashboard with marking not in User allowed markings', async () => {
        // Add security user in private dashboard authorizedMembers with admin access right
        const authorizedMembersUpdate = [
          {
            id: ADMIN_USER.id,
            access_right: 'admin',
          },
          {
            id: userEditorId,
            access_right: 'admin',
          },
        ];

        const authorizedMembersUpdateQuery = await queryAsAdmin({
          query: UPDATE_MEMBERS_QUERY,
          variables: { id: privateDashboardInternalId, input: authorizedMembersUpdate },
        });
        expect(authorizedMembersUpdateQuery.data.workspaceEditAuthorizedMembers.authorizedMembers.length).toEqual(2);

        // Try to create public dashboard
        const PUBLIC_DASHBOARD_TO_CREATE = {
          input: {
            name: 'public dashboard ',
            uri_key: 'public-dashboard-markings-red',
            dashboard_id: privateDashboardInternalId,
            allowed_markings_ids: [tlpRed.id],
            enabled: true,
          },
        };

        const publicDashboardQuery = await editorQuery({
          query: CREATE_QUERY,
          variables: PUBLIC_DASHBOARD_TO_CREATE,
        });
        expect(publicDashboardQuery).not.toBeNull();
        expect(publicDashboardQuery.errors.length).toEqual(1);
        expect(publicDashboardQuery.errors.at(0).message).toEqual('Not allowed markings');
      });

      it('User cannot create public dashboard with marking not in User shareable markings', async () => {
        // Try to create public dashboard
        const PUBLIC_DASHBOARD_TO_CREATE = {
          input: {
            name: 'public dashboard markings amber',
            uri_key: 'public-dashboard-markings-amber',
            dashboard_id: privateDashboardInternalId,
            allowed_markings_ids: [tlpAmber.id],
            enabled: true,
          },
        };

        const publicDashboardQuery = await editorQuery({
          query: CREATE_QUERY,
          variables: PUBLIC_DASHBOARD_TO_CREATE,
        });
        expect(publicDashboardQuery).not.toBeNull();
        expect(publicDashboardQuery.errors.length).toEqual(1);
        expect(publicDashboardQuery.errors.at(0).message).toEqual('You are not allowed to share these markings');
      });

      it('should publicDashboard created', async () => {
        // Create the publicDashboard
        const PUBLIC_DASHBOARD_TO_CREATE = {
          input: {
            name: publicDashboardName,
            uri_key: publicDashboardName,
            dashboard_id: privateDashboardInternalId,
            enabled: true,
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

        const queryResult2 = await queryAsAdmin({
          query: READ_QUERY_PRIVATE_DASHBOARD,
          variables: { id: privateDashboardInternalId },
        });
        expect(queryResult2.data.workspace.isShared).toEqual(true);
      });

      it('should publicDashboard loaded by internal id', async () => {
        const queryResult = await queryAsAdmin({
          query: READ_QUERY,
          variables: { id: publicDashboardInternalId },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.data.publicDashboard).not.toBeNull();
        expect(queryResult.data.publicDashboard.id).toEqual(publicDashboardInternalId);
        expect(queryResult.data.publicDashboard.dashboard_id).toEqual(queryResult.data.publicDashboard.dashboard.id);
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
        expect(queryResult.errors.at(0).message).toEqual('You cannot update incompatible attribute');
      });

      it('should not update publicDashboard if not allowed', async () => {
        const updatedName = `${publicDashboardName} - updated`;
        const queryResult = await participantQuery({
          query: UPDATE_QUERY,
          variables: {
            id: publicDashboardInternalId,
            input: { key: 'name', value: updatedName },
          },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('You are not allowed to do this.');
      });

      it('should not update publicDashboard if not allowed', async () => {
        const updatedName = `${publicDashboardName} - updated`;
        const queryResult = await participantQuery({
          query: UPDATE_QUERY,
          variables: {
            id: publicDashboardInternalId,
            input: { key: 'name', value: updatedName },
          },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('You are not allowed to do this.');
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

      it('should disabled/enabled publicDashboard', async () => {
        // Disabled public dashboard
        const disabledQueryResult = await queryAsAdmin({
          query: UPDATE_QUERY,
          variables: {
            id: publicDashboardInternalId,
            input: { key: 'enabled', value: false },
          },
        });
        expect(disabledQueryResult.data.publicDashboardFieldPatch.enabled).toEqual(false);

        // Enabled public dashboard
        const enabledQueryResult = await queryAsAdmin({
          query: UPDATE_QUERY,
          variables: {
            id: publicDashboardInternalId,
            input: { key: 'enabled', value: true },
          },
        });
        expect(enabledQueryResult.data.publicDashboardFieldPatch.enabled).toEqual(true);
      });

      describe('Tests widgets API', () => {
        let vadorId;
        let magnetoId;
        let octopusId;
        let franceId;
        let belgiqueId;

        afterAll(async () => {
          // region Delete areas.
          const DELETE_AREA = gql`
            mutation administrativeAreaDelete($id: ID!) {
              administrativeAreaDelete(id: $id)
            }
          `;
          await queryAsAdmin({
            query: DELETE_AREA,
            variables: { id: franceId },
          });
          await queryAsAdmin({
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
          await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: vadorId,
                toId: franceId
              }
            },
          });
          await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: magnetoId,
                toId: franceId
              }
            },
          });
          await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: magnetoId,
                toId: belgiqueId
              }
            },
          });
          await editorQuery({
            query: ADD_TARGETS_REL,
            variables: {
              input: {
                relationship_type: 'targets',
                fromId: octopusId,
                toId: belgiqueId
              }
            },
          });
          // endregion
        });

        it('should not return data if disabled publicDashboard', async () => {
          // Disabled public dashboard
          const disabledQueryResult = await queryAsAdmin({
            query: UPDATE_QUERY,
            variables: {
              id: publicDashboardInternalId,
              input: { key: 'enabled', value: false },
            },
          });
          resetCacheForEntity(ENTITY_TYPE_PUBLIC_DASHBOARD);
          expect(disabledQueryResult.data.publicDashboardFieldPatch.enabled).toEqual(false);

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
          expect(data.publicStixCoreObjectsNumber).toBeNull();

          // Enabled public dashboard
          const enabledQueryResult = await queryAsAdmin({
            query: UPDATE_QUERY,
            variables: {
              id: publicDashboardInternalId,
              input: { key: 'enabled', value: true },
            },
          });
          resetCacheForEntity(ENTITY_TYPE_PUBLIC_DASHBOARD);
          expect(enabledQueryResult.data.publicDashboardFieldPatch.enabled).toEqual(true);
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
          resetCacheForEntity(ENTITY_TYPE_PUBLIC_DASHBOARD);

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
          expect(attacksData[0].value).toEqual(4); // same result as for '6dbb6564-3e4a-4a28-85b1-e2ac479e38e7' widget
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
      });

      it('should not delete publicDashboard if not allowed', async () => {
        // Delete the publicDashboard
        const queryResult = await participantQuery({
          query: DELETE_QUERY,
          variables: { id: publicDashboardInternalId },
        });
        expect(queryResult).not.toBeNull();
        expect(queryResult.errors.length).toEqual(1);
        expect(queryResult.errors.at(0).message).toEqual('You are not allowed to do this.');
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

    describe('Tests widgets API with markings', () => {
      let greenPublicDashboardInternalId;
      let clearPublicDashboardInternalId;

      let spainId;
      let raditzId;
      let vegetaId;

      afterAll(async () => {
        // region Delete areas.
        const DELETE_AREA = gql`
          mutation administrativeAreaDelete($id: ID!) {
            administrativeAreaDelete(id: $id)
          }
        `;
        await queryAsAdmin({
          query: DELETE_AREA,
          variables: { id: spainId },
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
          variables: { id: raditzId },
        });
        await queryAsAdmin({
          query: DELETE_MALWARE,
          variables: { id: vegetaId },
        });
        // endregion
        // region Delete the publicDashboards.
        await queryAsAdmin({
          query: DELETE_QUERY,
          variables: { id: greenPublicDashboardInternalId },
        });
        await queryAsAdmin({
          query: DELETE_QUERY,
          variables: { id: clearPublicDashboardInternalId },
        });
        // endregion
      });

      beforeAll(async () => {
        // endregion
        // region Create the publicDashboards.
        const GREEN_PUBLIC_DASHBOARD_TO_CREATE = {
          input: {
            name: 'public dashboard marking green',
            uri_key: 'public-dashboard-marking-green',
            dashboard_id: privateDashboardInternalId,
            allowed_markings_ids: [tlpGreen.id],
            enabled: true,
          },
        };
        const greenPublicDashboard = await editorQuery({
          query: CREATE_QUERY,
          variables: GREEN_PUBLIC_DASHBOARD_TO_CREATE,
        });
        const CLEAR_PUBLIC_DASHBOARD_TO_CREATE = { // a dashboard with more a restricted marking
          input: {
            name: 'public dashboard marking clear',
            uri_key: 'public-dashboard-marking-clear',
            dashboard_id: privateDashboardInternalId,
            allowed_markings_ids: [tlpClear.id],
            enabled: true,
          },
        };
        const clearPublicDashboard = await editorQuery({
          query: CREATE_QUERY,
          variables: CLEAR_PUBLIC_DASHBOARD_TO_CREATE,
        });
        resetCacheForEntity(ENTITY_TYPE_PUBLIC_DASHBOARD);
        greenPublicDashboardInternalId = greenPublicDashboard.data.publicDashboardAdd.id;
        clearPublicDashboardInternalId = clearPublicDashboard.data.publicDashboardAdd.id;
        // endregion
        // region Create some areas.
        const CREATE_AREA = gql`
          mutation AdministrativeAreaAdd($input: AdministrativeAreaAddInput!) {
            administrativeAreaAdd(input: $input) { id }
          }
        `;
        const spain = await queryAsAdmin({
          query: CREATE_AREA,
          variables: {
            input: {
              name: 'spain',
              description: 'widget tests',
              objectMarking: [tlpGreen.id]
            }
          },
        });
        spainId = spain.data.administrativeAreaAdd.id;
        // endregion
        // region Create some malwares.
        const CREATE_MALWARES = gql`
          mutation MalwareAdd($input: MalwareAddInput!) {
            malwareAdd(input: $input) { id }
          }
        `;
        const raditz = await queryAsAdmin({
          query: CREATE_MALWARES,
          variables: {
            input: {
              name: 'raditz',
              malware_types: ['ddos'],
              description: 'widget tests',
              objectMarking: [tlpGreen.id]
            }
          },
        });
        raditzId = raditz.data.malwareAdd.id;
        const vegeta = await editorQuery({
          query: CREATE_MALWARES,
          variables: {
            input: {
              name: 'vegeta',
              malware_types: ['backdoor'],
              description: 'widget tests',
              objectMarking: [tlpGreen.id]
            }
          },
        });
        vegetaId = vegeta.data.malwareAdd.id;
        // endregion
        // region Create targets relationships between areas and malwares.
        const ADD_TARGETS_REL = gql`
          mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
            stixCoreRelationshipAdd(input: $input) { id }
          }
        `;
        await editorQuery({
          query: ADD_TARGETS_REL,
          variables: {
            input: {
              relationship_type: 'targets',
              fromId: raditzId,
              toId: spainId,
              objectMarking: [tlpGreen.id]
            }
          },
        });
        await editorQuery({
          query: ADD_TARGETS_REL,
          variables: {
            input: {
              relationship_type: 'targets',
              fromId: vegetaId,
              toId: spainId,
              objectMarking: [tlpGreen.id]
            }
          },
        });
        // endregion
      });

      it('should return the data for API: SCR Number', async () => {
        const aaa = await queryAsAdmin({
          query: API_SCR_NUMBER_QUERY,
          variables: {
            uriKey: 'public-dashboard-marking-green',
            widgetId: 'ecb25410-7048-4de7-9288-704e962215f6'
          },
        });
        const result = aaa.data.publicStixRelationshipsNumber;
        expect(result.total).toEqual(2);
        expect(result.count).toEqual(0);
      });

      it('should return the data for API: SCR Number with limited max marking', async () => {
        // Same query but with a dashboard with more restrictive markings (clear marking)
        const aaa = await queryAsAdmin({
          query: API_SCR_NUMBER_QUERY,
          variables: {
            uriKey: 'public-dashboard-marking-clear',
            widgetId: 'ecb25410-7048-4de7-9288-704e962215f6'
          },
        });
        const result = aaa.data.publicStixRelationshipsNumber;
        expect(result.total).toEqual(0);
        expect(result.count).toEqual(0);
      });
    });
  });
});
