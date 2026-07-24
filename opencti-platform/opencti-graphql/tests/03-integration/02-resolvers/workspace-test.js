import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { elLoadById } from '../../../src/database/engine';
import { MEMBER_ACCESS_ALL } from '../../../src/utils/access';
import { createUploadFromTestDataFile, queryAsUser, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { toB64, fromB64 } from '../../../src/utils/base64';
import { addSavedFilter, deleteSavedFilter } from '../../../src/modules/savedFilter/savedFilter-domain';

const LIST_QUERY = gql`
  query workspaces(
    $first: Int
    $after: ID
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $includeAuthorities: Boolean
    $search: String
  ) {
    workspaces(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      includeAuthorities: $includeAuthorities
      search: $search
    ) {
      edges {
        node {
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
    }
  }
`;

const READ_QUERY = gql`
  query workspace($id: String!) {
    workspace(id: $id) {
      id
      type
      name
    }
  }
`;

const CREATE_QUERY = gql`
  mutation WorkspaceAdd($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
      name
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation WorkspaceEdit($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

const DELETE_QUERY = gql`
  mutation workspaceDelete($id: ID!) {
    workspaceDelete(id: $id)
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

const EXPORT_WIDGET_QUERY = gql`
  query workspaceWidgetExport($id: String!, $widgetId: ID!) {
    workspace(id: $id) {
      toWidgetExport(widgetId: $widgetId)
    }
  }
`;

describe('Workspace resolver standard behavior', () => {
  let workspaceInternalId;
  const workspaceName = 'an investigation';
  it('should workspace created', async () => {
    // Create the workspace
    const WORKSPACE_TO_CREATE = {
      input: {
        type: 'investigation',
        name: workspaceName,
      },
    };
    const workspace = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE_TO_CREATE,
    });
    expect(workspace).not.toBeNull();
    expect(workspace.data.workspaceAdd).not.toBeNull();
    expect(workspace.data.workspaceAdd.name).toEqual(workspaceName);
    workspaceInternalId = workspace.data.workspaceAdd.id;
  });
  it('should workspace loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).not.toBeNull();
    expect(queryResult.data.workspace.id).toEqual(workspaceInternalId);
  });
  it('should list workspaces', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult.data.workspaces.edges.length).toEqual(1);
  });
  it('should update workspace', async () => {
    const updatedName = `${workspaceName} - updated`;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: workspaceInternalId,
        input: { key: 'name', value: updatedName },
      },
    });
    expect(queryResult.data.workspaceFieldPatch.name).toEqual(updatedName);
  });
  it('should context patch workspace', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation WorkspaceEdit($id: ID!, $input: EditContext!) {
        workspaceContextPatch(id: $id, input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: workspaceInternalId, input: { focusOn: 'name' } },
    });
    expect(queryResult.data.workspaceContextPatch.id).toEqual(
      workspaceInternalId,
    );
  });
  it('should context clean workspace', async () => {
    const CONTEXT_CLEAN_QUERY = gql`
      mutation WorkspaceEdit($id: ID!) {
        workspaceContextClean(id: $id) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_CLEAN_QUERY,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult.data.workspaceContextClean.id).toEqual(
      workspaceInternalId,
    );
  });

  it('can not investigate on an entity that does not exists', async () => {
    const nonExistingEntityId = 'non-existing-entity-id';

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation addEntityToInvestigation($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: nonExistingEntityId,
        },
      },
    });

    expect(queryResult.errors[0].message).toEqual('Invalid ids specified');
  });

  it('can not import workspace configuration, given invalid entity type JSON import', async () => {
    const upload = await createUploadFromTestDataFile('20233010_octi_dashboard_Custom Dash_invalid_type.json', 'invalid-type.json', 'application/json');
    const queryResult = await queryAsAdmin({
      query: gql`
        mutation importWorkspaceConfiguration($file: Upload!) {
          workspaceConfigurationImport(file: $file)
        }
      `,
      variables: {
        file: upload,
      },
    });
    expect(queryResult.errors[0].message).toEqual(
      'Invalid type. Please import OpenCTI dashboard-type only',
    );
  });

  it('can not import workspace configuration, given invalid dashboard version import', async () => {
    const upload = await createUploadFromTestDataFile('20233010_octi_dashboard_Custom Dash_invalid_5.11.0_version.json', 'invalid-type.json', 'application/json');
    const queryResult = await queryAsAdmin({
      query: gql`
        mutation importWorkspaceConfiguration($file: Upload!) {
          workspaceConfigurationImport(file: $file)
        }
      `,
      variables: {
        file: upload,
      },
    });

    expect(queryResult.errors[0].message).toEqual(
      'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.16',
    );
  });

  it('can import workspace configuration, given valid entity type JSON import', async () => {
    const upload = await createUploadFromTestDataFile('20233010_octi_dashboard_Custom Dash_valid.json', 'valid.json', 'application/json');
    const queryResult = await queryAsAdmin({
      query: gql`
        mutation importWorkspaceConfiguration($file: Upload!) {
          workspaceConfigurationImport(file: $file)
        }
      `,
      variables: {
        file: upload,
      },
    });

    expect(queryResult).not.toBeUndefined();
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: queryResult.data.workspaceConfigurationImport },
    });
  });

  it('can duplicate workspace', async () => {
    const manifestWithFiltersId = toB64({
      widgets: {
        'widget-1': {
          id: 'widget-1',
          type: 'vertical-bar',
          perspective: 'entities',
          dataSelection: [
            {
              filters_id: 'saved-filter-123',
              date_attribute: 'created_at',
              label: 'My widget',
            },
          ],
          parameters: { title: 'Test widget' },
        },
      },
      config: {},
    });

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation duplicateWorkspace($input: WorkspaceDuplicateInput!) {
          workspaceDuplicate(input: $input) {
            id
            entity_type
            name
            manifest
            authorizedMembers {
              access_right
            }
          }
        }
      `,
      variables: {
        input: {
          type: 'dashboard',
          name: 'Dashboard to duplicate',
          manifest: manifestWithFiltersId,
        },
      },
    });

    expect(queryResult.data.workspaceDuplicate.id).toBeDefined();
    expect(queryResult.data.workspaceDuplicate.name).toBe('Dashboard to duplicate');
    expect(queryResult.data.workspaceDuplicate.entity_type).toBe('Workspace');
    expect(queryResult.data.workspaceDuplicate.authorizedMembers.length).toBe(1);
    expect(queryResult.data.workspaceDuplicate.authorizedMembers[0].access_right).toBe('admin');

    // Verify filters_id is preserved in the duplicated manifest
    const duplicatedManifest = JSON.parse(
      Buffer.from(queryResult.data.workspaceDuplicate.manifest, 'base64').toString('utf-8'),
    );
    const widget = duplicatedManifest.widgets['widget-1'];
    expect(widget).toBeDefined();
    expect(widget.dataSelection[0].filters_id).toBe('saved-filter-123');

    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: queryResult.data.workspaceDuplicate.id },
    });
  });

  describe('Widget export', () => {
    let savedFilterId;
    let dynamicFromSavedFilterId;
    let exportTestWorkspaceId;
    const savedFilterContent = {
      mode: 'and',
      filters: [{ key: 'relationship_type', values: ['targets'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    const dynamicFromFilterContent = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Threat-Actor-Group'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    const existingDynamicToFilters = {
      mode: 'or',
      filters: [{ key: 'entity_type', values: ['Identity'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };

    beforeAll(async () => {
      const savedFilter = await addSavedFilter(testContext, ADMIN_USER, {
        name: 'export-test-filter',
        filters: JSON.stringify(savedFilterContent),
        scope: 'stix-core-relationship',
      });
      savedFilterId = savedFilter.id;
      const dynamicFromSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
        name: 'export-test-dynamic-from-filter',
        filters: JSON.stringify(dynamicFromFilterContent),
        scope: 'Stix-Core-Object',
      });
      dynamicFromSavedFilterId = dynamicFromSavedFilter.id;

      // Load malware entity for ID conversion test
      const malwareEntity = await elLoadById(
        testContext,
        ADMIN_USER,
        'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85',
      );
      const internalId = malwareEntity.internal_id;

      // Create a single dashboard with all widgets needed for export tests
      const manifest = toB64({
        widgets: {
          'widget-export-test': {
            id: 'widget-export-test',
            type: 'vertical-bar',
            perspective: 'relationships',
            dataSelection: [
              {
                filters_id: savedFilterId,
                filters: null,
                dynamicFrom_id: dynamicFromSavedFilterId,
                dynamicTo: existingDynamicToFilters,
                date_attribute: 'created_at',
                label: 'Widget with saved filters',
              },
            ],
            parameters: { title: 'Test export widget with saved filters' },
            layout: { w: 6, h: 4, x: 0, y: 0, i: 'widget-export-test', moved: false, static: false },
          },
          'widget-ids-test': {
            id: 'widget-ids-test',
            type: 'vertical-bar',
            perspective: 'relationships',
            dataSelection: [
              {
                filters: {
                  mode: 'and',
                  filters: [
                    { key: 'objects', values: [internalId], operator: 'eq', mode: 'or' },
                  ],
                  filterGroups: [],
                },
                dynamicFrom: {
                  mode: 'and',
                  filters: [
                    { key: 'regardingOf', values: [{ key: 'id', values: [internalId] }] },
                  ],
                  filterGroups: [],
                },
                date_attribute: 'created_at',
                label: 'Widget with internal id in filter',
              },
            ],
            parameters: { title: 'Test IDs conversion' },
            layout: { w: 6, h: 4, x: 6, y: 0, i: 'widget-ids-test', moved: false, static: false },
          },
        },
        config: {},
      });

      const workspace = await queryAsAdmin({
        query: CREATE_QUERY,
        variables: {
          input: {
            type: 'dashboard',
            name: 'Dashboard for widget export tests',
          },
        },
      });
      expect(workspace).not.toBeNull();
      expect(workspace.data.workspaceAdd).not.toBeNull();
      exportTestWorkspaceId = workspace.data.workspaceAdd.id;

      // Set the manifest separately since it's not part of WorkspaceAddInput
      const updateResult = await queryAsAdmin({
        query: UPDATE_QUERY,
        variables: {
          id: exportTestWorkspaceId,
          input: { key: 'manifest', value: manifest },
        },
      });
      expect(updateResult.data.workspaceFieldPatch).not.toBeNull();
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: DELETE_QUERY,
        variables: { id: exportTestWorkspaceId },
      });
      await deleteSavedFilter(testContext, ADMIN_USER, savedFilterId);
      await deleteSavedFilter(testContext, ADMIN_USER, dynamicFromSavedFilterId);
    });

    it('should resolve filters_id into inline filters when exporting a widget', async () => {
      const widgetId = 'widget-export-test';

      const exportResult = await queryAsAdmin({
        query: EXPORT_WIDGET_QUERY,
        variables: { id: exportTestWorkspaceId, widgetId },
      });

      expect(exportResult.data.workspace.toWidgetExport).toBeDefined();
      const exportedData = JSON.parse(exportResult.data.workspace.toWidgetExport);
      expect(exportedData.type).toBe('widget');

      const widgetConfig = fromB64(exportedData.configuration);
      const selection = widgetConfig.dataSelection[0];

      // filters_id should be cleared after export and filters should be filled with the saved filter content
      expect(selection.filters_id).toBeUndefined();
      expect(selection.filters).toEqual(savedFilterContent);

      // dynamicFrom_id should be cleared and dynamicFrom filled with saved filter content
      expect(selection.dynamicFrom_id).toBeUndefined();
      expect(selection.dynamicFrom).toEqual(dynamicFromFilterContent);

      // dynamicTo should be preserved as-is since dynamicTo_id is undefined
      expect(selection.dynamicTo_id).toBeUndefined();
      expect(selection.dynamicTo).toEqual(existingDynamicToFilters);
    });

    it('should convert internal IDs to standard STIX IDs in filters when exporting a widget', async () => {
      const malwareEntity = await elLoadById(
        testContext,
        ADMIN_USER,
        'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85',
      );
      const internalId = malwareEntity.internal_id;
      const standardId = malwareEntity.standard_id;
      // Verify the test is meaningful: internalId and standardId should differ
      expect(internalId).not.toBe(standardId);

      const widgetId = 'widget-ids-test';

      const exportResult = await queryAsAdmin({
        query: EXPORT_WIDGET_QUERY,
        variables: { id: exportTestWorkspaceId, widgetId },
      });

      expect(exportResult.data.workspace.toWidgetExport).toBeDefined();
      const exportedData = JSON.parse(exportResult.data.workspace.toWidgetExport);
      const widgetConfig = fromB64(exportedData.configuration);
      const selection = widgetConfig.dataSelection[0];

      // Internal ID should have been converted to standard STIX ID in filters
      expect(selection.filters).toEqual({
        mode: 'and',
        filters: [
          { key: 'objects', values: [standardId], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      });

      // Internal ID should have been converted to standard STIX ID in dynamicFrom
      expect(selection.dynamicFrom).toEqual({
        mode: 'and',
        filters: [
          { key: 'regardingOf', values: [{ key: 'id', values: [standardId] }] },
        ],
        filterGroups: [],
      });
    });
  });

  it('can import widget, given valid entity type JSON import', async () => {
    const workspaceWidgetName = 'workspaceImportWidget';
    const CREATE_WORKSPACE = {
      input: {
        type: 'dashboard',
        name: workspaceWidgetName,
      },
    };
    const workspaceWidget = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CREATE_WORKSPACE,
    });
    expect(workspaceWidget).not.toBeNull();
    expect(workspaceWidget.data.workspaceAdd).not.toBeNull();
    expect(workspaceWidget.data.workspaceAdd.name).toEqual(workspaceWidgetName);
    const workspaceId = workspaceWidget.data.workspaceAdd.id;
    const upload = await createUploadFromTestDataFile('20231123_octi_widget_list.json', 'valid.json', 'application/json');
    const emptyDashboardManifest = toB64({ widgets: {}, config: {} });

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation workspaceImportWidget($id: ID!, $input: ImportConfigurationInput!) {
          workspaceWidgetConfigurationImport(id: $id, input: $input) {
            id
            manifest
          }
        }
      `,
      variables: {
        id: workspaceId,
        input: {
          file: upload,
          dashboardManifest: emptyDashboardManifest,
          importType: 'widget',
        },
      },
    });
    expect(queryResult.data.workspaceWidgetConfigurationImport).not.toBeUndefined();
    expect(queryResult.data.workspaceWidgetConfigurationImport).not.toBeNull();
    const deleteWorkspace = await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspaceId },
    });
    expect(deleteWorkspace.data.workspaceDelete).toEqual(workspaceId);
    expect(deleteWorkspace).not.toBeNull();
  });

  it('can not import widget, given invalid widget type import', async () => {
    const upload = await createUploadFromTestDataFile('20231123_invalid_type_octi_widget_list.json', 'invalid-type.json', 'application/json');
    const emptyDashboardManifest = toB64({ widgets: {}, config: {} });

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation workspaceImportWidget($id: ID!, $input: ImportConfigurationInput!) {
          workspaceWidgetConfigurationImport(id: $id, input: $input) {
            manifest
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          file: upload,
          dashboardManifest: emptyDashboardManifest,
          importType: 'widget',
        },
      },
    });

    expect(queryResult.errors[0].message).toEqual(
      'Invalid type. Please import OpenCTI widget-type only',
    );
  });

  it('can not import widget, given invalid widget version import', async () => {
    const upload = await createUploadFromTestDataFile('20231123_invalid_version_octi_widget_list.json', 'invalid-version.json', 'application/json', 'utf8');
    const emptyDashboardManifest = toB64({ widgets: {}, config: {} });

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation workspaceImportWidget($id: ID!, $input: ImportConfigurationInput!) {
          workspaceWidgetConfigurationImport(id: $id, input: $input) {
            manifest
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          file: upload,
          dashboardManifest: emptyDashboardManifest,
          importType: 'widget',
        },
      },
    });

    expect(queryResult.errors[0].message).toEqual(
      'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.16',
    );
  });

  it('can not investigate on an internal object', async () => {
    const queryResult = await queryAsAdmin({
      query: gql`
        mutation investigateOnCity($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: workspaceInternalId,
        },
      },
    });

    expect(queryResult.errors[0].message).toEqual('Invalid ids specified');
  });

  it('can investigate on an entity', async () => {
    const anEntity = await elLoadById(
      testContext,
      ADMIN_USER,
      'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85',
    );
    const anEntityId = anEntity.internal_id;

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation investigateOnALocation($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            id
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: anEntityId,
        },
      },
    });

    expect(
      queryResult.data.workspaceFieldPatch.investigated_entities_ids[0],
    ).toEqual(anEntityId);
  });

  it('can not investigate twice on the same entity', async () => {
    const anEntity = await elLoadById(
      testContext,
      ADMIN_USER,
      'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85',
    );
    const anEntityId = anEntity.internal_id;

    const queryResult = await queryAsAdmin({
      query: gql`
        mutation addEntityToInvestigation($id: ID!, $input: [EditInput!]!) {
          workspaceFieldPatch(id: $id, input: $input) {
            id
            investigated_entities_ids
          }
        }
      `,
      variables: {
        id: workspaceInternalId,
        input: {
          key: 'investigated_entities_ids',
          operation: 'add',
          value: anEntityId,
        },
      },
    });

    expect(
      queryResult.data.workspaceFieldPatch.investigated_entities_ids,
    ).toHaveLength(1);
  });

  it('can retrieve the investigated entity object', async () => {
    const anEntity = await elLoadById(
      testContext,
      ADMIN_USER,
      'malware--8a4b5aef-e4a7-524c-92f9-a61c08d1cd85',
    );
    const anEntityId = anEntity.internal_id;

    const WORKSPACE_STIX_DOMAIN_ENTITIES = gql`
      query workspace($id: String!) {
        workspace(id: $id) {
          id
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: WORKSPACE_STIX_DOMAIN_ENTITIES,
      variables: { id: workspaceInternalId },
    });

    expect(queryResult.data.workspace.objects.edges[0].node.id).toEqual(
      anEntityId,
    );
  });

  it('exports the investigation as a report along with the investigated entity', async () => {
    const queryResult = await queryAsAdmin({
      query: gql`
        query exportInvestigation($id: String!) {
          workspace(id: $id) {
            id
            toStixReportBundle
          }
        }
      `,
      variables: { id: workspaceInternalId },
    });

    const exportedInvestigationObjects = JSON.parse(
      queryResult.data.workspace.toStixReportBundle,
    ).objects;
    const exportedInvestigationObjectsTypes = exportedInvestigationObjects.map(
      (object) => object.type,
    );

    expect(exportedInvestigationObjectsTypes).toHaveLength(2);
    expect(exportedInvestigationObjectsTypes).toContain('report');
    expect(exportedInvestigationObjectsTypes).toContain('malware');
  });

  it('should workspace stix objects or stix relationships accurate', async () => {
    const WORKSPACE_STIX_DOMAIN_ENTITIES = gql`
      query workspace($id: String!) {
        workspace(id: $id) {
          id
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
                  standard_id
                }
                ... on BasicRelationship {
                  id
                  standard_id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: WORKSPACE_STIX_DOMAIN_ENTITIES,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).not.toBeNull();
    expect(queryResult.data.workspace.objects.edges.length).toEqual(1);
  });
  it('should add knowledge from investigation to container', async () => {
    const userEditorId = await getUserIdByEmail(USER_EDITOR.email);

    // Create wanted entities
    const SECTOR_TO_CREATE = {
      input: {
        name: 'Video games',
      },
    };
    const CREATE_SECTOR_QUERY = gql`
      mutation SectorAdd($input: SectorAddInput!) {
        sectorAdd(input: $input) {
          id
          name
        }
      }
    `;
    const sector = await queryAsUser(USER_EDITOR, {
      query: CREATE_SECTOR_QUERY,
      variables: SECTOR_TO_CREATE,
    });
    const sectorId = sector.data.sectorAdd.id;

    const INDIVIDUAL_TO_CREATE = {
      input: {
        name: 'tester',
      },
    };
    const CREATE_INDIVIDUAL_QUERY = gql`
      mutation IndividualAdd($input: IndividualAddInput!) {
        individualAdd(input: $input) {
          id
          name
        }
      }
    `;
    const individual = await queryAsUser(USER_EDITOR, {
      query: CREATE_INDIVIDUAL_QUERY,
      variables: INDIVIDUAL_TO_CREATE,
    });

    const individualId = individual.data.individualAdd.id;

    // Create the workspace
    const WORKSPACE_WITH_WANTED_ENTITIES_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace',
        investigated_entities_ids: [sectorId, individualId],
        authorized_members: [
          {
            id: userEditorId,
            access_right: 'admin',
          },
        ],
      },
    };

    const workspace = await queryAsUser(USER_EDITOR, {
      query: CREATE_QUERY,
      variables: WORKSPACE_WITH_WANTED_ENTITIES_TO_CREATE,
    });

    const CREATE_REPORT_QUERY = gql`
      mutation ReportAdd($input: ReportAddInput!) {
        reportAdd(input: $input) {
          id
          standard_id
          name
          description
          published
        }
      }
    `;
    // Create the report
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report for investigation transformation',
        published: '2020-02-26T00:51:35.000Z',
      },
    };
    const report = await queryAsAdmin({
      query: CREATE_REPORT_QUERY,
      variables: REPORT_TO_CREATE,
    });
    const reportId = report.data.reportAdd.id;

    const workspaceId = workspace.data.workspaceAdd.id;
    const graphQLResponse = await queryAsAdmin({
      query: gql`
        mutation KnowledgeAddFromInvestigation($id: ID!, $workspaceId: ID!) {
          containerEdit(id: $id) {
            knowledgeAddFromInvestigation(workspaceId: $workspaceId) {
              id
              numberOfConnectedElement
            }
          }
        }
      `,
      variables: {
        id: reportId,
        workspaceId,
      },
    });
    expect(
      graphQLResponse.data.containerEdit.knowledgeAddFromInvestigation.id,
    ).toBeDefined();
    expect(
      graphQLResponse.data.containerEdit.knowledgeAddFromInvestigation.numberOfConnectedElement,
    ).toBe(2);

    // Delete entities
    await queryAsAdmin({
      query: gql`
        mutation sectorDelete($id: ID!) {
          sectorEdit(id: $id) {
            delete
          }
        }
      `,
      variables: { id: sectorId },
    });
    await queryAsAdmin({
      query: gql`
        mutation individualDelete($id: ID!) {
          individualEdit(id: $id) {
            delete
          }
        }
      `,
      variables: { id: individualId },
    });

    // Delete the report
    await queryAsAdmin({
      query: gql`
        mutation reportDelete($id: ID!) {
          reportEdit(id: $id) {
            delete
          }
        }
      `,
      variables: { id: reportId },
    });
    // Delete the workspace
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspaceId },
    });
  });

  it('should workspace deleted', async () => {
    // Delete the workspace
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspaceInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: workspaceInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).toBeNull();
  });
});

describe('Workspace member access behavior', () => {
  let workspace1InternalId;
  let workspace2InternalId;
  let workspace3InternalId;
  let workspace4InternalId;
  let userEditorId;
  it('should 4 workspaces created', async () => {
    userEditorId = await getUserIdByEmail(USER_EDITOR.email);
    // Create the workspace
    const WORKSPACE1_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace1',
        authorized_members: [
          {
            id: userEditorId,
            access_right: 'admin',
          },
        ],
      },
    };
    const WORKSPACE2_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace2',
        authorized_members: [
          {
            id: userEditorId,
            access_right: 'edit',
          },
        ],
      },
    };
    const WORKSPACE3_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace3',
        authorized_members: [
          {
            id: userEditorId,
            access_right: 'view',
          },
        ],
      },
    };
    const WORKSPACE4_TO_CREATE = {
      input: {
        type: 'dashboard',
        name: 'workspace4',
        authorized_members: [
          {
            id: ADMIN_USER.id, // or any other user_id
            access_right: 'admin',
          },
        ],
      },
    };
    const workspace1 = await queryAsUser(USER_EDITOR, {
      query: CREATE_QUERY,
      variables: WORKSPACE1_TO_CREATE,
    });
    expect(workspace1.data.workspaceAdd).not.toBeNull();
    expect(workspace1.data.workspaceAdd.name).toEqual('workspace1');
    workspace1InternalId = workspace1.data.workspaceAdd.id;

    const workspace2 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE2_TO_CREATE,
    });
    expect(workspace2.data.workspaceAdd).not.toBeNull();
    expect(workspace2.data.workspaceAdd.name).toEqual('workspace2');
    workspace2InternalId = workspace2.data.workspaceAdd.id;

    const workspace3 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE3_TO_CREATE,
    });
    expect(workspace3.data.workspaceAdd).not.toBeNull();
    expect(workspace3.data.workspaceAdd.name).toEqual('workspace3');
    workspace3InternalId = workspace3.data.workspaceAdd.id;

    const workspace4 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: WORKSPACE4_TO_CREATE,
    });
    expect(workspace4.data.workspaceAdd).not.toBeNull();
    expect(workspace4.data.workspaceAdd.name).toEqual('workspace4');
    workspace4InternalId = workspace4.data.workspaceAdd.id;
  });

  it('Admin gets only his 3 created workspaces', async () => {
    const queryResultDefault = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResultDefault.data.workspaces.edges.length).toEqual(3);
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult.data.workspaces.edges.length).toEqual(3);
  });

  it('Admin gets all 4 workspaces when bypass', async () => {
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10, includeAuthorities: true },
    });
    expect(queryResult.data.workspaces.edges.length).toEqual(4);
  });

  it('User gets only the 3 shared workspaces', async () => {
    const queryResult = await queryAsUser(USER_EDITOR, {
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult.data.workspaces.edges.length).toEqual(3);
  });

  it('User with view access right cannot update workspace3', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: UPDATE_QUERY,
      variables: {
        id: workspace3InternalId,
        input: { key: 'name', value: ['custom dashboard3'] },
      },
    });
  });

  it('User with edit access right updates workspace2', async () => {
    const queryResult = await queryAsUser(USER_EDITOR, {
      query: UPDATE_QUERY,
      variables: {
        id: workspace2InternalId,
        input: { key: 'name', value: ['custom dashboard2'] },
      },
    });
    expect(queryResult.data.workspaceFieldPatch.name).toEqual(
      'custom dashboard2',
    );
  });

  it('User with admin access right should update workspace members', async () => {
    const authorizedMembersUpdate = [
      {
        id: userEditorId,
        access_right: 'admin',
      },
      {
        id: ADMIN_USER.id,
        access_right: 'admin',
      },
      {
        id: MEMBER_ACCESS_ALL,
        access_right: 'view',
      },
    ];
    const queryResult = await queryAsUser(USER_EDITOR, {
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace1InternalId, input: authorizedMembersUpdate },
    });
    expect(
      queryResult.data.workspaceEditAuthorizedMembers.authorizedMembers.length,
    ).toEqual(3);
  });

  it("A user can't modify authorized_members if the update leads to a workspace with no valid admin", async () => {
    const authorizedMembersUpdate = [
      {
        id: 'not_existing_id',
        access_right: 'admin',
      },
      {
        id: ADMIN_USER.id,
        access_right: 'edit',
      },
    ];
    const queryResult = await queryAsUser(USER_EDITOR, {
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace1InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).extensions.code).toEqual('FUNCTIONAL_ERROR');
    expect(queryResult.errors.at(0).message).toEqual('It should have at least one valid member with admin access');
  });

  it('User with edit access right should not update workspace members', async () => {
    const authorizedMembersUpdate = [
      {
        id: userEditorId,
        access_right: 'admin',
      },
      {
        id: ADMIN_USER.id,
        access_right: 'admin',
      },
    ];
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace2InternalId, input: authorizedMembersUpdate },
    });
  });

  it('User with admin access right deletes workspace1', async () => {
    // Delete the workspace
    const editorDeleteResult = await queryAsUser(USER_EDITOR, {
      query: DELETE_QUERY,
      variables: { id: workspace1InternalId },
    });
    expect(editorDeleteResult).not.toBeNull();
    expect(editorDeleteResult.data.workspaceDelete).toEqual(
      workspace1InternalId,
    );
    // Verify is no longer found
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: workspace1InternalId },
    }); // ce1bd336-6353-4ee8-96c9-4e723196dbf0
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspace).toBeNull();
  });

  it('Admin delete workspaces', async () => {
    // Delete the workspace
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspace2InternalId },
    });
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspace3InternalId },
    });
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: workspace4InternalId },
    });

    // Verify is no longer found
    const queryResult = await queryAsAdmin({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.workspaces.edges.length).toEqual(0);
  });
});
