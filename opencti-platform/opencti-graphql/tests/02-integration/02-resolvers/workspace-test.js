import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import fs from 'node:fs';
import path from 'node:path';
import Upload from 'graphql-upload/Upload.mjs';
import { ADMIN_USER, editorQuery, getUserIdByEmail, queryAsAdmin, testContext, USER_EDITOR } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { MEMBER_ACCESS_ALL } from '../../../src/utils/access';
import { toBase64 } from '../../../src/database/utils';

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
    const file = fs.createReadStream(
      path.resolve(
        __dirname,
        '../../data/20233010_octi_dashboard_Custom Dash_invalid_type.json',
      ),
    );
    const upload = new Upload();
    const fileUpload = {
      fieldName: 'fieldName',
      filename: 'invalid-type.json',
      mimetype: 'application/json',
      createReadStream: () => file,
    };
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;

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
    const file = fs.createReadStream(
      path.resolve(
        __dirname,
        '../../data/20233010_octi_dashboard_Custom Dash_invalid_5.11.0_version.json',
      ),
    );
    const upload = new Upload();
    const fileUpload = {
      fieldName: 'fieldName',
      filename: 'invalid-version.json',
      mimetype: 'application/json',
      createReadStream: () => file,
    };
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;

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
      'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.0',
    );
  });

  it('can import workspace configuration, given valid entity type JSON import', async () => {
    const file = fs.createReadStream(
      path.resolve(
        __dirname,
        '../../data/20233010_octi_dashboard_Custom Dash_valid.json',
      ),
    );
    const upload = new Upload();
    const fileUpload = {
      fieldName: 'fieldName',
      filename: 'valid.json',
      mimetype: 'application/json',
      createReadStream: () => file,
    };
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;

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
    const queryResult = await queryAsAdmin({
      query: gql`
        mutation duplicateWorkspace($input: WorkspaceDuplicateInput!) {
          workspaceDuplicate(input: $input) {
            id
            entity_type
            name
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
        },
      },
    });

    expect(queryResult.data.workspaceDuplicate.id).toBeDefined();
    expect(queryResult.data.workspaceDuplicate.name).toBe(
      'Dashboard to duplicate',
    );
    expect(queryResult.data.workspaceDuplicate.entity_type).toBe('Workspace');
    expect(queryResult.data.workspaceDuplicate.authorizedMembers.length).toBe(
      1,
    );
    expect(
      queryResult.data.workspaceDuplicate.authorizedMembers[0].access_right,
    ).toBe('admin');
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: queryResult.data.workspaceDuplicate.id },
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
    const file = fs.createReadStream(path.resolve(__dirname, '../../data/20231123_octi_widget_list.json'));
    const upload = new Upload();
    const fileUpload = {
      fieldName: 'fieldName',
      filename: 'valid.json',
      mimetype: 'application/json',
      createReadStream: () => file,
    };
    upload.promise = new Promise((executor) => { executor(fileUpload); });
    upload.file = fileUpload;
    const emptyDashboardManifest = toBase64(JSON.stringify({ widgets: {}, config: {} }));

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
        }
      }
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
    const file = fs.createReadStream(path.resolve(__dirname, '../../data/20231123_invalid_type_octi_widget_list.json'));
    const upload = new Upload();
    const fileUpload = {
      fieldName: 'fieldName',
      filename: 'invalid-type.json',
      mimetype: 'application/json',
      createReadStream: () => file,
    };
    upload.promise = new Promise((executor) => { executor(fileUpload); });
    upload.file = fileUpload;
    const emptyDashboardManifest = toBase64(JSON.stringify({ widgets: {}, config: {} }));

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
        }
      }
    });

    expect(queryResult.errors[0].message).toEqual(
      'Invalid type. Please import OpenCTI widget-type only'
    );
  });

  it('can not import widget, given invalid widget version import', async () => {
    const file = fs.createReadStream(path.resolve(__dirname, '../../data/20231123_invalid_version_octi_widget_list.json'));
    const upload = new Upload();
    const fileUpload = {
      fieldName: 'fieldName',
      filename: 'invalid-version.json',
      mimetype: 'application/json',
      createReadStream: () => file,
    };
    upload.promise = new Promise((executor) => { executor(fileUpload); });
    upload.file = fileUpload;
    const emptyDashboardManifest = toBase64(JSON.stringify({ widgets: {}, config: {} }));

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
        }
      }
    });

    expect(queryResult.errors[0].message).toEqual(
      'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.0'
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
    const sector = await editorQuery({
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
    const individual = await editorQuery({
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

    const workspace = await editorQuery({
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
    const workspace1 = await editorQuery({
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
    const queryResult = await editorQuery({
      query: LIST_QUERY,
      variables: { first: 10 },
    });
    expect(queryResult.data.workspaces.edges.length).toEqual(3);
  });

  it('User with view access right cannot update workspace3', async () => {
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: {
        id: workspace3InternalId,
        input: { key: 'name', value: ['custom dashboard3'] },
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('FORBIDDEN_ACCESS');
  });

  it('User with edit access right updates workspace2', async () => {
    const queryResult = await editorQuery({
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
    const queryResult = await editorQuery({
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
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace1InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('FUNCTIONAL_ERROR');
    expect(queryResult.errors.at(0).message).toEqual(
      'Workspace should have at least one admin',
    );
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
    const queryResult = await editorQuery({
      query: UPDATE_MEMBERS_QUERY,
      variables: { id: workspace2InternalId, input: authorizedMembersUpdate },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).name).toEqual('FORBIDDEN_ACCESS');
  });

  it('User with admin access right deletes workspace1', async () => {
    // Delete the workspace
    const editorDeleteResult = await editorQuery({
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
