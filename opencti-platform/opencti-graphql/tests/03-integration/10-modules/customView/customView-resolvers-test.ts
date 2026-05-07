import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { createEntity } from '../../../../src/database/middleware';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsUserWithSuccess, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsAdminWithError } from '../../../utils/testQueryHelper';
import { CUSTOM_VIEW_ENTITY_1, CUSTOM_VIEW_ENTITY_2, CUSTOM_VIEW_ENTITY_INVALID, DASHBOARD_MANIFEST, DASHBOARD_MANIFEST_OBJECT } from './customView-fixtures';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../../../../src/modules/case/feedback/feedback-types';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import type { StoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import { fileToReadStream } from '../../../../src/database/file-storage';

const READ_CUSTOM_VIEW_QUERY = gql`
  query CustomViewTest($id: ID!) {
    customView(id: $id) {
      id
      manifest
      name
    }
  }
`;

const READ_SETTINGS_QUERY = gql`
  query CustomViewsSettingsTest($entityType: String!) {
    customViewsSettings(entityType: $entityType) {
      canEntityTypeHaveCustomViews
    }
  }
`;

const READ_ALL_CUSTOM_VIEWS_QUERY = gql`
  query CustomViewsTest($entityType: String) {
    customViews(
      entityType: $entityType
      orderBy: name
      orderMode: asc
    ) {
      edges {
        node {
          id
          name
          path
          description
          created_at
          updated_at
          targetEntityType
          enabled
          default
        }
      }
    }
  }
`;

const READ_DEFAULT_CUSTOM_VIEWS_QUERY = gql`
  query DefaultCustomViewsTest($entityType: String) {
    customViews(
      entityType: $entityType
      filters: {
        mode: and
        filters: [{
          key: ["default"]
          values: [true]
        }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const CREATE_CUSTOM_VIEW_QUERY = gql`
  mutation CreateCustomViewTest($input: CustomViewAddInput!) {
    customViewAdd(input: $input) {
      id
      name
      description
      path
      targetEntityType
      updated_at
      created_at
      enabled
      default
    }
  }
`;

const EDIT_CUSTOM_VIEW_QUERY = gql`
  mutation EditCustomViewTest($id: ID!, $input: [EditInput!]!) {
    customViewEdit(
      id: $id
      input: $input
    ) {
      id
      name
      description
      path
      manifest
      updated_at
      default
    }
  }
`;

const EXPORT_WIDGET_CUSTOM_VIEW_QUERY = gql`
  query ExportWidgetCustomViewTest($id: ID!, $widgetId: ID!) {
    customView(id: $id) {
      toWidgetExport(widgetId: $widgetId)
    }
  }
`;

const IMPORT_WIDGET_CUSTOM_VIEW_QUERY = gql`
  mutation ImportWidgetCustomViewTest(
    $id: ID!
    $input: CustomViewImportWidgetInput!
  ) {
    customViewWidgetConfigurationImport(id: $id, input: $input) {
      id
      manifest
    }
  }
`;

const DUPLICATE_CUSTOM_VIEW_QUERY = gql`
  mutation DuplicateCustomViewQuery(
    $input: CustomViewDuplicateInput!
  ) {
    customViewDuplicate(input: $input) {
      id
      name
      path
      description
      targetEntityType
      created_at
      updated_at
      enabled
      default
    }
  }
`;

const DELETE_CUSTOM_VIEW_QUERY = gql`
    mutation DeleteCustomViewQuery($id: ID!) {
        customViewDelete(id: $id)
    }
`;

const EXPORT_CUSTOM_VIEW_QUERY = gql`
  query ExportCustomViewQuery($id: ID!) {
    customView(id: $id) {
      toConfigurationExport
    }
  }
`;

const IMPORT_CUSTOM_VIEW_QUERY = gql`
  mutation ImportCustomViewQuery($targetEntityType: String!, $file: Upload!) {
    customViewConfigurationImport(targetEntityType: $targetEntityType, file: $file) {
      id
      name
      description
      enabled
      default
      path
      targetEntityType
    }
  }
`;

const createUploadFile = (filePath: string, fileName: string) => {
  const readStream = fileToReadStream(filePath, fileName, fileName, 'text/plain');
  const fileUpload = { ...readStream, encoding: 'utf8' };
  const upload = new Upload();
  upload.promise = new Promise((executor) => {
    executor(fileUpload);
  });
  upload.file = fileUpload;

  return upload;
};

describe('CustomView resolvers', () => {
  let customView1: StoreEntityCustomView | undefined;
  let customView2: StoreEntityCustomView | undefined;
  beforeAll(async () => {
    customView1 = await createEntity(
      testContext,
      ADMIN_USER,
      CUSTOM_VIEW_ENTITY_1,
      'CustomView',
    );
    customView2 = await createEntity(
      testContext,
      ADMIN_USER,
      CUSTOM_VIEW_ENTITY_2,
      'CustomView',
    );
    await createEntity(
      testContext,
      ADMIN_USER,
      CUSTOM_VIEW_ENTITY_INVALID,
      'CustomView',
    );
  });
  describe('display use cases', () => {
    it('should retrieve serialized dashboard manifest', async () => {
      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: READ_CUSTOM_VIEW_QUERY,
        variables: {
          id: customView1?.id,
        },
      });
      expect(result.data.customView.manifest).toBe(CUSTOM_VIEW_ENTITY_1.manifest);
    });

    it('should retrieve all custom views', async () => {
      const result = await queryAsAdminWithSuccess({
        query: READ_ALL_CUSTOM_VIEWS_QUERY,
      });
      const nodes = result.data.customViews.edges.map((e: any) => e.node);
      expect(nodes).toContainEqual({
        id: customView1?.id,
        name: CUSTOM_VIEW_ENTITY_1.name,
        description: CUSTOM_VIEW_ENTITY_1.description,
        path: `${CUSTOM_VIEW_ENTITY_1.slug}-${customView1?.id.replaceAll('-', '')}`,
        created_at: expect.any(Date),
        updated_at: expect.any(Date),
        targetEntityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
        enabled: true,
        default: true,
      });
      expect(nodes).toContainEqual({
        id: customView2?.id,
        name: CUSTOM_VIEW_ENTITY_2.name,
        description: CUSTOM_VIEW_ENTITY_2.description,
        path: `${CUSTOM_VIEW_ENTITY_2.slug}-${customView2?.id.replaceAll('-', '')}`,
        created_at: expect.any(Date),
        updated_at: expect.any(Date),
        targetEntityType: CUSTOM_VIEW_ENTITY_2.target_entity_type,
        enabled: false,
        default: false,
      });
      // Ordered by name ascending as defined by the query
      // Doesn't contain custom view not part of the whitelist
      expect(nodes.map(({ name }: { name: string }) => name)).toStrictEqual([
        CUSTOM_VIEW_ENTITY_2.name,
        CUSTOM_VIEW_ENTITY_1.name,
      ]);
    });

    it('should retrieve all custom views of given type', async () => {
      const result = await queryAsAdminWithSuccess({
        query: READ_ALL_CUSTOM_VIEWS_QUERY,
        variables: {
          entityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
        },
      });
      const targetEntityTypes = result.data.customViews.edges.map((e: any) => e.node)
        .map((n: any) => n.targetEntityType);
      expect(targetEntityTypes).toStrictEqual([CUSTOM_VIEW_ENTITY_1.target_entity_type]);
    });
  });

  describe('settings use cases', () => {
    describe('when user is admin', () => {
      it('should retrieve canEntityTypeHaveCustomViews=true for allowed entity type', async () => {
        const result = await queryAsAdminWithSuccess({
          query: READ_SETTINGS_QUERY,
          variables: {
            entityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
          },
        });
        expect(result.data.customViewsSettings.canEntityTypeHaveCustomViews).toBe(true);
      });

      it('should retrieve canEntityTypeHaveCustomViews=false for other entity type', async () => {
        const result = await queryAsAdminWithSuccess({
          query: READ_SETTINGS_QUERY,
          variables: {
            entityType: CUSTOM_VIEW_ENTITY_INVALID.target_entity_type,
          },
        });
        expect(result.data.customViewsSettings.canEntityTypeHaveCustomViews).toBe(false);
      });

      it('should allow creating a custom view', async () => {
        const description = 'Some great description';
        const manifest = DASHBOARD_MANIFEST;
        const name = 'Custom view name';
        const targetEntityType = 'Intrusion-Set';
        const result = await queryAsAdminWithSuccess({
          query: CREATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              description,
              manifest,
              name,
              targetEntityType,
            },
          },
        });
        expect(result.data.customViewAdd).toMatchObject({
          id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i),
          name,
          description,
          path: `custom-view-name-${result.data.customViewAdd.id.replaceAll('-', '')}`,
          targetEntityType,
          created_at: expect.any(Date),
          updated_at: expect.any(Date),
          // Defaults to false when not provided
          enabled: false,
          // Defaults to false when not provided
          default: false,
        });
      });

      it('should return a client error when trying to create a custom view for a non-supported entity type', async () => {
        const description = 'Some great description';
        const manifest = DASHBOARD_MANIFEST;
        const name = 'Custom view name';
        const targetEntityType = ENTITY_TYPE_CONTAINER_FEEDBACK;
        await queryAsAdminWithError({
          query: CREATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              description,
              manifest,
              name,
              targetEntityType,
            },
          },
        },
        'Custom views cannot be created for given entity type',
        'FUNCTIONAL_ERROR',
        );
      });

      it('should allow editing a custom view', async () => {
        const updatedDescription = 'Updated description';
        const updatedAtBefore = customView1?.updated_at;
        const updatedManifest = toB64({
          widgets: {},
          config: {
            relativeDate: 'months-3',
            startDate: null,
            endDate: null,
          },
        })!;
        const result = await queryAsAdminWithSuccess({
          query: EDIT_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView1?.id,
            input: [{
              key: 'description',
              value: [updatedDescription],
            }, {
              key: 'manifest',
              value: [updatedManifest],
            }],
          },
        });
        expect(result.data.customViewEdit.description).toBe(updatedDescription);
        expect(result.data.customViewEdit.manifest).toBe(updatedManifest);
        expect(result.data.customViewEdit.updated_at).not.toBe(updatedAtBefore);
        // TODO: Check activity logs using the audits query
      });

      it('should update the slug and thus the path when the name is edited', async () => {
        const updatedName = 'Updated name';
        const result = await queryAsAdminWithSuccess({
          query: EDIT_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView1?.id,
            input: [{
              key: 'name',
              value: [updatedName],
            }],
          },
        });
        expect(result.data.customViewEdit.name).toBe(updatedName);
        expect(result.data.customViewEdit.path).toBe(`updated-name-${customView1?.id.replaceAll('-', '')}`);
      });

      it('should allow exporting a widget', async () => {
        const widgetId = Object.keys(DASHBOARD_MANIFEST_OBJECT.widgets)[0];
        const result = await queryAsAdminWithSuccess({
          query: EXPORT_WIDGET_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView2?.id,
            widgetId,
          },
        });
        expect(result.data.customView.toWidgetExport).toBeDefined();
        expect(typeof result.data.customView.toWidgetExport).toBe('string');
        const parsedWidget = JSON.parse(result.data.customView.toWidgetExport);
        expect(parsedWidget.openCTI_version).toBeDefined();
        expect(parsedWidget.configuration).toBeDefined();
        expect(parsedWidget.type).toBe('widget');
      });

      it('should allow importing a widget', async () => {
        const file = createUploadFile(
          './tests/03-integration/10-modules/customView/data/',
          'custom-view-widget.json',
        );
        const manifestBefore = customView2?.manifest;
        const result = await queryAsAdminWithSuccess({
          query: IMPORT_WIDGET_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView2?.id,
            input: {
              file,
              manifest: customView2?.manifest,
            },
          },
        });
        expect(fromB64(result.data?.customViewWidgetConfigurationImport?.manifest)).toBeDefined();
        expect(fromB64(result.data?.customViewWidgetConfigurationImport?.manifest)).not.toBe(manifestBefore);
      });

      it('should duplicate a custom view', async () => {
        const duplicateName = 'Duplicated custom view 2';
        const result = await queryAsAdminWithSuccess({
          query: DUPLICATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              name: duplicateName,
              description: customView2?.description,
              manifest: customView2?.manifest,
              targetEntityType: customView2?.target_entity_type,
            },
          },
        });
        const expectedResult = {
          id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i),
          name: duplicateName,
          description: customView2?.description,
          path: `duplicated-custom-view-2-${result.data.customViewDuplicate.id.replaceAll('-', '')}`,
          targetEntityType: customView2?.target_entity_type,
          created_at: expect.any(Date),
          updated_at: expect.any(Date),
          // Defaults to false when not provided
          enabled: false,
          // Defaults to false when not provided
          default: false,
        };
        expect(result.data.customViewDuplicate).toMatchObject(expectedResult);
        expect(result.data.customViewDuplicate.id).not.toBe(customView2?.id);

        // Find new custom view in list query
        const listResult = await queryAsAdminWithSuccess({
          query: READ_ALL_CUSTOM_VIEWS_QUERY,
        });
        const nodes = listResult.data.customViews.edges.map((e: any) => e.node);
        expect(nodes).toContainEqual(expectedResult);
      });

      it('should delete a custom view', async () => {
        const result = await queryAsAdminWithSuccess({
          query: DELETE_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView2?.id,
          },
        });
        expect(result.data.customViewDelete).toBe(customView2?.id);

        // Not returned in list query
        const listResult = await queryAsAdminWithSuccess({
          query: READ_ALL_CUSTOM_VIEWS_QUERY,
          variables: {
            entityType: result.data.targetEntityType,
          },
        });
        const nodeIds = listResult.data.customViews.edges.map((e: any) => e.node).map((node: any) => node.id);
        expect(nodeIds).not.toContain(customView2?.id);
      });

      it('should guarantee unique default custom view', async () => {
        // 1. Guarantee unique default custom view upon creation
        let result = await queryAsAdminWithSuccess({
          query: CREATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              name: 'The new default',
              targetEntityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
              default: true,
            },
          },
        });
        const firstElementId = result.data.customViewAdd.id;
        expect(result.data.customViewAdd.default).toBe(true);

        let listResult = await queryAsAdminWithSuccess({
          query: READ_DEFAULT_CUSTOM_VIEWS_QUERY,
          variables: {
            entityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
          },
        });
        let nodes = listResult.data.customViews.edges.map((e: any) => e.node);
        expect(nodes.length).toBe(1);
        expect(nodes[0].id).toBe(result.data.customViewAdd.id);

        // 2. Guarantee unique default custom view upon duplication
        result = await queryAsAdminWithSuccess({
          query: DUPLICATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              name: 'The newer default',
              targetEntityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
              default: true,
            },
          },
        });
        expect(result.data.customViewDuplicate.default).toBe(true);

        listResult = await queryAsAdminWithSuccess({
          query: READ_DEFAULT_CUSTOM_VIEWS_QUERY,
          variables: {
            entityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
          },
        });
        nodes = listResult.data.customViews.edges.map((e: any) => e.node);
        expect(nodes.length).toBe(1);
        expect(nodes[0].id).toBe(result.data.customViewDuplicate.id);

        result = await queryAsAdminWithSuccess({
          query: EDIT_CUSTOM_VIEW_QUERY,
          variables: {
            id: firstElementId,
            input: [{
              key: 'default',
              value: [true],
            }],
          },
        });
        expect(result.data.customViewEdit.default).toBe(true);

        listResult = await queryAsAdminWithSuccess({
          query: READ_DEFAULT_CUSTOM_VIEWS_QUERY,
          variables: {
            entityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
          },
        });
        nodes = listResult.data.customViews.edges.map((e: any) => e.node);
        expect(nodes.length).toBe(1);
        expect(nodes[0].id).toBe(firstElementId);
      });

      it('should export a custom view', async () => {
        const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
          query: READ_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView1?.id,
          },
        });
        const exportResult = await queryAsAdminWithSuccess({
          query: EXPORT_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView1?.id,
          },
        });
        expect(typeof exportResult.data.customView.toConfigurationExport).toBe('string');
        const parsedExport = JSON.parse(exportResult.data.customView.toConfigurationExport);
        expect(parsedExport).toMatchObject({
          type: 'custom-view',
          openCTI_version: expect.stringMatching(/[0-9]{1}\.[0-9]{6}\.[0-9]{1}/),
          configuration: {
            name: result.data.customView.name,
            manifest: result.data.customView.manifest,
          },
        });
      });

      it('should import a custom view', async () => {
        const file = createUploadFile(
          './tests/03-integration/10-modules/customView/data/',
          'custom-view.json',
        );
        const result = await queryAsAdminWithSuccess({
          query: IMPORT_CUSTOM_VIEW_QUERY,
          variables: {
            targetEntityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
            file,
          },
        });
        expect(result.data.customViewConfigurationImport).toMatchObject({
          id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i),
          name: 'A view to import',
          enabled: false,
          default: false,
          path: `a-view-to-import-${result.data.customViewConfigurationImport.id.replaceAll('-', '')}`,
          targetEntityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
        });
      });
    });

    describe('when user is a simple participant', () => {
      it('should fail retrieving custom view settings with ForbiddenAccess 403 error', async () => {
        await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
          query: READ_SETTINGS_QUERY,
          variables: {
            entityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
          },
        });
      });

      it('should fail creating a custom view with ForbiddenAccess 403 error', async () => {
        await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
          query: CREATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              description: 'Some great description',
              manifest: DASHBOARD_MANIFEST,
              name: 'Custom view name',
              targetEntityType: ENTITY_TYPE_INTRUSION_SET,
            },
          },
        });
      });

      it('should fail trying to edit a custom view', async () => {
        const updatedDescription = 'Updated description';
        await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
          query: EDIT_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView1?.id,
            input: [{
              key: 'description',
              value: [updatedDescription],
            }],
          },
        });
      });

      it('should fail trying to delete a custom view', async () => {
        await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
          query: DELETE_CUSTOM_VIEW_QUERY,
          variables: {
            id: customView1?.id,
          },
        });
      });

      it('should fail trying to duplicate a custom view', async () => {
        await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
          query: DUPLICATE_CUSTOM_VIEW_QUERY,
          variables: {
            input: {
              name: 'Never gonna be created',
              description: customView1?.description,
              manifest: customView1?.manifest,
              targetEntityType: customView1?.target_entity_type,
            },
          },
        });
      });
    });
  });
});
