import { beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { createEntity } from '../../../../src/database/middleware';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsUserWithSuccess, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsAdminWithError } from '../../../utils/testQueryHelper';
import { CUSTOM_VIEW_ENTITY_1, CUSTOM_VIEW_ENTITY_2, CUSTOM_VIEW_ENTITY_INVALID, DASHBOARD_MANIFEST } from './customView-fixtures';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../../../../src/modules/case/feedback/feedback-types';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';

const READ_CUSTOM_VIEW_FOR_DISPLAY_QUERY = gql`
  query CustomViewDisplayTest($id: ID!) {
    customViewDisplay(id: $id) {
      manifest
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
          description
          created_at
          updated_at
          targetEntityType
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
    }
  }
`;

describe('CustomView resolvers', () => {
  let customViewId1: string;
  let customViewId2: string;
  beforeAll(async () => {
    const result1 = await createEntity(
      testContext,
      ADMIN_USER,
      CUSTOM_VIEW_ENTITY_1,
      'CustomView',
    );
    customViewId1 = result1.id;
    const result2 = await createEntity(
      testContext,
      ADMIN_USER,
      CUSTOM_VIEW_ENTITY_2,
      'CustomView',
    );
    customViewId2 = result2.id;
    await createEntity(
      testContext,
      ADMIN_USER,
      CUSTOM_VIEW_ENTITY_INVALID,
      'CustomView',
    );
  });
  describe('display use cases', () => {
    describe('customViewDisplay', () => {
      it('should retrieve serialized dashboard manifest', async () => {
        const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
          query: READ_CUSTOM_VIEW_FOR_DISPLAY_QUERY,
          variables: {
            id: customViewId1,
          },
        });
        expect(result.data.customViewDisplay.manifest).toBe(CUSTOM_VIEW_ENTITY_1.manifest);
      });
    });

    describe('customViews', () => {
      it('should retrieve all custom views', async () => {
        const result = await queryAsAdminWithSuccess({
          query: READ_ALL_CUSTOM_VIEWS_QUERY,
        });
        const nodes = result.data.customViews.edges.map((e: any) => e.node);
        expect(nodes).toContainEqual({
          id: customViewId1,
          name: CUSTOM_VIEW_ENTITY_1.name,
          description: CUSTOM_VIEW_ENTITY_1.description,
          created_at: new Date(CUSTOM_VIEW_ENTITY_1.created_at),
          updated_at: new Date(CUSTOM_VIEW_ENTITY_1.updated_at),
          targetEntityType: CUSTOM_VIEW_ENTITY_1.target_entity_type,
        });
        expect(nodes).toContainEqual({
          id: customViewId2,
          name: CUSTOM_VIEW_ENTITY_2.name,
          description: CUSTOM_VIEW_ENTITY_2.description,
          created_at: new Date(CUSTOM_VIEW_ENTITY_2.created_at),
          updated_at: new Date(CUSTOM_VIEW_ENTITY_2.updated_at),
          targetEntityType: CUSTOM_VIEW_ENTITY_2.target_entity_type,
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
  });

  describe('settings use cases', () => {
    describe('customViewsSettings', () => {
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
      });
    });
  });
});
