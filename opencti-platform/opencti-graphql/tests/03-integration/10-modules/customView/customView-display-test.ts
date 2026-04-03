import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { createEntity } from '../../../../src/database/middleware';
import { toB64 } from '../../../../src/utils/base64';
import { queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import type { BasicStoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import type { CustomViewsDisplayContext } from '../../../../src/generated/graphql';

const READ_CONTEXT_QUERY = gql`
  query CustomViewsDisplayContextTest {
    customViewsDisplayContext {
      entity_type
      custom_views_info {
        id
        name
        path
      }
    }
  }
`;

const READ_CUSTOM_VIEW_FOR_DISPLAY_QUERY = gql`
  query CustomViewDisplayTest($id: String!) {
    customViewDisplay(id: $id) {
      manifest
    }
  }
`;

const DASHBOARD_MANIFEST = toB64({
  widgets: {
    'a3f0a894-6f60-4661-8005-7d84f470ed5c': {
      id: 'a3f0a894-6f60-4661-8005-7d84f470ed5c',
      type: 'text',
      perspective: null,
      parameters: {
        title: 'Salut',
        content: 'Blahblah',
      },
      dataSelection: [
        {
          label: '',
          number: 10,
          sort_by: 'created_at',
          sort_mode: 'desc',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: null,
          isTo: true,
          filters: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
          dynamicTo: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
        },
      ],
      layout: {
        w: 5,
        h: 3,
        x: 0,
        y: 0,
        i: 'a3f0a894-6f60-4661-8005-7d84f470ed5c',
        moved: false,
        static: false,
      },
    },
    '67d4ccbb-2b9a-4855-a3d3-4f0eb67facbd': {
      id: '67d4ccbb-2b9a-4855-a3d3-4f0eb67facbd',
      type: 'list',
      perspective: 'entities',
      parameters: {
        title: 'yeahhh',
      },
      dataSelection: [
        {
          label: 'nope',
          number: 10,
          sort_by: 'created_at',
          sort_mode: 'desc',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: 'entities',
          isTo: true,
          filters: {
            mode: 'and',
            filters: [
              {
                key: [
                  'entity_type',
                ],
                operator: 'eq',
                values: [
                  'Intrusion-Set',
                ],
                mode: 'or',
              },
              {
                key: [
                  'creator_id',
                ],
                operator: 'eq',
                values: [
                  '@me',
                ],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
          dynamicTo: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
          columns: [
            {
              attribute: 'entity_type',
              label: 'Type',
            },
            {
              attribute: 'name',
              label: 'Name',
            },
            {
              attribute: 'created',
              label: 'Original creation date',
            },
            {
              attribute: 'created_at',
              label: 'Platform creation date',
            },
            {
              attribute: 'modified',
              label: 'Modification date',
            },
            {
              attribute: 'createdBy',
            },
            {
              attribute: 'creators',
              label: 'Creators',
            },
            {
              attribute: 'x_opencti_workflow_id',
            },
            {
              attribute: 'objectLabel',
            },
            {
              attribute: 'objectMarking',
            },
          ],
        },
      ],
      layout: {
        w: 8,
        h: 3,
        x: 4,
        y: 3,
        i: '67d4ccbb-2b9a-4855-a3d3-4f0eb67facbd',
        moved: false,
        static: false,
      },
    },
    '59a8fd33-bb90-4179-aaab-047aae9717a3': {
      id: '59a8fd33-bb90-4179-aaab-047aae9717a3',
      type: 'horizontal-bar',
      perspective: 'relationships',
      parameters: {
        title: 'bouh',
      },
      dataSelection: [
        {
          label: 'lool',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: 'entities',
          filters: {
            mode: 'and',
            filters: [
              {
                key: [
                  'entity_type',
                ],
                operator: 'eq',
                values: [
                  'Campaign',
                ],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
          dynamicTo: {
            mode: 'and',
            filters: [],
            filterGroups: [],
          },
        },
      ],
      layout: {
        w: 6,
        h: 3,
        x: 0,
        y: 6,
        i: '59a8fd33-bb90-4179-aaab-047aae9717a3',
        moved: false,
        static: false,
      },
    },
  },
  config: {
    relativeDate: 'months-3',
    startDate: null,
    endDate: null,
  },
})!;

type BasicStoreEntityCustomViewForTests = Pick<
  BasicStoreEntityCustomView,
  'name' | 'description' | 'slug' | 'manifest' | 'target_entity_type'
>;

const CUSTOM_VIEW_ENTITY_1: BasicStoreEntityCustomViewForTests = {
  name: 'My first custom view',
  description: 'A custom view used for tests',
  slug: 'first-custom-view',
  manifest: DASHBOARD_MANIFEST,
  target_entity_type: 'Intrusion-Set',
};

const CUSTOM_VIEW_ENTITY_2: BasicStoreEntityCustomViewForTests = {
  name: 'My second custom view',
  description: 'Another custom view used for tests',
  slug: 'second-custom-view',
  manifest: DASHBOARD_MANIFEST,
  target_entity_type: 'Case-Rft',
};

const CUSTOM_VIEW_ENTITY_INVALID: BasicStoreEntityCustomViewForTests = {
  name: 'An invalid custom view',
  description: 'Just to test the filtering',
  slug: 'invalid-custom-view',
  manifest: DASHBOARD_MANIFEST,
  target_entity_type: 'Region', // Can't have custom views on Region entity_type
};

describe('CustomView resolvers for display use cases', () => {
  let customViewId1: string;
  describe('customViewsDisplayContext', () => {
    it('should retrieve custom views display context', async () => {
      const { id } = await createEntity(
        testContext,
        ADMIN_USER,
        CUSTOM_VIEW_ENTITY_1,
        'CustomView',
      );
      customViewId1 = id;
      const { id: customViewId2 } = await createEntity(
        testContext,
        ADMIN_USER,
        CUSTOM_VIEW_ENTITY_2,
        'CustomView',
      );

      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: READ_CONTEXT_QUERY,
        variables: {},
      });
      expect(result.data.customViewsDisplayContext).toContainEqual({
        entity_type: CUSTOM_VIEW_ENTITY_1.target_entity_type,
        custom_views_info: [{
          id: customViewId1,
          name: CUSTOM_VIEW_ENTITY_1.name,
          path: `${CUSTOM_VIEW_ENTITY_1.slug}-${customViewId1.replaceAll('-', '')}`,
        }],
      });
      expect(result.data.customViewsDisplayContext).toContainEqual({
        entity_type: CUSTOM_VIEW_ENTITY_2.target_entity_type,
        custom_views_info: [{
          id: customViewId2,
          name: CUSTOM_VIEW_ENTITY_2.name,
          path: `${CUSTOM_VIEW_ENTITY_2.slug}-${customViewId2.replaceAll('-', '')}`,
        }],
      });
    });

    it('should not include excluded entity types in display context', async () => {
      await createEntity(
        testContext,
        ADMIN_USER,
        CUSTOM_VIEW_ENTITY_INVALID,
        'CustomView',
      );

      const result = await queryAsUserWithSuccess(USER_PARTICIPATE, {
        query: READ_CONTEXT_QUERY,
        variables: {},
      });
      expect(result.data.customViewsDisplayContext).not.toSatisfy(
        (contexts: CustomViewsDisplayContext[]) => contexts.some((c) => {
          return c.entity_type === CUSTOM_VIEW_ENTITY_INVALID.target_entity_type;
        }));
    });
  });

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
});
