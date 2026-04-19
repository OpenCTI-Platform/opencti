import { toB64 } from '../../../../src/utils/base64';
import type { BasicStoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import { utcDate } from '../../../../src/utils/format';

type BasicStoreEntityCustomViewForTestsKeys = Extract<
  keyof BasicStoreEntityCustomView,
  | 'name'
  | 'description'
  | 'slug'
  | 'manifest'
  | 'target_entity_type'
  | 'created_at'
  | 'updated_at'
>;

type BasicStoreEntityCustomViewForTests = Record<
  BasicStoreEntityCustomViewForTestsKeys,
  any
>;

export const DASHBOARD_MANIFEST = toB64({
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

export const CUSTOM_VIEW_ENTITY_1: BasicStoreEntityCustomViewForTests = {
  name: '2 - My first custom view',
  description: 'A custom view used for tests',
  slug: 'first-custom-view',
  manifest: DASHBOARD_MANIFEST,
  target_entity_type: 'Intrusion-Set',
  created_at: utcDate('1986-09-22T02:22:00.000Z').toISOString(),
  updated_at: utcDate('2026-09-22T02:22:00.000Z').toISOString(),
};

export const CUSTOM_VIEW_ENTITY_2: BasicStoreEntityCustomViewForTests = {
  name: '1 - My second custom view',
  description: 'Another custom view used for tests',
  slug: 'second-custom-view',
  manifest: DASHBOARD_MANIFEST,
  target_entity_type: 'Case-Rft',
  created_at: utcDate('1986-09-22T02:22:00.000Z').toISOString(),
  updated_at: utcDate('2026-09-22T02:22:00.000Z').toISOString(),
};

export const CUSTOM_VIEW_ENTITY_INVALID: BasicStoreEntityCustomViewForTests = {
  name: 'An invalid custom view',
  description: 'Just to test the filtering',
  slug: 'invalid-custom-view',
  manifest: DASHBOARD_MANIFEST,
  target_entity_type: 'Feedback', // Can't have custom views on Feedback entity_type
  created_at: utcDate('1986-09-22T02:22:00.000Z').toISOString(),
  updated_at: utcDate('2026-09-22T02:22:00.000Z').toISOString(),
};
