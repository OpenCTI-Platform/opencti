export const PRIVATE_DASHBOARD_MANIFEST = {
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
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'malwares number',
      },
      layout: {
        w: 4,
        h: 2,
        x: 4,
        y: 0,
        i: 'ebb25410-7048-4de7-9288-704e962215f6',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
              {
                key: 'relationship_type',
                values: ['targets'],
                operator: 'eq',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'malwares attacking areas',
      },
      layout: {
        w: 4,
        h: 2,
        x: 4,
        y: 0,
        i: 'ecb25410-7048-4de7-9288-704e962215f6',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
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
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of malwares and areas',
      },
      layout: {
        w: 2,
        h: 4,
        x: 0,
        y: 0,
        i: '0a471055-7426-4840-9501-33770b845f92',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [{
              key: ['description'],
              values: ['widget tests'],
              operator: 'search',
              mode: 'or',
            }],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of attacks',
      },
      layout: {
        w: 3,
        h: 4,
        x: 2,
        y: 0,
        i: '9e6afa7e-0db7-424c-8951-16b867245583',
        moved: false,
        static: false,
      },
    },
    'f05b4f8f-9386-4890-9f9c-a6bd5b0913eb': {
      id: 'f05b4f8f-9386-4890-9f9c-a6bd5b0913eb',
      type: 'line',
      perspective: 'relationships',
      dataSelection: [
        {
          label: '',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: 'relationships',
          isTo: true,
          filters: undefined,
          dynamicFrom: {
            mode: 'and',
            filters: [{
              key: ['description'],
              values: ['widget tests'],
              operator: 'search',
              mode: 'or',
            }],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of attacks without filters',
      },
      layout: {
        w: 3,
        h: 4,
        x: 2,
        y: 4,
        i: 'f05b4f8f-9386-4890-9f9c-a6bd5b0913eb',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Donut entities',
      },
      layout: {
        w: 2,
        h: 4,
        x: 6,
        y: 0,
        i: '9865bec0-d8b1-4592-b14e-0e81e1645f59',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Malwares by type',
      },
      layout: {
        w: 2,
        h: 4,
        x: 6,
        y: 0,
        i: '1865bec0-d8b1-4592-b14e-0e81e1645f59',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
              {
                key: ['toTypes'],
                values: ['Administrative-Area'],
                operator: 'eq',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [{
              key: ['description'],
              values: ['widget tests'],
              operator: 'search',
              mode: 'or',
            }],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Donut relationships',
      },
      layout: {
        w: 2,
        h: 4,
        x: 8,
        y: 0,
        i: '2b3c637b-bf25-46ca-8b28-b891d349cc31',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'List entities',
      },
      layout: {
        w: 4,
        h: 2,
        x: 8,
        y: 4,
        i: 'bec879df-4da2-46c0-994a-e795c1b3a649',
        moved: false,
        static: false,
      },
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
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [{
              key: ['description'],
              values: ['widget tests'],
              operator: 'search',
              mode: 'or',
            }],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'List relationships',
      },
      layout: {
        w: 4,
        h: 2,
        x: 8,
        y: 6,
        i: '6dbb6564-3e4a-4a28-85b1-e2ac479e38e7',
        moved: false,
        static: false,
      },
    },
    'd7a1c3e2-5b64-4f0e-8a39-2c1f6e9b7a10': {
      id: 'd7a1c3e2-5b64-4f0e-8a39-2c1f6e9b7a10',
      type: 'vertical-bar',
      perspective: 'entities',
      dataSelection: [
        {
          label: 'areas and malwares by entity type',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: 'entities',
          isTo: true,
          filters: {
            mode: 'and',
            filters: [
              {
                key: ['entity_type'],
                values: ['Administrative-Area', 'Malware'],
                operator: 'eq',
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of areas and malwares by entity type',
        interval: 'day',
        breakdownBy: 'entity_type',
        breakdownLimit: 5,
        breakdownOrder: 'desc',
        breakdownOther: false,
      },
      layout: {
        w: 4,
        h: 2,
        x: 0,
        y: 8,
        i: 'd7a1c3e2-5b64-4f0e-8a39-2c1f6e9b7a10',
        moved: false,
        static: false,
      },
    },
    'e4b9f2a6-1c3d-4e8f-9a07-6b5c2d1e0f38': {
      id: 'e4b9f2a6-1c3d-4e8f-9a07-6b5c2d1e0f38',
      type: 'line',
      perspective: 'relationships',
      dataSelection: [
        {
          label: 'attacks by target type',
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
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
          dynamicFrom: {
            mode: 'and',
            filters: [{
              key: ['description'],
              values: ['widget tests'],
              operator: 'search',
              mode: 'or',
            }],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of attacks by target type',
        interval: 'day',
        breakdownBy: 'toTypes',
        breakdownLimit: 5,
        breakdownOrder: 'desc',
        breakdownOther: true,
      },
      layout: {
        w: 4,
        h: 2,
        x: 4,
        y: 8,
        i: 'e4b9f2a6-1c3d-4e8f-9a07-6b5c2d1e0f38',
        moved: false,
        static: false,
      },
    },
    '2f27537c-a5ae-45de-b8d4-1e85e325a71c': {
      id: '2f27537c-a5ae-45de-b8d4-1e85e325a71c',
      type: 'line',
      perspective: 'relationships',
      dataSelection: [
        {
          label: 'relationships by type',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: 'relationships',
          isTo: true,
          // No relationship type: the same relationships as the 'Evolution of attacks without filters' widget
          filters: undefined,
          dynamicFrom: {
            mode: 'and',
            filters: [{
              key: ['description'],
              values: ['widget tests'],
              operator: 'search',
              mode: 'or',
            }],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of relationships by type',
        interval: 'day',
        breakdownBy: 'relationship_type',
        breakdownLimit: 5,
        breakdownOrder: 'desc',
        breakdownOther: false,
      },
      layout: {
        w: 4,
        h: 2,
        x: 8,
        y: 8,
        i: '2f27537c-a5ae-45de-b8d4-1e85e325a71c',
        moved: false,
        static: false,
      },
    },
    '65b10e7f-f502-4fed-a192-085f460fb94a': {
      id: '65b10e7f-f502-4fed-a192-085f460fb94a',
      type: 'area',
      perspective: 'entities',
      dataSelection: [
        {
          label: 'top type of areas and malwares',
          attribute: 'entity_type',
          date_attribute: 'created_at',
          perspective: 'entities',
          isTo: true,
          filters: {
            mode: 'and',
            filters: [
              {
                key: ['entity_type'],
                values: ['Administrative-Area', 'Malware'],
                operator: 'eq',
                mode: 'or',
              },
              {
                key: 'description',
                values: ['widget tests'],
                operator: 'search',
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      ],
      parameters: {
        title: 'Evolution of the top type of areas and malwares',
        interval: 'day',
        // A single serie: the other type is counted in the Other serie
        breakdownBy: 'entity_type',
        breakdownLimit: 1,
        breakdownOrder: 'desc',
        breakdownOther: true,
      },
      layout: {
        w: 4,
        h: 2,
        x: 0,
        y: 10,
        i: '65b10e7f-f502-4fed-a192-085f460fb94a',
        moved: false,
        static: false,
      },
    },
  },
  config: {

  },
};
