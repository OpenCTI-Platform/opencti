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
