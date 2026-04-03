import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_LOCATION_COUNTRY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';

export const groupings_mapper: Partial<JsonMapperParsed> = {
  type: 'jsonMapper',
  name: 'groupings mapper',
  variables: [],
  representations: [
    {
      id: 'e81dd818-1511-4233-b201-84b225772fef',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_LOCATION_COUNTRY,
        path: '$..counties',
      },
      identifier: '$.name',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$.name',
          },
        },
      ],
    },
    {
      id: 'e81dd818-1511-4233-b201-84b225772fff',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_INDICATOR,
        path: '$..indicators',
      },
      identifier: '$.pattern',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$.pattern',
          },
        },
        {
          mode: 'simple',
          key: 'pattern_type',
          default_values: ['stix'],
          attr_path: undefined,
        },
        {
          mode: 'simple',
          key: 'pattern',
          attr_path: {
            path: '$.pattern',
          },
        },
        {
          mode: 'simple',
          key: 'x_opencti_main_observable_type',
          default_values: ['Domain-Name'],
          attr_path: undefined,
        },
      ],
    },
    {
      id: 'e81dd818-1511-4233-b201-84b225782fef',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_CONTAINER_GROUPING,
        path: '$',
      },
      identifier: '$.state',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$.state',
          },
        },
        {
          mode: 'base',
          key: 'objects',
          based_on: {
            identifier: [
              { identifier: '$..counties..name', representation: 'e81dd818-1511-4233-b201-84b225772fef' },
              { identifier: '$...indicators..pattern', representation: 'e81dd818-1511-4233-b201-84b225772fff' },
            ],
            representations: [
              'e81dd818-1511-4233-b201-84b225772fef',
              'e81dd818-1511-4233-b201-84b225772fff',
            ],
          },
        },
      ],
    },
  ],
};

export const groupings_data = `[
    {
        "state": "Florida",
        "shortname": "FL",
        "info": {"governor": "Rick Scott"},
        "counties": [
            {"name": "Dade", "population": 12345},
            {"name": "Broward", "population": 40000},
            {"name": "Palm Beach", "population": 60000}
        ],
        "indicators": [
          {"pattern": "[domain-name:value = 'Florida01.com']" },
          {"pattern": "[domain-name:value = 'Florida02.com']" }
        ]
    },
    {
        "state": "Ohio",
        "shortname": "OH",
        "info": {"governor": "John Kasich"},
        "counties": [
            {"name": "Summit", "population": 1234},
            {"name": "Cuyahoga", "population": 1337}
        ],
        "indicators": [
          {"pattern": "[domain-name:value = 'Ohio01.com']" }
        ]
    }
]`;
