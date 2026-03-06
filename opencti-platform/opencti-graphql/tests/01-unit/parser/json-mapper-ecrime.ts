import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_LOCATION_COUNTRY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';

export const ecrime_mapper: Partial<JsonMapperParsed> = {

  type: 'jsonMapper',
  name: 'Ecrime mapper (JRI)',
  variables: [],
  representations: [
    {
      id: 'ff4b06cd-d727-47bf-903f-fd2cbb4c6cf4',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_LOCATION_COUNTRY,
        path: '$.data[?(@.country != "" && @.country != null)]',
      },
      identifier: '$..country',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$..country',
          },
        },
      ],
    },
    {
      id: '666294ab-2b80-46ca-8423-84aa804ac7d7',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_IDENTITY_SECTOR,
        path: '$.data[?(@.sector != "" && @.sector != null)]',
      },
      identifier: '$..sector',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$..sector',
          },
        },
      ],
    },
    {
      id: '4b1709f1-c249-4cea-ac83-54f272232511',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
        path: '$.data[?(@.name != "" && @.name != null)]',
      },
      identifier: '$..name',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$..name',
          },
        },
        {
          mode: 'simple',
          key: 'description',
          attr_path: {
            path: '$.employees',
          },
        },
      ],
    },
    {
      id: 'e0ab5978-3b88-46ae-9dc0-7d1b21633564',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_INTRUSION_SET,
        path: '$.data',
      },
      identifier: '$.leak_site',
      attributes: [
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$.leak_site',
          },
        },
      ],
    },
    {
      id: '582f8ea1-6b4a-4d0b-a4ea-7bab5817ac9d',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_CONTAINER_REPORT,
        path: '$.data',
      },
      identifier: '$.leak_title',
      attributes: [
        {
          mode: 'simple',
          key: 'created',
          attr_path: {
            path: '$.first_seen',
          },
        },
        {
          mode: 'simple',
          key: 'name',
          attr_path: {
            path: '$.leak_title',
          },
        },
        {
          mode: 'simple',
          key: 'published',
          attr_path: {
            path: '$.data_leak_seen',
          },
        },
        {
          mode: 'base',
          key: 'objects',
          based_on: {
            identifier: [
              { identifier: '$.country', representation: 'ff4b06cd-d727-47bf-903f-fd2cbb4c6cf4' },
              { identifier: '$.sector', representation: '666294ab-2b80-46ca-8423-84aa804ac7d7' },
            ],
            representations: [
              'ff4b06cd-d727-47bf-903f-fd2cbb4c6cf4',
              '666294ab-2b80-46ca-8423-84aa804ac7d7',
            ],
          },
        },
      ],
    },
    {
      id: '06b94f95-c6eb-4144-8074-a40ee490f4be',
      type: JsonMapperRepresentationType.Relationship,
      target: {
        entity_type: 'targets',
        path: '$.data',
      },
      identifier: undefined,
      attributes: [
        {
          mode: 'base',
          key: 'from',
          based_on: {
            identifier: '$.leak_site',
            representations: [
              'e0ab5978-3b88-46ae-9dc0-7d1b21633564',
            ],
          },
        },
        {
          mode: 'base',
          key: 'to',
          based_on: {
            identifier: '$.name',
            representations: [
              '4b1709f1-c249-4cea-ac83-54f272232511',
            ],
          },
        },
      ],
    },
    {
      id: 'd98ef93c-78e6-4527-8b9c-4eae5cd9af0b',
      type: JsonMapperRepresentationType.Relationship,
      target: {
        entity_type: 'part-of',
        path: '$.data',
      },
      identifier: undefined,
      attributes: [
        {
          mode: 'base',
          key: 'from',
          based_on: {
            identifier: '$.name',
            representations: [
              '4b1709f1-c249-4cea-ac83-54f272232511',
            ],
          },
        },
        {
          mode: 'base',
          key: 'to',
          based_on: {
            identifier: '$.sector',
            representations: [
              '666294ab-2b80-46ca-8423-84aa804ac7d7',
            ],
          },
        },
      ],
    },
  ],
};

export const ecrime_data = `{
  "data": [
    {
      "id": "32204",
      "first_seen": "2025-11-17 10:53:49.000000+00:00",
      "last_seen": "2025-11-18 14:48:33.000000+00:00",
      "leak_site": "Akira",
      "leak_title": "MOBI Technologies",
      "country": "United States",
      "sector": "Consumer Electronics",
      "name": "MOBI Technologies, Inc.",
      "website": "https://mobiusa.com/",
      "employees": "11-50 employees",
      "keyword": "False",
      "leak_domain": "",
      "leak_url": "",
      "duplicate": "",
      "data_leak": "False",
      "data_leak_seen": "",
      "last_update": "2025-11-17 10:57:34.000000+00:00",
      "has_screenshot": "False"
    },
    {
      "id": "32206",
      "first_seen": "2025-11-17 11:19:37.000000+00:00",
      "last_seen": "2025-11-18 13:15:47.000000+00:00",
      "leak_site": "Akira",
      "leak_title": "ConsolidatedRestaurant Operations, Inc.",
      "country": "",
      "sector": "",
      "name": "ConsolidatedRestaurant Operations, Inc.",
      "website": "",
      "employees": "",
      "keyword": "False",
      "leak_domain": "",
      "leak_url": "",
      "duplicate": "31343",
      "data_leak": "True",
      "data_leak_seen": "",
      "last_update": "2025-11-17 12:06:31.000000+00:00",
      "has_screenshot": "False"
    },
    {
      "id": "32212",
      "first_seen": "2025-11-17 14:01:23.000000+00:00",
      "last_seen": "2025-11-18 14:48:33.000000+00:00",
      "leak_site": "Akira",
      "leak_title": "ARH Associates",
      "country": "United States",
      "sector": "Civil Engineering",
      "name": "ARH Associates, Inc.",
      "website": "https://www.arh-us.com/",
      "employees": "51-200 employees",
      "keyword": "False",
      "leak_domain": "",
      "leak_url": "",
      "duplicate": "",
      "data_leak": "False",
      "data_leak_seen": "",
      "last_update": "2025-11-17 14:18:41.000000+00:00",
      "has_screenshot": "False"
    },
    {
      "id": "32213",
      "first_seen": "2025-11-17 14:01:23.000000+00:00",
      "last_seen": "2025-11-18 14:48:33.000000+00:00",
      "leak_site": "Akira",
      "leak_title": "Eagle Oil & Gas",
      "country": "United States",
      "sector": "Oil and Gas",
      "name": "Eagle Oil & Gas, LLC / Eagle Oil & Gas Co.",
      "website": "https://eagleog.com/",
      "employees": "11-50 employees",
      "keyword": "False",
      "leak_domain": "",
      "leak_url": "",
      "duplicate": "",
      "data_leak": "False",
      "data_leak_seen": "",
      "last_update": "2025-11-17 14:17:23.000000+00:00",
      "has_screenshot": "False"
    },
    {
      "id": "32214",
      "first_seen": "2025-11-17 14:01:23.000000+00:00",
      "last_seen": "2025-11-18 14:48:33.000000+00:00",
      "leak_site": "Akira",
      "leak_title": "LG Energy Solution",
      "country": "South Korea",
      "sector": "Chemical Manufacturing",
      "name": "LG Energy Solution, Ltd.",
      "website": "https://www.lgensol.com/",
      "employees": "10,001+ employees",
      "keyword": "False",
      "leak_domain": "",
      "leak_url": "",
      "duplicate": "",
      "data_leak": "False",
      "data_leak_seen": "",
      "last_update": "2025-11-17 14:15:24.000000+00:00",
      "has_screenshot": "False"
    }
  ]
}`;
