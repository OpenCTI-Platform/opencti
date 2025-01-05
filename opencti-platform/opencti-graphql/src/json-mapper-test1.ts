import { type JsonMapperParsed, JsonMapperRepresentationType } from './modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_LABEL } from './schema/stixMetaObject';
import { ENTITY_TYPE_LOCATION_CITY } from './schema/stixDomainObject';

export const json = `
[
  {
    "Event": {
      "id": 1,
      "org_id": 1,
      "uuid": "6df8c0c0-56bf-4fce-a41d-7cf0f1b5207b",
      "info": "Malicious activity detected in certain countries.",
      "date": "2025-01-03",
      "threat_level_id": 3,
      "analysis": 0,
      "published": false,
      "organic": false,
      "proposal": false,
      "timestamp": 1640995200,
      "attributes": [
        {
          "type": "text",
          "category": "External analysis",
          "to_ids": true,
          "value": "Malicious IPs detected",
          "comment": "These IPs were linked to attacks."
        }
      ],
      "galaxies": [
        {
          "type": "country-galaxy",
          "galaxy_id": "country-galaxy",
          "name": "Country",
          "description": "This galaxy contains objects related to countries involved in cybersecurity incidents.",
          "values": [
            {
              "country": "US",
              "label": "United States",
              "iso_code": "USA",
              "population": 331000000,
              "area": 9833517,
              "gdp": 21137518,
              "cybersecurity_rating": "A",
              "threat_level": "High",
              "comment": "Known for a large number of reported incidents.",
              "aliases": ["label1", "label2"]
            },
            {
              "country": "RU",
              "label": "Russia",
              "iso_code": "RUS",
              "population": 145912025,
              "area": 17098242,
              "gdp": 1687000,
              "cybersecurity_rating": "C",
              "threat_level": "Critical",
              "comment": "Frequent source of cyber threats."
            },
            {
              "country": "CN",
              "label": "China",
              "iso_code": "CHN",
              "population": 1439323776,
              "area": 9596961,
              "gdp": 14140163,
              "cybersecurity_rating": "B",
              "threat_level": "Medium",
              "comment": "Increasingly active in cyber operations.",
              "aliases": ["label1", "label3"]
            }
          ]
        }
      ]
    }
  }
]
`;

export const mispJsonMapper: Partial<JsonMapperParsed> = {
  id: 'misp-json-mapper',
  entity_type: 'JsonMapper',
  name: 'MispJsonMapper',
  representations: [
    {
      id: 'labelRepresentation',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_LABEL,
      },
      base_path: {
        path: '$.Event.galaxies[?(@.galaxy_id == \'country-galaxy\')]..values..aliases'
      },
      identifier: {
        key: 'identifier',
        attr_path: {
          path: '$'
        }
      },
      attributes: [
        {
          key: 'value',
          attr_path: {
            path: '$',
          },
        },
      ]
    },
    {
      id: 'countryRepresentation',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_LOCATION_CITY,
      },
      base_path: {
        path: '$.Event.galaxies[?(@.galaxy_id == \'country-galaxy\')]..values'
      },
      identifier: {
        key: 'identifier',
        attr_path: {
          path: '$.iso_code'
        }
      },
      attributes: [
        {
          key: 'name',
          attr_path: {
            path: '$.label',
          },
        },
        {
          key: 'description',
          attr_path: {
            path: '$.comment',
          },
        },
        {
          key: 'objectLabel',
          based_on: {
            identifier_path: '$.aliases',
            representations: [
              'labelRepresentation'
            ]
          }
        }
      ]
    }
  ]
};
