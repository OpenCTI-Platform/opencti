import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import {ENTITY_TYPE_CONTAINER_REPORT} from "../../../src/schema/stixDomainObject";

export const indicators_mapper: Partial<JsonMapperParsed> = {
  type: 'jsonMapper',
  name: 'indicators',
  variables: [],
  representations: [
    {
      id: '29934027-c90a-4b63-bb6b-c0ea3b14c12c',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_EXTERNAL_REFERENCE,
        path: '$..external_references',
      },
      identifier: '$.url',
      attributes: [
        {
          mode: 'simple',
          key: 'source_name',
          attr_path: {
            path: '$.source_name',
          },
        },
        {
          mode: 'simple',
          key: 'url',
          attr_path: {
            path: '$.url',
          },
        },
      ],
    },
    {
      id: 'e81dd818-1511-4233-b201-84b225772fef',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_INDICATOR,
        path: '$..[?(@.type == "indicator")]',
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
        {
          mode: 'base',
          key: 'externalReferences',
          based_on: {
            identifier: '$.external_references..url',
            representations: ['29934027-c90a-4b63-bb6b-c0ea3b14c12c'],
          },
        },
      ],
    },
  ],
};

export const indicators_data = `{
  "indicators": [
    {
      "type": "indicator",
      "pattern": "[domain-name:value = 'malicious.com']",
      "external_references": [
        {
          "source_name": "abuse.ch",
          "url": "https://abuse.ch/domain/malicious.com"
        }
      ]
    },
    {
      "type": "indicator",
      "pattern": "[domain-name:value = 'malicious2.com']",
      "external_references": [
        {
          "source_name": "abuse.ch",
          "url": "https://abuse.ch/domain/malicious2.com"
        }
      ]
    }
  ]
}`;
