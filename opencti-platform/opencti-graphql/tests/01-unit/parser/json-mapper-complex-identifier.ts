import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_DOMAIN_NAME } from '../../../src/schema/stixCyberObservable';

export const complex_identifier_mapper: Partial<JsonMapperParsed> = {
  type: 'jsonMapper',
  name: 'complex_identifier_test',
  variables: [],
  representations: [
    {
      id: 'rep_domain_1',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_DOMAIN_NAME,
        path: '$[?(@.type == "domain")]',
      },
      identifier: '$.value',
      attributes: [
        {
          mode: 'simple',
          key: 'value',
          attr_path: {
            path: '$.value',
          },
        },
      ],
    },
    {
      id: 'rep_domain_2',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_DOMAIN_NAME,
        path: '$[?(@.type == "domain_alt")]',
      },
      identifier: '$.value_alt',
      attributes: [
        {
          mode: 'simple',
          key: 'value',
          attr_path: {
            path: '$.value_alt',
          },
        },
      ],
    },
    {
      id: 'rep_rel',
      type: JsonMapperRepresentationType.Relationship,
      target: {
        entity_type: 'related-to',
        path: '$[?(@.type == "relationship")]',
      },
      attributes: [
        {
          mode: 'base',
          key: 'from',
          based_on: {
            identifier: [
              { identifier: '$.source', representation: 'rep_domain_1' },
            ],
            representations: ['rep_domain_1'],
          },
        },
        {
          mode: 'base',
          key: 'to',
          based_on: {
            // Legacy mix test: string and implicit representation
            identifier: '$.target',
            representations: ['rep_domain_2'],
          },
        },
      ],
    },
  ],
};

export const complex_data = `[
  { "type": "domain", "value": "source.com" },
  { "type": "domain_alt", "value_alt": "target.com" },
  { "type": "relationship", "source": "source.com", "target": "target.com" }
]`;
