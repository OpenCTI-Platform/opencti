import { type JsonMapperParsed, JsonMapperRepresentationType } from '../../../src/modules/internal/jsonMapper/jsonMapper-types';
import { ENTITY_DOMAIN_NAME } from '../../../src/schema/stixCyberObservable';

export const domains_mapper: Partial<JsonMapperParsed> = {
  type: 'jsonMapper',
  name: 'domains',
  variables: [],
  representations: [
    {
      id: '22698bcd-ea5a-44ec-a799-db0445913ce1',
      type: JsonMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_DOMAIN_NAME,
        path: '$[?(@.type == "domain")]',
      },
      identifier: undefined,
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
  ],
};

export const domains_data = `[
  { "type": "domain", "value": "evil.com" },
  { "type": "ipv4-addr", "value": "10.0.0.5" }
]`;
