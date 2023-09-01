import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../../../src/schema/stixDomainObject';
import {
  type BasicStoreEntityCsvMapper,
  CsvMapperRepresentationType
} from '../../../../src/modules/internal/csvMapper/csvMapper-types';

export const csvMapperMockSimpleEntity: Partial<BasicStoreEntityCsvMapper> = {
  id: 'mapper-mock-simple-entity',
  has_header: true,
  separator: ';',
  representations: [
    {
      id: 'representation01',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_THREAT_ACTOR_GROUP,
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'R',
          },
        },
        {
          key: 'threat_actor_types',
          column: {
            column_name: 'AG',
            configuration: {
              seperator: ',',
            }
          },
        },
      ]
    }
  ]
}
