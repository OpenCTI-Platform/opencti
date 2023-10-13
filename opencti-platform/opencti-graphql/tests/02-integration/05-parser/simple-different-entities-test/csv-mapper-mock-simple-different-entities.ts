import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import {
  type BasicStoreEntityCsvMapper,
  CsvMapperRepresentationType, Operator
} from '../../../../src/modules/internal/csvMapper/csvMapper-types';

export const csvMapperMockSimpleDifferentEntities: Partial<BasicStoreEntityCsvMapper> = {
  id: 'mapper-mock-simple-different-entities',
  has_header: true,
  separator: ';',
  representations: [
    {
      id: 'representation01',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_THREAT_ACTOR_GROUP,
        column_based: {
          column_reference: 'B',
          operator: Operator.eq,
          value: 'threat-actor'
        }
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        },
      ]
    },
    {
      id: 'representation02',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
        column_based: {
          column_reference: 'B',
          operator: Operator.neq,
          value: 'threat-actor'
        }
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        },
      ]
    }
  ]
}
