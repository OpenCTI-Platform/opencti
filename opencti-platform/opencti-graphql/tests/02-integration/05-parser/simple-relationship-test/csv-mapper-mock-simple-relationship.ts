import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../../../src/schema/stixDomainObject';
import { RELATION_PART_OF } from '../../../../src/schema/stixCoreRelationship';
import {
  type BasicStoreEntityCsvMapper,
  CsvMapperRepresentationType
} from '../../../../src/modules/internal/csvMapper/csvMapper-types';

export const csvMapperMockSimpleRelationship: Partial<BasicStoreEntityCsvMapper> = {
  id: 'mapper-mock-simple-relationship',
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
            column_name: 'B',
          },
        },
        {
          key: 'confidence',
          column: {
            column_name: 'A',
          },
        }
      ]
    }, {
      id: 'representation02',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_THREAT_ACTOR_GROUP,
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'C',
          },
        },
        {
          key: 'confidence',
          column: {
            column_name: 'D',
          },
        }
      ]
    },
    {
      id: 'representation01-PART_OF-representation02',
      type: CsvMapperRepresentationType.relationship,
      target: {
        entity_type: RELATION_PART_OF,
      },
      attributes: [
        {
          key: 'from',
          based_on: {
            representations: ['representation01'],
          }
        },
        {
          key: 'to',
          based_on: {
            representations: ['representation02'],
          }
        },
        {
          key: 'confidence',
          column: {
            column_name: 'E',
          },
        }
      ]
    },
  ]
}
