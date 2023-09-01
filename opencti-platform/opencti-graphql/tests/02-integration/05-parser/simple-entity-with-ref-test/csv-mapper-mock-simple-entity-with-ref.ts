import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_THREAT_ACTOR_GROUP
} from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_LABEL } from '../../../../src/schema/stixMetaObject';
import {
  type BasicStoreEntityCsvMapper,
  CsvMapperRepresentationType
} from '../../../../src/modules/internal/csvMapper/csvMapper-types';

export const csvMapperMockSimpleEntityWithRef: Partial<BasicStoreEntityCsvMapper> = {
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
            column_name: 'B',
          },
        },
        {
          key: 'createdBy',
          based_on: {
            representations: ['representation02'],
          },
        },
        {
          key: 'objectLabel',
          based_on: {
            representations: ['representation03'],
          },
        }
      ]
    },
    {
      id: 'representation02',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL,
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        }
      ]
    },
    {
      id: 'representation03',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_LABEL,
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'C',
          },
        }
      ]
    }
  ]
}
