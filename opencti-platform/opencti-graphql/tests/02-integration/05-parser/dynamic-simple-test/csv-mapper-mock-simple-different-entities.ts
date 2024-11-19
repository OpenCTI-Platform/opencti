import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { type CsvMapperParsed, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { CsvMapperOperator } from '../../../../src/generated/graphql';

export const csvMapperMockSimpleDifferentEntities: Partial<CsvMapperParsed> = {
  id: 'mapper-mock-simple-different-entities',
  has_header: true,
  separator: ';',
  representations: [
    {
      id: 'representation01',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_THREAT_ACTOR_GROUP,
        column_based: {
          column_reference: 'B',
          operator: CsvMapperOperator.Eq,
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
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
        column_based: {
          column_reference: 'B',
          operator: CsvMapperOperator.NotEq,
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
};
