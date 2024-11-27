import { type CsvMapperParsed, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_IPV4_ADDR } from '../../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../../../src/schema/stixDomainObject';
import { CsvMapperOperator } from '../../../../src/generated/graphql';

export const csvMapperDynamicIpAndThreatActor: Partial<CsvMapperParsed> = {
  id: 'dyn-mapper-threatactor-ip',
  has_header: true,
  separator: ',',
  representations: [
    {
      id: 'representationIP',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_IPV4_ADDR,
        column_based: {
          column_reference: 'E',
          operator: CsvMapperOperator.Eq,
          value: 'ipv'
        }
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'A',
          },
        },
        {
          key: 'x_opencti_score',
          column: {
            column_name: 'F',
          },
        }
      ]
    }, {
      id: 'representationLabel',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: 'Label',
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'B',
          },
        },
        {
          key: 'color',
          column: {
            column_name: 'C',
          },
        }
      ]
    },
    {
      id: 'representationThreatActorGroup',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_THREAT_ACTOR_GROUP,
        column_based: {
          column_reference: 'E',
          operator: CsvMapperOperator.Eq,
          value: 'threat'
        }
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        },
        {
          key: 'description',
          column: {
            column_name: 'D',
          },
        },
        {
          key: 'objectLabel',
          based_on: {
            representations: [
              'representationLabel'
            ]
          }
        },
        {
          key: 'confidence',
          column: {
            column_name: 'F',
          },
        }
      ]
    }
  ]
};
